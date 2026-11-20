import math
from dataclasses import dataclass
from .codec import digest, dumps, key as checked_key, loads, name
from .errors import Conflict, InvalidDocument, NotFound
from .indexes import refresh_document
from .mvcc import latest_row
from .schema import validate_document

MAX_OPERATIONS = 10000


@dataclass(frozen=True)
class CommitResult:
    revision: int
    count: int
    replayed: bool = False


def commit_operations(store, connection, operations, request_key, fingerprint, origin=None):
    """Validate and commit prepared operations inside the caller's writable transaction.

    Whatever selection produced the operations and this commit share one
    IMMEDIATE boundary, so preconditions, schema checks, index maintenance,
    the commit log and the idempotency receipt are linearized together.
    """
    if request_key is not None:
        prior = connection.execute("SELECT * FROM receipts WHERE request_key=?", (request_key,)).fetchone()
        if prior:
            if prior["request_hash"] != fingerprint:
                raise Conflict("request key was used with different operations")
            return CommitResult(prior["rev"], prior["count"], True)
    head = int(store.get("head"))
    for op in operations:
        schema = connection.execute("SELECT schema FROM collections WHERE name=?", (op["collection"],)).fetchone()
        if schema is None:
            raise NotFound("unknown collection: " + op["collection"])
        old = latest_row(connection, op["collection"], op["key"], head)
        current = old["rev"] if old is not None else 0
        if op["expected"] is not None and op["expected"] != current:
            raise Conflict(f"revision conflict for {op['collection']}/{op['key']}: expected {op['expected']}, found {current}")
        if op["document"] is not None:
            validate_document(op["document"], loads(schema[0]))
    revision = head + 1
    for op in operations:
        body = dumps(op["document"]) if op["document"] is not None else None
        connection.execute("INSERT INTO versions VALUES (?,?,?,?,?)",
                           (op["collection"], op["key"], revision, body, op["expires_at"]))
        refresh_document(connection, op["collection"], op["key"], op["document"])
    payload = {"revision": revision, "operations": operations}
    if origin is not None:
        payload["origin"] = origin
    connection.execute("INSERT INTO commits VALUES (?,?,?,?)",
                       (revision, dumps(payload), request_key, fingerprint))
    if request_key is not None:
        connection.execute("INSERT INTO receipts VALUES (?,?,?,?)", (request_key, revision, fingerprint, len(operations)))
    store.set("head", revision)
    return CommitResult(revision, len(operations))


class WriteBatch:
    def __init__(self, store, request_key=None):
        self.store = store
        self.request_key = checked_key(request_key) if request_key is not None else None
        self.operations = []
        self.identities = set()
        self.state = "open"

    def _append(self, operation):
        if self.state != "open":
            raise Conflict("batch is already " + self.state)
        identity = (operation["collection"], operation["key"])
        if identity in self.identities:
            raise InvalidDocument("one operation per document per batch")
        expected = operation["expected"]
        if expected is not None and (isinstance(expected, bool) or not isinstance(expected, int) or expected < 0):
            raise InvalidDocument("expected revision must be nonnegative or None")
        self.identities.add(identity)
        self.operations.append(operation)
        return self

    def put(self, collection, key, document, expected=None, expires_at=None):
        name(collection)
        checked_key(key)
        if not isinstance(document, dict):
            raise InvalidDocument("document must be an object")
        if expires_at is not None and (isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)) or not math.isfinite(expires_at)):
            raise InvalidDocument("expires_at must be a finite timestamp")
        return self._append({"collection": collection, "key": key, "document": loads(dumps(document)),
                             "expected": expected, "expires_at": expires_at})

    def delete(self, collection, key, expected=None):
        return self._append({"collection": name(collection), "key": checked_key(key), "document": None,
                             "expected": expected, "expires_at": None})

    def abort(self):
        if self.state != "open":
            raise Conflict("batch is already " + self.state)
        self.operations.clear()
        self.identities.clear()
        self.state = "aborted"

    def commit(self):
        if self.state != "open":
            raise Conflict("batch is already " + self.state)
        if not self.operations or len(self.operations) > MAX_OPERATIONS:
            raise InvalidDocument(f"batch must contain between 1 and {MAX_OPERATIONS} operations")
        fingerprint = digest(self.operations)
        try:
            with self.store.atomic(writable=True) as connection:
                result = commit_operations(self.store, connection, self.operations, self.request_key, fingerprint)
        except BaseException:
            self.state = "aborted"
            raise
        self.state = "committed"
        return result
