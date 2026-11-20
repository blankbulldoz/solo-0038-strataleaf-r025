from dataclasses import dataclass
from .codec import digest, dumps, key as checked_key, loads, name
from .errors import Conflict, InvalidDocument, NotFound
from .mvcc import visible_rows
from .patch import merge_patch
from .predicates import matches, validate_predicate
from .transaction import MAX_OPERATIONS, commit_operations


@dataclass(frozen=True)
class BulkResult:
    """Outcome of one predicate-based bulk write.

    revision is None when nothing matched and no commit was created. keys
    holds the affected document keys in ascending key order; on an idempotent
    replay they are recovered from the retained commit log and are empty once
    that commit has been compacted away, while the receipt revision and count
    remain authoritative.
    """
    revision: int | None
    count: int
    keys: tuple
    replayed: bool = False


def _replayed_result(connection, request_key, fingerprint):
    if request_key is None:
        return None
    prior = connection.execute("SELECT * FROM receipts WHERE request_key=?", (request_key,)).fetchone()
    if prior is None:
        return None
    if prior["request_hash"] != fingerprint:
        raise Conflict("request key was used with different operations")
    row = connection.execute("SELECT payload FROM commits WHERE rev=?", (prior["rev"],)).fetchone()
    keys = tuple(op["key"] for op in loads(row["payload"])["operations"]) if row else ()
    return BulkResult(prior["rev"], prior["count"], keys, True)


def _bulk_write(store, collection, predicate, patch, request_key):
    name(collection)
    validate_predicate(predicate)
    if patch is not None:
        if not isinstance(patch, dict):
            raise InvalidDocument("document merge patch must be an object")
        dumps(patch)
    request_key = checked_key(request_key) if request_key is not None else None
    origin = {"kind": "bulk_update" if patch is not None else "bulk_delete", "predicate": predicate}
    if patch is not None:
        origin["patch"] = patch
    fingerprint = digest({"collection": collection, "request": origin})
    with store.atomic(writable=True) as connection:
        replay = _replayed_result(connection, request_key, fingerprint)
        if replay is not None:
            return replay
        if not connection.execute("SELECT 1 FROM collections WHERE name=?", (collection,)).fetchone():
            raise NotFound("unknown collection: " + collection)
        head = int(store.get("head"))
        matched = [(row, loads(row["body"])) for row in visible_rows(connection, collection, head)]
        matched = [(row, document) for row, document in matched if matches(document, predicate)]
        if len(matched) > MAX_OPERATIONS:
            raise InvalidDocument(f"{origin['kind']} matched {len(matched)} documents, exceeding the batch capacity "
                                  f"of {MAX_OPERATIONS}; narrow the predicate")
        if not matched:
            return BulkResult(None, 0, ())
        operations = []
        for row, document in matched:
            if patch is None:
                operations.append({"collection": collection, "key": row["key"], "document": None,
                                   "expected": row["rev"], "expires_at": None})
            else:
                operations.append({"collection": collection, "key": row["key"],
                                   "document": merge_patch(document, patch),
                                   "expected": row["rev"], "expires_at": row["expires"]})
        result = commit_operations(store, connection, operations, request_key, fingerprint, origin)
        return BulkResult(result.revision, result.count, tuple(op["key"] for op in operations), result.replayed)


def update_where(store, collection, predicate, patch, request_key=None):
    """Merge the same patch into every current document matching the predicate.

    Selection and commit share one IMMEDIATE transaction, so no other
    connection can change or insert matching documents in between.
    """
    return _bulk_write(store, collection, predicate, patch, request_key)


def delete_where(store, collection, predicate, request_key=None):
    """Delete every current document matching the predicate in one commit."""
    return _bulk_write(store, collection, predicate, None, request_key)
