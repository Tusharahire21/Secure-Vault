"""
SecureVault – MongoDB Handler (U4)
Covers:
  U4 – pymongo connection, CRUD operations, indexing,
       filter by IP/timestamp/status, pagination
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

try:
    from pymongo import MongoClient, ASCENDING, DESCENDING
    from pymongo.collection import Collection
    from pymongo.errors import ConnectionFailure, PyMongoError
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

from core.anomaly_detector import Anomaly


# -------------------------------------------------------------------
# Connection Settings
# -------------------------------------------------------------------

MONGO_URI      = "mongodb://localhost:27017/"
DB_NAME        = "securevault_db"
COLLECTION_NAME = "anomalies"

PAGE_SIZE = 20   # Default documents per page


# -------------------------------------------------------------------
# DBHandler Class (U4)
# -------------------------------------------------------------------

class DBHandler:
    """
    Manages all MongoDB interactions for SecureVault.

    Demonstrates (U4):
    - pymongo MongoClient connection
    - Insert, query, filter, paginate documents
    - Store flagged events as BSON documents
    - Index on ip and timestamp fields
    """

    def __init__(
        self,
        uri: str = MONGO_URI,
        db_name: str = DB_NAME,
        collection_name: str = COLLECTION_NAME,
    ):
        if not PYMONGO_AVAILABLE:
            raise ImportError("pymongo is not installed. Run: pip install pymongo")

        try:
            self._client: MongoClient = MongoClient(uri, serverSelectionTimeoutMS=3000)
            # Ping to verify connection
            self._client.admin.command("ping")
            print(f"[DBHandler] Connected to MongoDB at {uri}")
        except ConnectionFailure as exc:
            raise ConnectionError(f"[DBHandler] Cannot connect to MongoDB: {exc}") from exc

        self._db = self._client[db_name]
        self._col: Collection = self._db[collection_name]
        self._ensure_indexes()

    # ----------------------------------------------------------------
    # Index Setup (U4)
    # ----------------------------------------------------------------

    def _ensure_indexes(self) -> None:
        """Create indexes on ip and timestamp for fast queries (U4)."""
        self._col.create_index([("ip", ASCENDING)], name="idx_ip")
        self._col.create_index([("timestamp", DESCENDING)], name="idx_timestamp")
        self._col.create_index([("severity", ASCENDING)], name="idx_severity")
        self._col.create_index([("event_type", ASCENDING)], name="idx_event_type")

    # ----------------------------------------------------------------
    # Insert Operations (U4)
    # ----------------------------------------------------------------

    def insert_anomaly(self, anomaly: Anomaly) -> Optional[str]:
        """
        Store a single flagged anomaly as a MongoDB document (U4).

        Returns:
            Inserted document _id as string, or None on failure.
        """
        doc = anomaly.to_dict()
        doc["created_at"] = datetime.utcnow()
        try:
            result = self._col.insert_one(doc)
            return str(result.inserted_id)
        except PyMongoError as exc:
            print(f"[DBHandler] Insert error: {exc}")
            return None

    def insert_many_anomalies(self, anomalies: list[Anomaly]) -> int:
        """Bulk-insert a list of anomalies. Returns count of inserted docs."""
        if not anomalies:
            return 0
        docs = []
        now = datetime.utcnow()
        for a in anomalies:
            doc = a.to_dict()
            doc["created_at"] = now
            docs.append(doc)
        try:
            result = self._col.insert_many(docs, ordered=False)
            return len(result.inserted_ids)
        except PyMongoError as exc:
            print(f"[DBHandler] Bulk insert error: {exc}")
            return 0

    # ----------------------------------------------------------------
    # Query / Filter Operations (U4)
    # ----------------------------------------------------------------

    def get_anomalies(
        self,
        skip: int = 0,
        limit: int = PAGE_SIZE,
        sort_by: str = "timestamp",
        sort_order: int = DESCENDING,
    ) -> list[dict]:
        """
        Fetch paginated anomaly documents (U4 – pagination).

        Args:
            skip:       Number of documents to skip (offset).
            limit:      Max documents to return per page.
            sort_by:    Field to sort on.
            sort_order: ASCENDING (1) or DESCENDING (-1).
        """
        cursor = (
            self._col
            .find({}, {"_id": 0})
            .sort(sort_by, sort_order)
            .skip(skip)
            .limit(limit)
        )
        return list(cursor)

    def filter_by_ip(self, ip: str, skip: int = 0, limit: int = PAGE_SIZE) -> list[dict]:
        """Filter documents by IP address (U4)."""
        cursor = (
            self._col
            .find({"ip": ip}, {"_id": 0})
            .sort("timestamp", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        return list(cursor)

    def filter_by_severity(self, severity: str, skip: int = 0, limit: int = PAGE_SIZE) -> list[dict]:
        """Filter documents by severity level (U4)."""
        cursor = (
            self._col
            .find({"severity": severity.upper()}, {"_id": 0})
            .sort("timestamp", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        return list(cursor)

    def filter_by_date(
        self,
        start: datetime,
        end: datetime,
        skip: int = 0,
        limit: int = PAGE_SIZE,
    ) -> list[dict]:
        """Filter documents by timestamp range (U4)."""
        cursor = (
            self._col
            .find(
                {"created_at": {"$gte": start, "$lte": end}},
                {"_id": 0},
            )
            .sort("timestamp", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        return list(cursor)

    def filter_by_event_type(self, event_type: str, skip: int = 0, limit: int = PAGE_SIZE) -> list[dict]:
        """Filter documents by event type (U4)."""
        cursor = (
            self._col
            .find({"event_type": event_type.upper()}, {"_id": 0})
            .sort("timestamp", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        return list(cursor)

    def search(self, query: dict, skip: int = 0, limit: int = PAGE_SIZE) -> list[dict]:
        """Generic filter using a raw pymongo query dict."""
        cursor = (
            self._col
            .find(query, {"_id": 0})
            .sort("timestamp", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        return list(cursor)

    def count(self, query: dict | None = None) -> int:
        """Count documents matching query (or all docs if None)."""
        return self._col.count_documents(query or {})

    def count_by_severity(self) -> dict[str, int]:
        """Return {severity: count} breakdown using aggregation."""
        pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ]
        result = {}
        for doc in self._col.aggregate(pipeline):
            result[doc["_id"]] = doc["count"]
        return result

    def count_by_event_type(self) -> dict[str, int]:
        """Return {event_type: count} breakdown."""
        pipeline = [
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
        ]
        return {doc["_id"]: doc["count"] for doc in self._col.aggregate(pipeline)}

    def get_top_ips(self, n: int = 10) -> list[dict]:
        """Return top N IPs by anomaly count."""
        pipeline = [
            {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
            {"$sort": {"count": DESCENDING}},
            {"$limit": n},
        ]
        return [{"ip": d["_id"], "count": d["count"]} for d in self._col.aggregate(pipeline)]

    # ----------------------------------------------------------------
    # Utility
    # ----------------------------------------------------------------

    def clear_all(self) -> int:
        """Delete all documents from the anomalies collection."""
        result = self._col.delete_many({})
        return result.deleted_count

    def close(self) -> None:
        """Close the MongoDB connection."""
        self._client.close()
        print("[DBHandler] MongoDB connection closed.")
