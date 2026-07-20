from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
from sentence_transformers import SentenceTransformer
from src.tools.interfaces import VectorRetrievalTool
import uuid
import os

COLLECTION = "past_incidents"


class QdrantIncidentTool(VectorRetrievalTool):
    def __init__(self):
        self.client = QdrantClient(
            host=os.getenv("QDRANT_HOST", "localhost"),
            port=6333,
            check_compatibility=False
        )
        self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
        existing = [c.name for c in self.client.get_collections().collections]
        if COLLECTION not in existing:
            self.client.create_collection(
                collection_name=COLLECTION,
                vectors_config=VectorParams(size=384, distance=Distance.COSINE),
            )

    def index_incident(self, text: str, metadata: dict):
        vector = self.embedder.encode(text).tolist()
        self.client.upsert(
            collection_name=COLLECTION,
            points=[PointStruct(
                id=str(uuid.uuid4()),
                vector=vector,
                payload={**metadata, "text": text}
            )],
        )

    def similar_incidents(self, query_text: str, top_k: int = 5) -> list[dict]:
        vector = self.embedder.encode(query_text).tolist()
        hits = self.client.query_points(
            collection_name=COLLECTION,
            query=vector,
            limit=top_k
        ).points
        return [{"score": h.score, **h.payload} for h in hits]
