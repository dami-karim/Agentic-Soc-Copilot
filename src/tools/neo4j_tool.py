from neo4j import GraphDatabase
from src.tools.interfaces import GraphQueryTool
import os


class Neo4jGraphTool(GraphQueryTool):
    def __init__(self):
        self.driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=(
                os.getenv("NEO4J_USER", "neo4j"),
                os.getenv("NEO4J_PASSWORD", "damdam@1234")
            )
        )

    def blast_radius(self, start_node_id: str, max_hops: int = 3) -> dict:
        query = f"""
        MATCH (start {{id: $start_id}})
        OPTIONAL MATCH path = (start)-[*1..{max_hops}]-(reachable)
        RETURN DISTINCT reachable.id AS id,
                        labels(reachable) AS labels,
                        length(path) AS hops
        ORDER BY hops
        """
        with self.driver.session() as session:
            result = session.run(query, start_id=start_node_id)
            reachable = [
                {"id": r["id"], "labels": r["labels"], "hops": r["hops"]}
                for r in result if r["id"] is not None
            ]
        return {
            "start_node": start_node_id,
            "max_hops": max_hops,
            "reachable_assets": reachable,
            "reachable_count": len(reachable),
        }

    def close(self):
        self.driver.close()
