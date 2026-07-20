from opensearchpy import OpenSearch
from src.tools.interfaces import LogSearchTool
import os


class OpenSearchLogTool(LogSearchTool):
    def __init__(self):
        self.client = OpenSearch(
            hosts=[{"host": os.getenv("OPENSEARCH_HOST", "localhost"), "port": 9200}],
            use_ssl=False,
            verify_certs=False,
        )

    def search(self, query: str, time_range: tuple = ("now-7d", "now"), index: str = "soc-alerts") -> list[dict]:
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query, "default_field": "*"}}],
                }
            },
            "size": 50,
        }
        try:
            resp = self.client.search(index=index, body=body)
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        except Exception as e:
            return [{"error": str(e)}]