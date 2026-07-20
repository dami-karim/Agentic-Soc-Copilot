from abc import ABC, abstractmethod


class LogSearchTool(ABC):
    @abstractmethod
    def search(self, query: str, time_range: tuple = ("now-24h", "now"), index: str = "soc-alerts") -> list[dict]:
        raise NotImplementedError


class GraphQueryTool(ABC):
    @abstractmethod
    def blast_radius(self, start_node_id: str, max_hops: int = 3) -> dict:
        raise NotImplementedError


class VectorRetrievalTool(ABC):
    @abstractmethod
    def similar_incidents(self, query_text: str, top_k: int = 5) -> list[dict]:
        raise NotImplementedError


class AttackCorpusTool(ABC):
    @abstractmethod
    def query_techniques(self, data_component: str, top_k: int = 11) -> list[dict]:
        raise NotImplementedError
    