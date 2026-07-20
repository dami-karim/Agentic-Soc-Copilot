from neo4j import GraphDatabase
import os

driver = GraphDatabase.driver(
    os.getenv("NEO4J_URI", "bolt://localhost:7687"),
    auth=(os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", "damdam@1234"))
)

def load(tx):
    for h in ["WIN-DC01", "WIN-WEB01", "WIN-FIN02", "WIN-DEV03"]:
        tx.run("MERGE (:Host {id: $id})", id=h)
    for u in ["administrator", "jsmith", "svc_backup", "mwilson"]:
        tx.run("MERGE (:User {id: $id})", id=u)
    for src, rel, dst in [
        ("administrator", "AUTHENTICATED_AS", "WIN-DC01"),
        ("jsmith", "AUTHENTICATED_AS", "WIN-WEB01"),
        ("svc_backup", "AUTHENTICATED_AS", "WIN-FIN02"),
        ("WIN-DC01", "CONNECTS_TO", "WIN-WEB01"),
        ("WIN-WEB01", "CONNECTS_TO", "WIN-FIN02"),
        ("WIN-WEB01", "CONNECTS_TO", "WIN-DEV03"),
    ]:
        tx.run(f"MATCH (a {{id: $src}}), (b {{id: $dst}}) MERGE (a)-[:{rel}]->(b)", src=src, dst=dst)

with driver.session() as s:
    s.execute_write(load)
driver.close()
print("Neo4j asset graph loaded OK")


