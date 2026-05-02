from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Generator

from neo4j import GraphDatabase, Driver, Session


class Neo4jConnection:

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "neo4j",
        database: str = "neo4j",
    ):
        self._uri = uri
        self._user = user
        self._password = password
        self._database = database
        self._driver: Driver | None = None


    def connect(self) -> None:
        if self._driver is None:
            self._driver = GraphDatabase.driver(
                self._uri, auth=(self._user, self._password),
            )

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        self.connect()
        assert self._driver is not None
        with self._driver.session(database=self._database) as s:
            yield s


    def run(self, cypher: str, **params: Any) -> list[dict]:
        with self.session() as s:
            result = s.run(cypher, **params)
            return [r.data() for r in result]

    def run_write(self, cypher: str, **params: Any) -> None:
        with self.session() as s:
            s.execute_write(lambda tx: tx.run(cypher, **params))

    def clear(self) -> None:
        self.run_write("MATCH (n) DETACH DELETE n")

    def ensure_indexes(self) -> None:
        indexes = [
            "CREATE INDEX IF NOT EXISTS FOR (n:CPGNode) ON (n.node_id)",
            "CREATE INDEX IF NOT EXISTS FOR (n:CPGNode) ON (n.op_label)",
            "CREATE INDEX IF NOT EXISTS FOR (n:CPGNode) ON (n.val_label)",
            "CREATE INDEX IF NOT EXISTS FOR (n:CPGNode) ON (n.component)",
            "CREATE INDEX IF NOT EXISTS FOR (n:CPGNode) ON (n.line)",
        ]
        for stmt in indexes:
            self.run_write(stmt)
