"""Transactional investigation state alongside the existing lookup evidence store."""
from copy import deepcopy
import json

from ..storage import EvidenceStore


class WorkflowConflict(ValueError):
    """The caller's saved revision or step no longer matches durable state."""


class WorkflowRepository:
    SCHEMA_VERSION = 1
    NODE_LIST_FIELDS = ("context", "sources", "passage_ids", "evidence_ids", "lookup_ids")
    EDGE_LIST_FIELDS = ("evidence_ids", "lookup_ids")
    TERMINAL_STEP_STATUSES = {"completed", "failed", "cancelled"}

    def __init__(self, store: EvidenceStore):
        self.store = store
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS wf_schema (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)")
            row = db.execute("SELECT version FROM wf_schema WHERE id=1").fetchone()
            if row and row[0] != self.SCHEMA_VERSION:
                raise WorkflowConflict(f"Unsupported workflow schema version: {row[0]}")
            statements = (
                "CREATE TABLE IF NOT EXISTS wf_runs (id TEXT PRIMARY KEY, record TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS wf_steps (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, "
                "sequence INTEGER NOT NULL, record TEXT NOT NULL, UNIQUE(run_id, sequence))",
                "CREATE INDEX IF NOT EXISTS wf_steps_run ON wf_steps(run_id, sequence)",
                "CREATE TABLE IF NOT EXISTS wf_nodes (run_id TEXT NOT NULL, id TEXT NOT NULL, "
                "record TEXT NOT NULL, PRIMARY KEY(run_id, id))",
                "CREATE TABLE IF NOT EXISTS wf_edges (run_id TEXT NOT NULL, id TEXT NOT NULL, "
                "left_id TEXT NOT NULL, right_id TEXT NOT NULL, method_id TEXT NOT NULL, record TEXT NOT NULL, "
                "PRIMARY KEY(run_id, id), UNIQUE(run_id, left_id, right_id, method_id))",
            )
            for statement in statements:
                db.execute(statement)
            db.execute("INSERT OR IGNORE INTO wf_schema VALUES (1, ?)", (self.SCHEMA_VERSION,))

    @staticmethod
    def _json(record: dict) -> str:
        return json.dumps(record, ensure_ascii=False, allow_nan=False)

    @staticmethod
    def _required(record: dict, field: str) -> str:
        value = record.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} must be a nonempty string")
        return value

    @staticmethod
    def _revision(run: dict) -> int:
        revision = run.get("graph_revision", 0)
        if type(revision) is not int or revision < 0:
            raise ValueError("graph_revision must be a nonnegative integer")
        return revision

    @classmethod
    def _check_revision(cls, current: dict, proposed: dict):
        if cls._revision(current) != cls._revision(proposed):
            raise WorkflowConflict("Run has changed; reload its current graph revision")

    @staticmethod
    def _read(db, table: str, record_id: str) -> dict:
        # Table names only come from fixed internal call sites.
        row = db.execute(f"SELECT record FROM {table} WHERE id=?", (record_id,)).fetchone()
        if not row:
            raise KeyError(f"Unknown {table.removeprefix('wf_')} ID: {record_id}")
        return json.loads(row[0])

    @staticmethod
    def _save_run(db, run: dict):
        db.execute("UPDATE wf_runs SET record=? WHERE id=?", (WorkflowRepository._json(run), run["id"]))

    @staticmethod
    def _lists(old: dict, new: dict, fields: tuple[str, ...]) -> dict:
        result = {}
        for field in fields:
            result[field] = []
            for record in (old, new):
                values = record.get(field, [])
                if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                    raise ValueError(f"{field} must be a list of strings")
                for value in values:
                    if value not in result[field]:
                        result[field].append(value)
        return result

    @classmethod
    def _merge_node(cls, db, run_id: str, proposed: dict) -> bool:
        node = deepcopy(proposed)
        node_id = cls._required(node, "id")
        cls._required(node, "type")
        cls._required(node, "value")
        row = db.execute("SELECT record FROM wf_nodes WHERE run_id=? AND id=?", (run_id, node_id)).fetchone()
        current = json.loads(row[0]) if row else {}
        if current and (current["type"], current["value"]) != (node["type"], node["value"]):
            raise WorkflowConflict("A node ID cannot identify two different IOCs")
        if "used" in node and not isinstance(node["used"], bool):
            raise ValueError("used must be a boolean")
        merged = {**current, **node, **cls._lists(current, node, cls.NODE_LIST_FIELDS)}
        merged["used"] = current.get("used", False) or node.get("used", False)
        if current.get("origin") == "report":
            merged["origin"] = "report"
        db.execute("INSERT INTO wf_nodes VALUES (?, ?, ?) ON CONFLICT(run_id, id) DO UPDATE SET record=excluded.record",
                   (run_id, node_id, cls._json(merged)))
        return row is None

    @classmethod
    def _merge_edge(cls, db, run_id: str, proposed: dict) -> tuple[bool, int]:
        edge = deepcopy(proposed)
        edge_id = cls._required(edge, "id")
        left, right = sorted((cls._required(edge, "left"), cls._required(edge, "right")))
        method_id = cls._required(edge, "method_id")
        if left == right:
            raise ValueError("A graph edge must connect different nodes")
        for node_id in (left, right):
            if not db.execute("SELECT 1 FROM wf_nodes WHERE run_id=? AND id=?", (run_id, node_id)).fetchone():
                raise ValueError(f"Edge endpoint is not in this investigation: {node_id}")
        edge["left"], edge["right"] = left, right
        row = db.execute("SELECT record FROM wf_edges WHERE run_id=? AND id=?", (run_id, edge_id)).fetchone()
        current = json.loads(row[0]) if row else {}
        identity = (left, right, method_id)
        if current and (current["left"], current["right"], current["method_id"]) != identity:
            raise WorkflowConflict("An edge ID cannot identify two different relationships")
        other = db.execute("SELECT id FROM wf_edges WHERE run_id=? AND left_id=? AND right_id=? AND method_id=?",
                           (run_id, *identity)).fetchone()
        if other and other[0] != edge_id:
            raise WorkflowConflict("This relationship already has a different stable edge ID")
        if current.get("ontology_label") and edge.get("ontology_label") and current["ontology_label"] != edge["ontology_label"]:
            raise WorkflowConflict("An existing relationship cannot change its ontology label")
        merged = {**current, **edge, **cls._lists(current, edge, cls.EDGE_LIST_FIELDS)}
        if current.get("ontology_label") and not edge.get("ontology_label"):
            merged["ontology_label"] = current["ontology_label"]
        evidence_links = len(merged["evidence_ids"]) - len(current.get("evidence_ids", []))
        db.execute("INSERT INTO wf_edges VALUES (?, ?, ?, ?, ?, ?) "
                   "ON CONFLICT(run_id, id) DO UPDATE SET record=excluded.record",
                   (run_id, edge_id, left, right, method_id, cls._json(merged)))
        return row is None, evidence_links

    def create_run(self, run: dict, nodes: list[dict]) -> None:
        saved = deepcopy(run)
        run_id = self._required(saved, "id")
        saved["graph_revision"] = self._revision(saved)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO wf_runs VALUES (?, ?)", (run_id, self._json(saved)))
            for node in nodes:
                self._merge_node(db, run_id, node)

    def finish_extraction(self, run: dict, nodes: list[dict]) -> None:
        """Publish the initial graph and extraction diagnostics in one transaction."""
        run_id = self._required(run, "id")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = self._read(db, "wf_runs", run_id)
            self._check_revision(current, run)
            if current.get("status") != "extracting":
                raise WorkflowConflict("Only an extracting investigation can publish its initial graph")
            if run.get("status") not in {"ready", "failed"}:
                raise ValueError("Extraction must have a final ready or failed outcome")
            if db.execute("SELECT 1 FROM wf_nodes WHERE run_id=? LIMIT 1", (run_id,)).fetchone():
                raise WorkflowConflict("An extracting investigation already contains graph nodes")
            for node in nodes:
                self._merge_node(db, run_id, node)
            saved = {**current, **deepcopy(run), "graph_revision": self._revision(current) + 1}
            self._save_run(db, saved)

    def get_run(self, run_id: str) -> dict:
        with self.store.connect() as db:
            return self._read(db, "wf_runs", run_id)

    def list_runs(self) -> list[dict]:
        with self.store.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT record FROM wf_runs ORDER BY rowid")]

    def save_run(self, run: dict) -> None:
        run_id = self._required(run, "id")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = self._read(db, "wf_runs", run_id)
            self._check_revision(current, run)
            self._save_run(db, {**current, **deepcopy(run)})

    def _records(self, table: str, run_id: str, order: str) -> list[dict]:
        with self.store.connect() as db:
            self._read(db, "wf_runs", run_id)
            return [json.loads(row[0]) for row in db.execute(
                f"SELECT record FROM {table} WHERE run_id=? ORDER BY {order}", (run_id,))]

    def nodes(self, run_id: str) -> list[dict]:
        return self._records("wf_nodes", run_id, "rowid")

    def edges(self, run_id: str) -> list[dict]:
        return self._records("wf_edges", run_id, "rowid")

    def steps(self, run_id: str) -> list[dict]:
        return self._records("wf_steps", run_id, "sequence")

    def get_step(self, step_id: str) -> dict:
        with self.store.connect() as db:
            return self._read(db, "wf_steps", step_id)

    @classmethod
    def _step_identity(cls, run: dict, step: dict):
        cls._required(step, "id")
        cls._required(step, "input_node_id")
        if step.get("run_id") != run["id"]:
            raise WorkflowConflict("Step belongs to a different investigation")
        if type(step.get("sequence")) is not int or step["sequence"] < 0:
            raise ValueError("Step sequence must be a nonnegative integer")

    @staticmethod
    def _check_step_identity(current: dict, proposed: dict):
        for field in ("id", "run_id", "sequence", "input_node_id"):
            if current[field] != proposed.get(field):
                raise WorkflowConflict(f"An existing step cannot change its {field}")
        if "method_id" in current and current["method_id"] != proposed.get("method_id"):
            raise WorkflowConflict("An existing step cannot change its method_id")

    @classmethod
    def _check_active(cls, db, run_id: str, step_id: str):
        for row in db.execute("SELECT record FROM wf_steps WHERE run_id=?", (run_id,)):
            step = json.loads(row[0])
            if step["id"] != step_id and step.get("status") not in cls.TERMINAL_STEP_STATUSES:
                raise WorkflowConflict("Another step is still active; resume it before starting a new lookup")

    def begin_step(self, run: dict, step: dict) -> None:
        self._step_identity(run, step)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current_run = self._read(db, "wf_runs", run["id"])
            self._check_revision(current_run, run)
            existing = db.execute("SELECT record FROM wf_steps WHERE id=?", (step["id"],)).fetchone()
            if existing:
                current_step = json.loads(existing[0])
                self._check_step_identity(current_step, step)
                if current_step.get("status") in self.TERMINAL_STEP_STATUSES:
                    raise WorkflowConflict("Step has already finished")
                return  # Resume keeps its existing lookup ID and durable progress.
            self._check_active(db, run["id"], step["id"])
            row = db.execute("SELECT record FROM wf_nodes WHERE run_id=? AND id=?",
                             (run["id"], step["input_node_id"])).fetchone()
            if not row:
                raise ValueError("The selected input IOC is not in this investigation")
            node = json.loads(row[0])
            node["used"] = True
            self._merge_node(db, run["id"], node)
            saved_step = {**deepcopy(step), "status": "running"}
            db.execute("INSERT INTO wf_steps VALUES (?, ?, ?, ?)",
                       (step["id"], run["id"], step["sequence"], self._json(saved_step)))
            self._save_run(db, {**current_run, **deepcopy(run)})

    def update_step(self, step: dict) -> None:
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = self._read(db, "wf_steps", self._required(step, "id"))
            self._check_step_identity(current, step)
            if current.get("status") in self.TERMINAL_STEP_STATUSES:
                if current == step:
                    return
                raise WorkflowConflict("A finished step is immutable")
            if step.get("status") == "completed":
                raise WorkflowConflict("Use commit_step to complete a step with its graph changes")
            saved = {**current, **deepcopy(step)}
            db.execute("UPDATE wf_steps SET record=? WHERE id=?", (self._json(saved), step["id"]))

    def commit_step(self, run: dict, step: dict, nodes: list[dict], edges: list[dict]) -> dict:
        self._step_identity(run, step)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current_step = self._read(db, "wf_steps", step["id"])
            self._check_step_identity(current_step, step)
            if current_step.get("status") == "completed":
                return deepcopy(current_step["delta"])
            if current_step.get("status") in self.TERMINAL_STEP_STATUSES:
                raise WorkflowConflict("A finished step cannot be committed again")
            current_run = self._read(db, "wf_runs", run["id"])
            self._check_revision(current_run, run)
            self._check_active(db, run["id"], step["id"])
            delta = {"new_nodes": 0, "new_edges": 0, "evidence_links": 0}
            for node in nodes:
                delta["new_nodes"] += self._merge_node(db, run["id"], node)
            for edge in edges:
                is_new, links = self._merge_edge(db, run["id"], edge)
                delta["new_edges"] += is_new
                delta["evidence_links"] += links
            saved_run = {**current_run, **deepcopy(run), "graph_revision": self._revision(current_run) + 1}
            saved_step = {**current_step, **deepcopy(step), "status": "completed", "delta": delta}
            self._save_run(db, saved_run)
            db.execute("UPDATE wf_steps SET record=? WHERE id=?", (self._json(saved_step), step["id"]))
            return deepcopy(delta)
