from copy import deepcopy
import sqlite3
import tempfile
import unittest

from ioc_hunter.evidence import LookupRecord
from ioc_hunter.models import IOC
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.workflow.repository import WorkflowConflict, WorkflowRepository


def node(node_id="a", value="example.com", **changes):
    return {"id": node_id, "type": "domain", "value": value,
            "context": ["original report"], "sources": ["cti report"],
            "passage_ids": ["p1"], "evidence_ids": [], "lookup_ids": [], "origin": "report", "used": False, **changes}


def edge(edge_id="ab", **changes):
    return {"id": edge_id, "left": "a", "right": "b", "method_id": "test.method",
            "ontology_label": "resolved", "evidence_ids": ["ev1"], "lookup_ids": ["lookup1"], **changes}


class WorkflowRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EvidenceStore(self.temp.name)
        self.repo = WorkflowRepository(self.store)
        self.run = {"id": "run1", "status": "ready", "graph_revision": 0,
                    "report": {"text": "original report"}, "extraction": {"warnings": ["diagnostic"]}}
        self.repo.create_run(self.run, [node()])

    def step(self, step_id="step1", sequence=1):
        return {"id": step_id, "run_id": "run1", "sequence": sequence,
                "input_node_id": "a", "method_id": "test.method", "status": "running", "lookup_id": "lookup1"}

    def begin(self, step=None):
        step = step or self.step()
        current = self.repo.get_run("run1")
        current["status"] = "running"
        self.repo.begin_step(current, step)
        return current, step

    def test_reopen_preserves_existing_lookup_store_and_nested_run_metadata(self):
        receipt = LookupRecord("lookup1", "test.method", IOC("example.com", "domain"))
        self.store.save_record(receipt, "key")
        reopened = WorkflowRepository(EvidenceStore(self.temp.name))
        self.assertEqual(reopened.get_run("run1"), self.run)
        self.assertEqual(reopened.store.get_record("lookup1"), receipt.to_dict())
        self.assertEqual(reopened.nodes("run1"), [node()])
        self.assertEqual(reopened.list_runs(), [self.run])

    def test_read_results_and_mutation_arguments_do_not_alias_durable_data(self):
        self.run["report"]["text"] = "changed outside repository"
        loaded = self.repo.get_run("run1")
        loaded["report"]["text"] = "changed loaded copy"
        nodes = self.repo.nodes("run1")
        nodes[0]["context"].append("outside change")
        self.assertEqual(self.repo.get_run("run1")["report"]["text"], "original report")
        self.assertEqual(self.repo.nodes("run1")[0]["context"], ["original report"])

    def test_finish_extraction_publishes_initial_graph_once_with_metadata(self):
        extracting = {"id": "extracting", "graph_revision": 0, "status": "extracting", "report": {"text": "report"}}
        self.repo.create_run(extracting, [])
        ready = {**extracting, "status": "ready", "extraction": {"warnings": ["warning"], "passages": []}}
        self.repo.finish_extraction(ready, [node(), node("b", "other.example")])
        self.assertEqual(self.repo.get_run("extracting"), {**ready, "graph_revision": 1})
        self.assertEqual(len(self.repo.nodes("extracting")), 2)
        self.assertEqual(ready["graph_revision"], 0)
        with self.assertRaisesRegex(WorkflowConflict, "reload"):
            self.repo.finish_extraction(ready, [node("c", "new.example")])
        with self.assertRaisesRegex(WorkflowConflict, "Only an extracting"):
            self.repo.finish_extraction(self.repo.get_run("extracting"), [])
        self.assertEqual(len(self.repo.nodes("extracting")), 2)

    def test_finish_extraction_rolls_back_initial_nodes_and_ready_state_on_failure(self):
        extracting = {"id": "extracting", "graph_revision": 0, "status": "extracting"}
        self.repo.create_run(extracting, [])
        ready = {**extracting, "status": "ready", "extraction": {"warnings": []}}
        with self.assertRaisesRegex(ValueError, "list of strings"):
            self.repo.finish_extraction(ready, [node(), node("b", "other.example", sources="wrong")])
        self.assertEqual(self.repo.get_run("extracting"), extracting)
        self.assertEqual(self.repo.nodes("extracting"), [])

    def test_begin_marks_seed_used_and_records_run_and_step_together(self):
        current, step = self.begin()
        self.assertTrue(self.repo.nodes("run1")[0]["used"])
        self.assertEqual(self.repo.get_run("run1")["status"], "running")
        self.assertEqual(self.repo.steps("run1"), [step])
        self.assertEqual(current["graph_revision"], 0)

    def test_begin_missing_seed_rolls_back_every_change(self):
        step = self.step()
        step["input_node_id"] = "unknown"
        changed_run = {**self.run, "status": "running"}
        with self.assertRaisesRegex(ValueError, "not in this investigation"):
            self.repo.begin_step(changed_run, step)
        self.assertEqual(self.repo.steps("run1"), [])
        self.assertEqual(self.repo.get_run("run1")["status"], "ready")
        self.assertFalse(self.repo.nodes("run1")[0]["used"])

    def test_duplicate_sequence_rolls_back_seed_and_run_changes(self):
        current, step = self.begin()
        self.repo.commit_step(current, step, [node("b", "other.example")], [])
        next_run = self.repo.get_run("run1")
        next_step = self.step("step2", 1)
        next_step["input_node_id"] = "b"
        next_run["status"] = "should roll back"
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.begin_step(next_run, next_step)
        self.assertFalse(self.repo.nodes("run1")[1]["used"])
        self.assertNotEqual(self.repo.get_run("run1")["status"], "should roll back")

    def test_active_step_cannot_be_duplicated_and_resume_keeps_receipt_link(self):
        current, step = self.begin()
        pending = self.repo.get_step(step["id"])
        pending["lookup_id"] = "saved-recovery-receipt"
        self.repo.update_step(pending)
        self.repo.begin_step(current, step)
        self.assertEqual(self.repo.get_step(step["id"])["lookup_id"], "saved-recovery-receipt")
        other = WorkflowRepository(self.store)
        with self.assertRaisesRegex(WorkflowConflict, "still active"):
            other.begin_step(current, self.step("step2", 2))

    def test_commit_merges_graph_provenance_and_is_idempotent_after_reopen(self):
        current, step = self.begin()
        pending_node = node("b", "other.example", evidence_ids=["ev1"], lookup_ids=["lookup1"])
        before = deepcopy((current, step, pending_node))
        delta = self.repo.commit_step(current, step, [pending_node], [edge()])
        self.assertEqual(delta, {"new_nodes": 1, "new_edges": 1, "evidence_links": 1})
        self.assertEqual((current, step, pending_node), before)
        reopened = WorkflowRepository(self.store)
        self.assertEqual(reopened.get_run("run1")["graph_revision"], 1)
        self.assertEqual(reopened.get_step(step["id"])["status"], "completed")
        self.assertEqual(reopened.commit_step(current, step, [node("ignored")], [edge()]), delta)
        self.assertEqual(len(reopened.nodes("run1")), 2)
        self.assertEqual(len(reopened.edges("run1")), 1)
        self.assertEqual(reopened.get_run("run1")["graph_revision"], 1)

    def test_later_discovery_merges_lists_without_unusing_seed_or_duplicate_edges(self):
        current, step = self.begin()
        self.repo.commit_step(current, step, [node("b", "other.example")], [edge()])
        current, step = self.begin(self.step("step2", 2))
        enriched = node(context=["original report", "provider context"], sources=["rapiddns"],
                        passage_ids=["p1", "p2"], evidence_ids=["ev2"], lookup_ids=["lookup2"], origin="lookup")
        repeated = edge(left="b", right="a", evidence_ids=["ev1", "ev2", "ev2"], lookup_ids=["lookup2"])
        delta = self.repo.commit_step(current, step, [enriched], [repeated, repeated])
        self.assertEqual(delta, {"new_nodes": 0, "new_edges": 0, "evidence_links": 1})
        saved = self.repo.nodes("run1")[0]
        self.assertTrue(saved["used"])
        self.assertEqual(saved["origin"], "report")
        self.assertEqual(saved["context"], ["original report", "provider context"])
        self.assertEqual(saved["sources"], ["cti report", "rapiddns"])
        self.assertEqual(saved["passage_ids"], ["p1", "p2"])
        self.assertEqual(self.repo.edges("run1")[0]["evidence_ids"], ["ev1", "ev2"])
        self.assertEqual(self.repo.edges("run1")[0]["lookup_ids"], ["lookup1", "lookup2"])

    def test_reverse_methods_remain_distinct_edges(self):
        current, step = self.begin()
        reverse = edge("ba", left="b", right="a", method_id="test.reverse", evidence_ids=["ev2"])
        delta = self.repo.commit_step(current, step, [node("b", "other.example")], [edge(), reverse])
        self.assertEqual(delta, {"new_nodes": 1, "new_edges": 2, "evidence_links": 2})
        self.assertEqual({item["method_id"] for item in self.repo.edges("run1")}, {"test.method", "test.reverse"})

    def test_bad_edge_rolls_back_nodes_graph_revision_and_step_completion(self):
        current, step = self.begin()
        with self.assertRaisesRegex(ValueError, "endpoint"):
            self.repo.commit_step(current, step, [node("b", "other.example")], [edge(), edge("bad", right="missing")])
        self.assertEqual(len(self.repo.nodes("run1")), 1)
        self.assertEqual(self.repo.edges("run1"), [])
        self.assertEqual(self.repo.get_run("run1")["graph_revision"], 0)
        self.assertEqual(self.repo.get_step(step["id"])["status"], "running")
        self.assertNotIn("delta", self.repo.get_step(step["id"]))

    def test_pending_step_cannot_change_selected_method(self):
        current, step = self.begin()
        with self.assertRaisesRegex(WorkflowConflict, "method_id"):
            self.repo.update_step({**step, "method_id": "other.method"})
        with self.assertRaisesRegex(WorkflowConflict, "method_id"):
            self.repo.commit_step(current, {**step, "method_id": "other.method"}, [], [])
        self.assertEqual(self.repo.get_step(step["id"])["method_id"], "test.method")

    def test_stale_revision_rejected_and_completed_replay_preserves_later_run(self):
        current, step1 = self.begin()
        delta1 = self.repo.commit_step(current, step1, [], [])
        with self.assertRaisesRegex(WorkflowConflict, "reload"):
            self.repo.save_run(self.run)
        with self.assertRaisesRegex(WorkflowConflict, "reload"):
            self.repo.begin_step(current, self.step("step2", 2))
        next_run, step2 = self.begin(self.step("step2", 2))
        next_run["status"] = "ready"
        self.repo.commit_step(next_run, step2, [], [])
        self.assertEqual(self.repo.commit_step(current, step1, [], []), delta1)
        self.assertEqual(self.repo.get_run("run1")["graph_revision"], 2)
        self.assertEqual(self.repo.get_run("run1")["status"], "ready")

    def test_completed_step_cannot_be_rewritten_or_completed_outside_transaction(self):
        current, step = self.begin()
        with self.assertRaisesRegex(WorkflowConflict, "commit_step"):
            self.repo.update_step({**step, "status": "completed"})
        self.repo.commit_step(current, step, [], [])
        saved = self.repo.get_step(step["id"])
        self.repo.update_step(saved)
        with self.assertRaisesRegex(WorkflowConflict, "immutable"):
            self.repo.update_step({**saved, "lookup_id": "wrong-receipt"})
        with self.assertRaisesRegex(WorkflowConflict, "already finished"):
            self.repo.begin_step(self.repo.get_run("run1"), step)

    def test_node_identity_collision_and_duplicate_edge_identity_are_rejected(self):
        current, step = self.begin()
        with self.assertRaisesRegex(WorkflowConflict, "different IOCs"):
            self.repo.commit_step(current, step, [node(value="wrong.example")], [])
        with self.assertRaisesRegex(WorkflowConflict, "different stable edge ID"):
            self.repo.commit_step(current, step, [node("b", "other.example")], [edge(), edge("different-id")])
        self.assertEqual(self.repo.edges("run1"), [])

    def test_create_run_failure_is_atomic_and_unknown_reads_are_explicit(self):
        with self.assertRaisesRegex(ValueError, "list of strings"):
            self.repo.create_run({"id": "broken"}, [node(context="not a list")])
        with self.assertRaises(KeyError):
            self.repo.get_run("broken")
        with self.assertRaises(KeyError):
            self.repo.nodes("broken")
        with self.assertRaises(KeyError):
            self.repo.get_step("missing")

    def test_future_schema_is_rejected_without_changing_evidence_or_tables(self):
        with self.store.connect() as db:
            db.execute("UPDATE wf_schema SET version=99 WHERE id=1")
            db.execute("INSERT INTO budgets VALUES ('2026-11-04', 'rapiddns', 2)")
        with self.assertRaisesRegex(WorkflowConflict, "schema version: 99"):
            WorkflowRepository(self.store)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT version FROM wf_schema").fetchone()[0], 99)
            self.assertEqual(db.execute("SELECT calls FROM budgets").fetchone()[0], 2)
        self.assertEqual(self.repo.get_run("run1"), self.run)


if __name__ == "__main__":
    unittest.main()
