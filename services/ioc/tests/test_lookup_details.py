"""Call-scoped lookup receipts and fixture/live transport isolation."""
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ioc_hunter import IOC, LookupClient, LookupError
from ioc_hunter.evidence import Evidence, LookupRecord
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import Document

FIXTURE = Path(__file__).parent / 'fixtures' / 'rapiddns.html'
METHOD = 'rapiddns.domain_to_ipv4'


def dns_document(address='192.0.2.10'):
    return Document('https://rapiddns.io/subdomain/example.com?page=1',
                    FIXTURE.read_text(encoding='utf-8').replace('192.0.2.10', address), 'html')


class FixtureTransport:
    def __init__(self, *results, scope='anonymous', offline=True):
        self.results = list(results)
        self.scope, self.offline = scope, offline
        self.requests = []

    def cache_scope(self):
        return self.scope

    def fetch(self, request):
        self.requests.append(request)
        if not self.results:
            raise AssertionError('Unexpected provider request')
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class LookupDetailsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EvidenceStore(self.temp.name)
        self.query = IOC('EXAMPLE.COM', 'domain', ['Original report passage'], 'report')

    def client(self, transport, **limits):
        return LookupClient(store=self.store, http=transport, browser=transport,
                            api_keys={}, interval=0, **limits)

    def test_exact_receipt_retains_supporting_evidence_and_rejections(self):
        client = self.client(FixtureTransport(dns_document()))
        with patch.object(client, 'latest_record', side_effect=AssertionError('No latest query')):
            record = client.lookup_detailed(self.query, METHOD, lookup_id='durable-attempt')
        self.assertEqual(record.id, 'durable-attempt')
        self.assertEqual(self.store.get_record(record.id), record.to_dict())
        self.assertEqual([(i.type, i.value) for i in record.outputs], [('ipv4', '192.0.2.10')])
        self.assertEqual(len(record.accepted), 2)  # Two DNS observations for one IOC.
        self.assertEqual(len({row['evidence_id'] for row in record.accepted}), 2)
        for row in record.accepted:
            self.assertEqual({key: row[key] for key in row if key != 'evidence_id'}, {
                'type': 'ipv4', 'value': '192.0.2.10', 'method_id': METHOD,
                'ontology_label': 'DNS-parse', 'validation': 'supported'})
            self.assertIn(row['evidence_id'], {e.id for e in record.evidence})
        rejected = next(row for row in record.rejected if row['value'] == '192.0.2.11')
        self.assertEqual(rejected['reason'], 'dns_domain_mismatch')
        self.assertEqual(rejected['details']['observed_domain'], 'sub.example.com')
        self.assertNotIn(rejected['evidence_id'], {row['evidence_id'] for row in record.accepted})
        self.assertEqual(self.query.value, 'EXAMPLE.COM')
        self.assertEqual(self.query.context, ['Original report passage'])

    def test_output_limit_excludes_truncated_relationships(self):
        document = dns_document()
        document.body = document.body.replace('sub.example.com', 'example.com')
        record = self.client(FixtureTransport(document), max_outputs=1).lookup_detailed(self.query, METHOD)
        self.assertEqual([ioc.value for ioc in record.outputs], ['192.0.2.10'])
        self.assertEqual({row['value'] for row in record.accepted}, {'192.0.2.10'})
        self.assertEqual(len(record.accepted), 2)
        self.assertEqual(record.status, 'partial')
        self.assertIn('output_limit', record.partial_reasons)
        self.assertTrue(any(e.facts.get('ip') == '192.0.2.11' for e in record.evidence))

    def test_legacy_lookup_and_callable_method_still_return_lists(self):
        client = self.client(FixtureTransport(dns_document()))
        first = client.lookup(self.query, METHOD)
        second = client.method(METHOD)(self.query)
        self.assertIs(type(first), list)
        self.assertEqual([asdict(i) for i in first], [asdict(i) for i in second])
        self.assertTrue(client.latest_record(self.query, METHOD)['cache_hit'])

    def test_roundtrip_and_old_receipt_does_not_infer_accepted_links(self):
        record = self.client(FixtureTransport(dns_document())).lookup_detailed(self.query, METHOD)
        restored = LookupRecord.from_dict(record.to_dict())
        self.assertEqual(restored.to_dict(), record.to_dict())
        self.assertIsInstance(restored.input_ioc, IOC)
        self.assertIsInstance(restored.outputs[0], IOC)
        self.assertIsInstance(restored.evidence[0], Evidence)
        old = record.to_dict()
        del old['accepted']
        restored = LookupRecord.from_dict(old)
        self.assertEqual(restored.accepted, [])
        self.assertTrue(restored.outputs)
        self.assertNotIn('accepted', old)

    def test_provider_error_exposes_preassigned_saved_receipt(self):
        transport = FixtureTransport(LookupError('rate_limited', 'Provider cooldown', retry_after=60))
        client = self.client(transport)
        with self.assertRaises(LookupError) as caught:
            client.lookup_detailed(self.query, METHOD, lookup_id='failed-attempt')
        self.assertEqual(caught.exception.lookup_id, 'failed-attempt')
        record = LookupRecord.from_dict(self.store.get_record('failed-attempt'))
        self.assertEqual(record.status, 'rate_limited')
        self.assertEqual(record.accepted, [])
        self.assertEqual(len(transport.requests), 1)

    def test_process_interrupt_retains_unknown_outcome_without_retry(self):
        for number, interruption in enumerate((KeyboardInterrupt(), SystemExit(2))):
            with self.subTest(interruption=type(interruption).__name__):
                transport = FixtureTransport()
                client = self.client(transport)
                attempt_id = f'interrupted-attempt-{number}'
                with patch.object(client, '_run', side_effect=interruption) as acquisition:
                    with self.assertRaises(type(interruption)):
                        client.lookup_detailed(self.query, METHOD, lookup_id=attempt_id)
                    record = LookupRecord.from_dict(self.store.get_record(attempt_id))
                    self.assertEqual(record.status, 'interrupted_unknown')
                    self.assertFalse(record.complete)
                    self.assertIn('provider completion is unknown', record.error)
                    self.assertTrue(record.finished_at)
                    self.assertEqual(record.accepted, [])
                    acquisition.assert_called_once()
                self.assertEqual(transport.requests, [])

    def test_http_transport_scopes_isolate_replay_from_live_cache(self):
        replay = FixtureTransport(dns_document(), scope='replay:fixture-v1')
        live = FixtureTransport(dns_document('192.0.2.20'), offline=False)
        self.client(replay).lookup_detailed(self.query, METHOD)
        live_record = self.client(live).lookup_detailed(self.query, METHOD)
        self.assertEqual([ioc.value for ioc in live_record.outputs], ['192.0.2.20'])
        self.assertFalse(live_record.cache_hit)
        self.assertEqual(len(live.requests), 1)
        replay_cached = self.client(FixtureTransport(scope='replay:fixture-v1')).lookup_detailed(self.query, METHOD)
        self.assertTrue(replay_cached.cache_hit)
        self.assertEqual([ioc.value for ioc in replay_cached.outputs], ['192.0.2.10'])

    def test_offline_transport_uses_no_provider_pacing_or_daily_budget(self):
        client = self.client(FixtureTransport(dns_document(), scope='replay:fixture'))
        with patch.object(client.limiter, 'wait', side_effect=AssertionError('No replay pacing')):
            client.lookup_detailed(self.query, METHOD)
        with self.store.connect() as database:
            self.assertEqual(database.execute('SELECT COUNT(*) FROM budgets').fetchone()[0], 0)

    def test_http_endpoint_returns_its_own_detailed_receipt(self):
        try:
            from fastapi.testclient import TestClient
            from ioc_hunter import http_api
        except ImportError:
            self.skipTest('Optional HTTP/extraction dependencies not installed')
        client = self.client(FixtureTransport(dns_document()))
        with patch.object(http_api, 'lookup_client', return_value=client), \
                patch.object(client, 'latest_record', side_effect=AssertionError('No latest query')):
            response = TestClient(http_api.app).post('/v1/lookup', json={
                'value': self.query.value, 'type': self.query.type, 'method': METHOD})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['lookup'], self.store.get_record(payload['lookup']['id']))
        self.assertEqual(payload['iocs'], payload['lookup']['outputs'])
        self.assertTrue(payload['lookup']['accepted'])


if __name__ == '__main__':
    unittest.main()
