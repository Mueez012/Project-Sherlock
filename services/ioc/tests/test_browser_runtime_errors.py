"""Local Playwright startup diagnostics without launching a browser or networking."""
from contextlib import contextmanager
import importlib.util
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ioc_hunter import IOC, LookupClient
from ioc_hunter.storage import EvidenceStore
from ioc_hunter.transport import BrowserTransport, FetchRequest, LookupError


@unittest.skipUnless(importlib.util.find_spec('playwright'), 'Optional browser dependency not installed')
class BrowserRuntimeErrorTests(unittest.TestCase):
    request = FetchRequest('alienvault', 'https://otx.alienvault.com/indicator/domain/example.com', 'dns')

    def failure_runtime(self, error):
        launch = Mock(side_effect=error)

        @contextmanager
        def runtime():
            yield SimpleNamespace(chromium=SimpleNamespace(launch=launch))

        return runtime, launch

    def fetch_error(self, error, *, headless=True):
        runtime, launch = self.failure_runtime(error)
        with patch('playwright.sync_api.sync_playwright', runtime):
            with self.assertRaises(LookupError) as caught:
                BrowserTransport(headless=headless).fetch(self.request)
        launch.assert_called_once_with(headless=headless, timeout=30000)
        self.assertIs(caught.exception.__cause__, error)
        self.assertIsNone(caught.exception.document)
        self.assertNotIn('private-browser-path', str(caught.exception))
        self.assertNotIn('private-token', str(caught.exception))
        return caught.exception

    def test_missing_matching_binary_names_same_environment_command(self):
        from playwright.sync_api import Error
        error = self.fetch_error(Error("BrowserType.launch: Executable doesn't exist at /private-browser-path private-token"))
        self.assertEqual(error.status, 'browser_binary_missing')
        self.assertIn('matching this Playwright installation', str(error))
        self.assertIn('python -m playwright install chromium --only-shell', str(error))
        self.assertIn('same Python environment', str(error))

    def test_headful_missing_binary_requires_full_chromium(self):
        from playwright.sync_api import Error
        error = self.fetch_error(Error("Executable doesn't exist at /private-browser-path"), headless=False)
        self.assertEqual(error.status, 'browser_binary_missing')
        self.assertIn('python -m playwright install chromium', str(error))
        self.assertNotIn('--only-shell', str(error))

    def test_known_missing_host_libraries_name_dependency_command(self):
        from playwright.sync_api import Error
        for text in ('Host system is missing dependencies to run browsers. private-token',
                     '/private-browser-path: error while loading shared libraries: libexample.so private-token'):
            with self.subTest(message=text):
                error = self.fetch_error(Error(text))
                self.assertEqual(error.status, 'browser_dependencies_missing')
                self.assertIn('python -m playwright install-deps chromium', str(error))
                self.assertIn('same environment', str(error))

    def test_unknown_playwright_error_retains_sanitized_generic_status(self):
        from playwright.sync_api import Error
        error = self.fetch_error(Error('Unexpected failure private-browser-path private-token'))
        self.assertEqual(error.status, 'browser_error')
        self.assertEqual(str(error), 'Browser lookup failed: Error')

    def test_arbitrary_non_playwright_error_is_not_misclassified(self):
        error = self.fetch_error(RuntimeError("Executable doesn't exist private-browser-path private-token"))
        self.assertEqual(error.status, 'browser_error')
        self.assertEqual(str(error), 'Browser lookup failed: RuntimeError')

    def test_existing_lookup_error_passes_through(self):
        original = LookupError('access_denied', 'Access denied')
        runtime, launch = self.failure_runtime(original)
        with patch('playwright.sync_api.sync_playwright', runtime):
            with self.assertRaises(LookupError) as caught:
                BrowserTransport().fetch(self.request)
        self.assertIs(caught.exception, original)
        self.assertIsNone(caught.exception.document)
        launch.assert_called_once()

    def test_startup_failure_receipt_retains_actionable_error_without_snapshots(self):
        from playwright.sync_api import Error
        runtime, launch = self.failure_runtime(Error("Executable doesn't exist at /private-browser-path private-token"))
        with tempfile.TemporaryDirectory() as directory:
            store = EvidenceStore(directory)
            client = LookupClient(store=store, browser=BrowserTransport(), api_keys={}, interval=0)
            with patch('playwright.sync_api.sync_playwright', runtime):
                with self.assertRaises(LookupError) as caught:
                    client.lookup_detailed(IOC('example.com', 'domain'), 'alienvault.domain_to_ipv4')
            receipt = store.get_record(caught.exception.lookup_id)
        self.assertEqual(receipt['status'], 'browser_binary_missing')
        self.assertEqual(receipt['responses'], [])
        self.assertEqual(receipt['transport_errors'][0]['status'], 'browser_binary_missing')
        self.assertIn('python -m playwright install chromium --only-shell', receipt['error'])
        self.assertNotIn('private-browser-path', str(receipt))
        self.assertNotIn('private-token', str(receipt))
        launch.assert_called_once()


if __name__ == '__main__':
    unittest.main()
