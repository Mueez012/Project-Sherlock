"""Stored response-header evidence, using synthetic data and no provider calls."""
from hashlib import sha256
import json
import unittest

from ioc_hunter.method_spec import supported_method
from ioc_hunter.models import IOC
from ioc_hunter.providers.common import (
    ObservationBuilder, content_disposition_filename, url_filename,
)
from ioc_hunter.transport.models import Document, LookupError


class ContentDispositionFilenameTests(unittest.TestCase):
    def test_token_quoted_delimiters_and_escaped_quote(self):
        cases = {
            'attachment; filename=report.csv': 'report.csv',
            'INLINE; FILENAME="quarter 1; report, final.csv"': 'quarter 1; report, final.csv',
            'attachment; filename="a\\\"b.txt"': 'a"b.txt',
            ' attachment \t; filename = "résumé.txt" ': 'résumé.txt',
            # Ordinary filename parameters do not percent-decode their contents.
            'attachment; filename="report%20one.txt"': 'report%20one.txt',
        }
        for header, expected in cases.items():
            with self.subTest(header=header):
                self.assertEqual(content_disposition_filename(header), expected)

    def test_extended_filename_precedence_language_and_charsets(self):
        cases = {
            "attachment; filename=ascii.txt; filename*=UTF-8''caf%C3%A9.txt": 'café.txt',
            "attachment; filename*=utf-8'en'%E2%82%AC%20rates.pdf; filename=fallback.pdf": '€ rates.pdf',
            "attachment; filename*=ISO-8859-1''caf%E9.txt": 'café.txt',
            "attachment; filename*=US-ASCII'en-US'report%20one.txt": 'report one.txt',
            "attachment; filename*=UTF-8''a+b.txt": 'a+b.txt',
        }
        for header, expected in cases.items():
            with self.subTest(header=header):
                self.assertEqual(content_disposition_filename(header), expected)

    def test_valid_disposition_without_filename_is_no_data(self):
        for header in ('attachment', 'inline; creation-date="yesterday"'):
            with self.subTest(header=header):
                self.assertIsNone(content_disposition_filename(header))

    def test_duplicate_and_multiple_values_fail_closed(self):
        headers = (
            'attachment; filename=a.txt; FILENAME=b.txt',
            "attachment; filename*=UTF-8''a.txt; FILENAME*=UTF-8''b.txt",
            'attachment; x=a; X=b; filename=a.txt',
            'attachment; filename=a.txt, attachment; filename=b.txt',
            'attachment, inline; filename=a.txt',
            "attachment; filename*0*=UTF-8''part; filename*1*=two.txt",
        )
        self.assert_invalid(headers)

    def test_malformed_extended_value_does_not_fall_back(self):
        headers = (
            "attachment; filename=safe.txt; filename*=UTF-8''bad%2.txt",
            "attachment; filename=safe.txt; filename*=UTF-8''bad%GG.txt",
            "attachment; filename=safe.txt; filename*=UTF-8''bad%FF.txt",
            "attachment; filename=safe.txt; filename*=UTF-16''name.txt",
            "attachment; filename*=UTF-8'name.txt",
            'attachment; filename*="UTF-8\'\'name.txt"',
            "attachment; filename*=UTF-8''café.txt",
            "attachment; filename*=UTF-8'en--US'name.txt",
        )
        self.assert_invalid(headers)

    def test_paths_and_control_characters_are_never_repaired(self):
        headers = (
            'attachment; filename="../payload.exe"',
            'attachment; filename="..\\payload.exe"',
            'attachment; filename="C:\\payload.exe"',
            'attachment; filename="C:payload.exe"',
            'attachment; filename="/tmp/payload.exe"',
            'attachment; filename=".."',
            'attachment; filename="."',
            'attachment; filename=" padded.txt"',
            'attachment; filename="padded.txt "',
            "attachment; filename*=UTF-8''..%2Fpayload.exe",
            "attachment; filename*=UTF-8''..%5Cpayload.exe",
            "attachment; filename*=UTF-8''null%00.exe",
            "attachment; filename*=UTF-8''delete%7F.exe",
            "attachment; filename*=UTF-8''control%C2%85.exe",
            "attachment; filename*=UTF-8''hidden%E2%80%AE.exe",
            'attachment; filename="bad\tname.txt"',
            'attachment; filename="bad\r\nname.txt"',
        )
        self.assert_invalid(headers)

    def test_malformed_grammar_is_not_a_successful_empty(self):
        self.assert_invalid((None, [], '', '; filename=a.txt', 'attachment;',
                             'attachment; filename', 'attachment; filename=',
                             'attachment; filename="unfinished',
                             'attachment; filename="name.txt"suffix',
                             'attachment; filename=two words.txt'))

    def assert_invalid(self, headers):
        for header in headers:
            with self.subTest(header=header):
                with self.assertRaises(LookupError) as error:
                    content_disposition_filename(header)
                self.assertEqual(error.exception.status, 'parse_error')


class URLFilenameEvidenceTests(unittest.TestCase):
    query = 'https://download.sysinternals.com/download/guess.exe?file=wrong.txt'

    def builder(self, attrs, query=None):
        body = json.dumps({'data': {'attributes': attrs}}, ensure_ascii=False)
        document = Document('https://www.virustotal.com/ui/urls/stored-id', body, 'json')
        method = supported_method('virustotal', 'url', 'filename', 'url_details')
        return ObservationBuilder(IOC(query or self.query, 'url'), method, document)

    def test_exact_stored_header_provenance_and_case_insensitive_name(self):
        header = "attachment; filename=plain.txt; filename*=UTF-8''actual%20name.pdf"
        attrs = {'url': self.query,
                 'last_http_response_headers': {'cOnTeNt-DiSpOsItIoN': header}}
        builder = self.builder(attrs)
        url_filename(builder, attrs, '$.data.attributes.url')
        observation, = builder.result.observations
        self.assertEqual((observation.ioc.type, observation.ioc.value), ('filename', 'actual name.pdf'))
        self.assertEqual(observation.evidence.fact_type, 'url_filename')
        self.assertEqual(observation.evidence.facts,
                         {'url': self.query, 'filename': 'actual name.pdf', 'header': header})
        self.assertEqual(observation.evidence.locator,
                         '$.data.attributes.last_http_response_headers["cOnTeNt-DiSpOsItIoN"]')
        self.assertEqual(observation.evidence.response_sha256,
                         sha256(builder.document.body.encode()).hexdigest())
        self.assertIn(header, json.loads(observation.evidence.excerpt)['last_http_response_headers'].values())
        self.assertTrue(builder.result.complete)

    def test_missing_optional_filename_data_is_completed_empty_without_guessing(self):
        for extra in ({}, {'last_http_response_headers': {}},
                      {'last_http_response_headers': {'Content-Type': 'application/octet-stream'}},
                      {'last_http_response_headers': {'Content-Disposition': 'attachment'}}):
            attrs = {'url': self.query, **extra}
            builder = self.builder(attrs)
            url_filename(builder, attrs, '$.data.attributes.url')
            with self.subTest(extra=extra):
                self.assertEqual(builder.result.observations, [])
                self.assertEqual(builder.result.reason, 'filename_unavailable')
                self.assertTrue(builder.result.complete)

    def test_wrong_or_missing_url_identity_fails_even_without_headers(self):
        for attrs in ({}, {'url': None}, {'url': 'not a URL'},
                      {'url': 'https://www.python.org/download'}):
            builder = self.builder(attrs)
            with self.subTest(attrs=attrs):
                with self.assertRaises(LookupError) as error:
                    url_filename(builder, attrs, '$.data.attributes.url')
                self.assertEqual(error.exception.status, 'parse_error')
                self.assertEqual(builder.result.observations, [])

    def test_url_identity_normalizes_host_but_preserves_case_sensitive_path(self):
        attrs = {'url': 'HTTPS://DOWNLOAD.SYSINTERNALS.COM/Download',
                 'last_http_response_headers': {'Content-Disposition': 'attachment; filename=actual.txt'}}
        builder = self.builder(attrs, query='https://download.sysinternals.com/Download')
        url_filename(builder, attrs, '$.data.attributes.url')
        self.assertEqual(builder.result.observations[0].evidence.facts['url'], 'https://download.sysinternals.com/Download')
        wrong = self.builder(attrs, query='https://download.sysinternals.com/download')
        with self.assertRaises(LookupError):
            url_filename(wrong, attrs, '$.data.attributes.url')

    def test_malformed_or_multiple_header_representation_fails_closed(self):
        values = (None, [], 'Content-Disposition: attachment; filename=x.txt',
                  {'Content-Disposition': ['attachment; filename=x.txt']},
                  {'Content-Disposition': 'attachment; filename=x.txt',
                   'content-disposition': 'attachment; filename=y.txt'},
                  {1: 'attachment; filename=x.txt'}, {'Content-Type': None})
        for headers in values:
            attrs = {'url': self.query, 'last_http_response_headers': headers}
            builder = self.builder(attrs)
            with self.subTest(headers=headers):
                with self.assertRaises(LookupError) as error:
                    url_filename(builder, attrs, '$.data.attributes.url')
                self.assertEqual(error.exception.status, 'parse_error')
                self.assertEqual(builder.result.observations, [])

    def test_unrelated_link_fields_do_not_affect_filename_operation(self):
        attrs = {'url': self.query, 'outgoing_links': 'irrelevant malformed link list',
                 'redirection_chain': {'irrelevant': 'value'},
                 'last_http_response_headers': {'Content-Disposition': 'attachment; filename=actual.txt'}}
        builder = self.builder(attrs)
        url_filename(builder, attrs, '$.data.attributes.url')
        self.assertEqual([x.ioc.value for x in builder.result.observations], ['actual.txt'])


if __name__ == '__main__':
    unittest.main()
