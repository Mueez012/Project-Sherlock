"""Explicit offline fixture transport. Unmapped requests fail without networking."""

from hashlib import sha256
import json
from pathlib import Path

from ..providers import requests_for
from ..transport import Document, LookupError, allowed_url, check_status


class ReplayTransport:
    offline = True

    def __init__(self, manifest: str | Path):
        self.path = Path(manifest).resolve()
        raw = self.path.read_bytes()
        self.digest = sha256(raw).hexdigest()
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("documents"), list):
            raise ValueError("Replay manifest requires version 1 and a documents array")
        self.documents = {}
        self.requests = []
        for entry in data["documents"]:
            if not isinstance(entry, dict):
                raise ValueError("Each replay document must be an object")
            source, url = entry["source"], entry["request_url"]
            if not allowed_url(source, url):
                raise ValueError("Replay requests must name a configured provider URL")
            key = (source, url, entry.get("operation", "dns"))
            if key in self.documents:
                raise ValueError("Duplicate request in replay manifest")
            document = dict(entry)
            status_code = entry.get("status_code", 200)
            if type(status_code) is not int or not 100 <= status_code <= 599:
                raise ValueError("Replay status_code must be an HTTP status integer")
            if "body_file" in entry:
                body_path = (self.path.parent / entry["body_file"]).resolve()
                if not body_path.is_relative_to(self.path.parent):
                    raise ValueError("Replay body files must stay inside the fixture directory")
                document["body"] = body_path.read_text(encoding="utf-8")
            if "body" not in document and not document.get("error_status"):
                raise ValueError("Replay document requires body, body_file or error_status")
            self.documents[key] = document
        # Include fixture bodies in identity so changing a body file is detected on resume.
        self.digest = sha256(json.dumps(self.documents_as_list(), sort_keys=True).encode()).hexdigest()

    def documents_as_list(self):
        return [self.documents[key] for key in sorted(self.documents)]

    def supports(self, ioc, method) -> bool:
        return any((request.source, request.url, request.operation) in self.documents
                   for _, request in requests_for(ioc, method, ""))

    def cache_scope(self) -> str:
        return "replay:" + self.digest

    def fetch(self, request):
        self.requests.append(request)
        entry = self.documents.get((request.source, request.continuation_url or request.url, request.operation))
        if entry is None:
            raise LookupError("replay_missing", "No offline fixture matches this provider request")
        if entry.get("error_status"):
            raise LookupError(entry["error_status"], entry.get("error", "Recorded offline provider failure"))
        document = Document(
            entry.get("response_url", entry["request_url"]), entry["body"], entry.get("format", "html"),
            transport="replay", fetched_at=entry.get("retrieved_at", "2026-01-01T00:00:00+00:00"),
            status_code=entry.get("status_code", 200), diagnostics=entry.get("diagnostics", {}),
        )
        try:
            check_status(document.status_code)
        except LookupError as exc:
            exc.document = document
            raise
        return document
