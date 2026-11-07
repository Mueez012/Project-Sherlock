"""Build a portable frontend reference from real, offline HTTP responses.

Requires the IOC extraction/API environment plus markdown-it-py and jsonschema.
No provider requests, credentials, application database or running server are used.
"""

import json
import os
import re
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "api"
TEMPLATE = ROOT / "scripts" / "templates" / "frontend-api-reference.md"
EXAMPLE = ROOT / "services" / "ioc" / "examples" / "manual-workflow"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def capture_examples():
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT / "services" / "ioc"))
    from uuid import uuid4

    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from ioc_hunter.api.errors import install_error_handlers
    from ioc_hunter.api.investigations import router as ioc_router
    from ioc_hunter.workflow.service import InvestigationService

    from threatmamba.api import investigations as proxy
    from threatmamba.api.main import app as hub_app
    from threatmamba.clients.investigations import IOCInvestigationClient

    warnings.filterwarnings("ignore", category=DeprecationWarning)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    examples = OUTPUT / "examples"
    examples.mkdir(exist_ok=True)
    specification = hub_app.openapi()
    specification["servers"] = [
        {"url": "http://localhost:8000", "description": "Hub development server; change to your deployment"},
        {"url": "http://localhost:3000", "description": "Existing Next.js development proxy"},
    ]
    specification["info"]["description"] = (
        "Frontend handoff snapshot, 7 November 2026. Browser clients use /api/investigations. "
        "Authentication verification is supplied by an external identity provider; there is no login/token issuer. "
        "Explicit local development mode uses no Authorization header. See FRONTEND_API_REFERENCE.md."
    )
    write_json(OUTPUT / "openapi.json", specification)
    manifest = {
        "description": (
            "Synthetic fixture data generated through the actual Hub and IOC HTTP routes; no live provider calls."
        ),
        "documentation_date": "2026-11-07",
        "redactions": {"export-response.json": ["run.replay.manifest: absolute server path replaced"]},
        "captures": [],
    }
    result_data = {}
    previous_actor = os.environ.get("IOC_HUNTER_LOCAL_ACTOR")
    previous_proxy = proxy._client
    os.environ["IOC_HUNTER_LOCAL_ACTOR"] = "documentation"
    try:
        with tempfile.TemporaryDirectory(prefix="sherlock-api-docs-") as directory:
            scratch = Path(directory)
            ioc_app = FastAPI()
            ioc_app.include_router(ioc_router)
            install_error_handlers(ioc_app)
            ioc_app.state.investigation_service = InvestigationService(
                scratch / "store", replay_path=EXAMPLE / "replay.json"
            )
            with TestClient(ioc_app) as ioc, TestClient(hub_app) as hub:
                failure = {"network": False}

                def forward(request):
                    if failure["network"]:
                        raise httpx.ConnectError("Synthetic offline transport failure", request=request)
                    response = ioc.request(
                        request.method,
                        request.url.raw_path.decode(),
                        content=request.content if request.content else None,
                        headers={key: value for key, value in request.headers.items() if key.lower() != "host"},
                    )
                    return httpx.Response(response.status_code, content=response.content, headers=response.headers)

                remote = IOCInvestigationClient("http://ioc-doc-fixture", transport=httpx.MockTransport(forward))
                proxy._client = lambda: remote

                def capture(name, method, path, pattern, status=200, body=None, headers=None):
                    response = hub.request(method, path, json=body, headers=headers)
                    if response.status_code != status:
                        raise RuntimeError(f"{name}: expected {status}, got {response.status_code}: {response.text}")
                    data = response.json()
                    if name == "export":
                        data["run"]["replay"]["manifest"] = "/server-managed-fixtures/manual-workflow/replay.json"
                    response_name = f"{name}-response.json"
                    write_json(examples / response_name, data)
                    request_name = None
                    if body is not None:
                        request_name = f"{name}-request.json"
                        write_json(examples / request_name, body)
                    declaration = specification["paths"][pattern][method.lower()]["responses"].get(str(status), {})
                    schema = declaration.get("content", {}).get("application/json", {}).get("schema")
                    manifest["captures"].append(
                        {
                            "name": name,
                            "method": method,
                            "path": path,
                            "openapi_path": pattern,
                            "status": status,
                            "request_file": request_name,
                            "response_file": response_name,
                            "request_headers": headers or {},
                            "response_headers": {
                                key: value
                                for key, value in response.headers.items()
                                if key in {"content-type", "location", "content-disposition"}
                            },
                            "response_schema": schema,
                        }
                    )
                    result_data[name] = {"request": body, "response": data}
                    return data

                prefix = "/api/investigations"
                request = {
                    "text": (EXAMPLE / "report.txt").read_text(encoding="utf-8"),
                    "source": "synthetic-example.txt",
                    "include_references": False,
                    "extended_types": False,
                    "limits": {
                        "max_steps": 20,
                        "max_nodes": 1000,
                        "max_seconds": 600,
                        "max_pages": 2,
                        "max_outputs": 1000,
                    },
                }
                key = uuid4().hex
                saved = capture("create", "POST", prefix, prefix, 201, request, {"Idempotency-Key": key})
                run_id = saved["run"]["id"]
                base, pattern = f"{prefix}/{run_id}", f"{prefix}/{{run_id}}"
                domain = next(node for node in saved["graph"]["nodes"] if node["value"] == "example.com")
                hash_node = next(node for node in saved["graph"]["nodes"] if node["type"] == "sha256")
                capture(
                    "methods", "GET", f"{base}/nodes/{domain['id']}/methods", f"{pattern}/nodes/{{node_id}}/methods"
                )
                capture(
                    "methodless",
                    "GET",
                    f"{base}/nodes/{hash_node['id']}/methods",
                    f"{pattern}/nodes/{{node_id}}/methods",
                )
                step_request = {
                    "step_id": uuid4().hex,
                    "input_node_id": domain["id"],
                    "method_id": "rapiddns.domain_to_ipv4",
                    "expected_graph_revision": 1,
                }
                first = capture("step", "POST", base + "/steps", pattern + "/steps", 201, step_request)
                discovered = next(node for node in first["graph"]["nodes"] if node["value"] == "192.0.2.12")
                second_request = {
                    "step_id": uuid4().hex,
                    "input_node_id": discovered["id"],
                    "method_id": "rapiddns.ipv4_to_domain",
                    "expected_graph_revision": first["run"]["graph_revision"],
                }
                capture("nonadmitted-step", "POST", base + "/steps", pattern + "/steps", 201, second_request)
                capture("snapshot", "GET", base, pattern)
                capture("history", "GET", prefix + "?limit=50&offset=0&status=ready", prefix)
                capture("step-replay", "POST", base + "/steps", pattern + "/steps", 200, step_request)
                capture(
                    "step-detail",
                    "GET",
                    f"{base}/steps/{step_request['step_id']}?include_snapshots=true",
                    pattern + "/steps/{step_id}",
                )
                capture("resume", "POST", base + "/resume", pattern + "/resume", body={})
                stale = {**step_request, "step_id": uuid4().hex}
                capture("stale-revision", "POST", base + "/steps", pattern + "/steps", 409, stale)
                capture(
                    "validation-error",
                    "POST",
                    prefix,
                    prefix,
                    422,
                    {"text": "Report", "sentences": ["Client sentence"]},
                    {"Idempotency-Key": uuid4().hex},
                )
                capture("not-found", "GET", prefix + "/" + uuid4().hex, pattern, 404)
                capture(
                    "authentication-error",
                    "GET",
                    prefix,
                    prefix,
                    401,
                    headers={"Authorization": "Bearer invalid-local-header"},
                )
                os.environ.pop("IOC_HUNTER_LOCAL_ACTOR")
                capture("authentication-unconfigured", "GET", prefix, prefix, 503)
                os.environ["IOC_HUNTER_LOCAL_ACTOR"] = "documentation"
                failure["network"] = True
                capture("service-unavailable", "GET", base, pattern, 503)
                failure["network"] = False
                capture("close", "POST", base + "/close", pattern + "/close", body={"action": "finish"})
                capture("export", "GET", base + "/export?include_evidence=true", pattern + "/export")
                capture("creation-replay", "POST", prefix, prefix, 200, request, {"Idempotency-Key": key})
                capture(
                    "failed-create",
                    "POST",
                    prefix,
                    prefix,
                    201,
                    {**request, "limits": {"max_nodes": 1}},
                    {"Idempotency-Key": uuid4().hex},
                )

                challenge = scratch / "challenge.json"
                write_json(
                    challenge,
                    {
                        "version": 1,
                        "documents": [
                            {
                                "source": "rapiddns",
                                "request_url": "https://rapiddns.io/subdomain/example.com?page=1",
                                "operation": "dns",
                                "error_status": "challenge",
                                "error": "Synthetic provider challenge",
                            }
                        ],
                    },
                )
                ioc_app.state.investigation_service = InvestigationService(
                    scratch / "challenge-store", replay_path=challenge
                )
                challenge_run = capture(
                    "challenge-create", "POST", prefix, prefix, 201, request, {"Idempotency-Key": uuid4().hex}
                )
                challenge_id = challenge_run["run"]["id"]
                challenge_node = next(
                    node for node in challenge_run["graph"]["nodes"] if node["value"] == "example.com"
                )
                capture(
                    "provider-failure",
                    "POST",
                    f"{prefix}/{challenge_id}/steps",
                    pattern + "/steps",
                    201,
                    {
                        "step_id": uuid4().hex,
                        "input_node_id": challenge_node["id"],
                        "method_id": "rapiddns.domain_to_ipv4",
                        "expected_graph_revision": 1,
                    },
                )
                capture(
                    "cancel", "POST", f"{prefix}/{challenge_id}/close", pattern + "/close", body={"action": "cancel"}
                )
    finally:
        proxy._client = previous_proxy
        if previous_actor is None:
            os.environ.pop("IOC_HUNTER_LOCAL_ACTOR", None)
        else:
            os.environ["IOC_HUNTER_LOCAL_ACTOR"] = previous_actor
    write_json(examples / "manifest.json", manifest)
    return specification, manifest, result_data


def validate_examples(specification, manifest):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    registry = Registry().with_resource(
        "urn:sherlock:openapi",
        Resource.from_contents(
            specification,
            default_specification=DRAFT202012,
        ),
    )
    validated = 0
    for capture in manifest["captures"]:
        schema = capture["response_schema"]
        if schema and "$ref" in schema:
            reference = "urn:sherlock:openapi" + schema["$ref"]
            validator = Draft202012Validator({"$ref": reference}, registry=registry)
            data = json.loads((OUTPUT / "examples" / capture["response_file"]).read_text(encoding="utf-8"))
            validator.validate(data)
            validated += 1
    export = json.loads((OUTPUT / "examples" / "export-response.json").read_text(encoding="utf-8"))
    if export["version"] != 1 or export["report"] != export["run"]["report"]:
        raise RuntimeError("Native export report/format mismatch")
    if export["extraction"] != export["run"]["extraction"]:
        raise RuntimeError("Native export extraction mismatch")
    receipts = {record["id"] for record in export["evidence"]["lookups"]}
    for step in export["steps"]:
        if step["lookup_id"] != step["lookup"]["id"] or step["lookup_id"] not in receipts:
            raise RuntimeError("Native export lost its exact receipt association")
        for response in step["lookup"]["responses"]:
            if response["snapshot_id"] not in export["evidence"]["snapshots"]:
                raise RuntimeError("Native export example lost a source snapshot")
    return validated


def schema_reference(specification):
    names = [
        "CreateInvestigation",
        "InvestigationLimits",
        "CreateInvestigationStep",
        "CloseInvestigation",
        "EmptyRequest",
        "InvestigationSnapshot",
        "RunMetadata",
        "SavedRunConfig",
        "SavedReport",
        "SavedExtraction",
        "SavedIOC",
        "Passage",
        "SavedGraph",
        "GraphNode",
        "GraphEdge",
        "Admission",
        "StepSummary",
        "SavedStep",
        "LookupReceipt",
        "InvestigationList",
        "InvestigationListItem",
        "NodeMethods",
        "MethodRow",
        "StepExecution",
        "StepDetail",
        "SourceSnapshot",
        "InvestigationError",
        "ErrorDetail",
    ]

    def value_type(schema):
        if "$ref" in schema:
            return schema["$ref"].rsplit("/", 1)[-1]
        if "const" in schema:
            return json.dumps(schema["const"])
        if "enum" in schema:
            return " / ".join(json.dumps(item) for item in schema["enum"])
        if "anyOf" in schema:
            return " or ".join(value_type(item) for item in schema["anyOf"])
        kind = schema.get("type", "unknown")
        if kind == "array":
            if "prefixItems" in schema:
                return "[" + ", ".join(value_type(item) for item in schema["prefixItems"]) + "]"
            return "Array<" + value_type(schema.get("items", {})) + ">"
        if kind == "object":
            additional = schema.get("additionalProperties", {})
            if isinstance(additional, dict):
                return "Record<string, " + value_type(additional) + ">"
        return kind

    def notes(schema):
        result = []
        if "default" in schema:
            result.append("default " + json.dumps(schema["default"]))
        for key, label in (
            ("minLength", "min length"),
            ("maxLength", "max length"),
            ("minimum", "minimum"),
            ("maximum", "maximum"),
            ("exclusiveMinimum", "greater than"),
            ("minItems", "min items"),
            ("maxItems", "max items"),
            ("pattern", "pattern"),
        ):
            if key in schema:
                result.append(label + " " + str(schema[key]))
        return "; ".join(result) or "—"

    blocks = []
    for name in names:
        schema = specification["components"]["schemas"][name]
        blocks += [f"### Schema: {name}", ""]
        if schema.get("additionalProperties") is False:
            blocks += ["Unknown fields are rejected.", ""]
        if not schema.get("properties"):
            blocks += ["Empty JSON object `{}`.", ""]
            continue
        blocks += ["| Field | JSON type / model | Required | Default / constraints |", "| --- | --- | --- | --- |"]
        for field, details in schema["properties"].items():
            kind = value_type(details).replace("|", "\\|")
            detail = notes(details).replace("|", "\\|")
            required = "Yes" if field in schema.get("required", []) else "No"
            blocks.append(f"| `{field}` | `{kind}` | {required} | {detail} |")
        blocks.append("")
    return "\n".join(blocks)


def build_html(markdown):
    from markdown_it import MarkdownIt

    parser = MarkdownIt("default", {"html": False}).enable("table")
    tokens = parser.parse(markdown)
    toc, used = [], {}
    for index, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        label = tokens[index + 1].content
        slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
        used[slug] = used.get(slug, 0) + 1
        if used[slug] > 1:
            slug += f"-{used[slug]}"
        token.attrSet("id", slug)
        if token.tag in {"h2", "h3"}:
            from html import escape

            toc.append(f'<a class="{token.tag}" href="#{slug}">{escape(label)}</a>')
    content = parser.renderer.render(tokens, parser.options, {})
    styles = (ROOT / "scripts" / "templates" / "api-reference.css").read_text(encoding="utf-8")
    toc_html = "".join(toc)
    navigation_script = """
document.getElementById("filter").addEventListener("input", function () {
  const query = this.value.toLowerCase();
  document.querySelectorAll("nav a").forEach(link => {
    link.hidden = !link.textContent.toLowerCase().includes(query);
  });
});
"""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Project Sherlock · Frontend API reference</title><style>{styles}</style></head><body>
<header><strong>Project Sherlock</strong>
<p>Frontend API reference · 7 November 2026 · Implemented endpoints</p></header>
<div class="layout"><nav aria-label="Table of contents">
<input id="filter" type="search" placeholder="Filter contents" aria-label="Filter table of contents">
{toc_html}</nav><main>{content}
<footer>Generated from the repository API and offline synthetic responses.
OpenAPI and complete payloads accompany this document.</footer>
</main></div><script>{navigation_script}</script></body></html>
"""


def main():
    specification, manifest, examples = capture_examples()
    validated = validate_examples(specification, manifest)
    markdown = TEMPLATE.read_text(encoding="utf-8")
    substitutions = {
        "CREATE_REQUEST": examples["create"]["request"],
        "STEP_REQUEST": examples["step"]["request"],
        "CLOSE_REQUEST": examples["close"]["request"],
        "ERROR_RESPONSE": examples["stale-revision"]["response"],
    }
    for name, data in substitutions.items():
        markdown = markdown.replace(f"@@{name}@@", json.dumps(data, indent=2, ensure_ascii=False))
    markdown = markdown.replace("@@MODEL_REFERENCE@@", schema_reference(specification))
    if re.search(r"@@[A-Z_]+@@", markdown):
        raise RuntimeError("Unexpanded documentation token")
    (OUTPUT / "FRONTEND_API_REFERENCE.md").write_text(markdown, encoding="utf-8")
    (OUTPUT / "index.html").write_text(build_html(markdown), encoding="utf-8")
    package = OUTPUT / "Project-Sherlock-Frontend-API.zip"
    members = [
        OUTPUT / name
        for name in (
            "README.md",
            "index.html",
            "FRONTEND_API_REFERENCE.md",
            "openapi.json",
            "frontend-client.mjs",
        )
    ]
    members.append(OUTPUT / "examples" / "manifest.json")
    for capture in manifest["captures"]:
        members.append(OUTPUT / "examples" / capture["response_file"])
        if capture["request_file"]:
            members.append(OUTPUT / "examples" / capture["request_file"])
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(members):
            archive.write(path, Path("Project-Sherlock-Frontend-API") / path.relative_to(OUTPUT))
    print(
        f"Built {len(manifest['captures'])} HTTP examples; "
        f"{validated} OpenAPI-validated responses and native export integrity checked."
    )
    print(f"Reference: {OUTPUT / 'index.html'}")
    print(f"Share package: {package}")


if __name__ == "__main__":
    main()
