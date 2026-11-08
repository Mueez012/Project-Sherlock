# Frontend API reference: saved IOC investigations

Open **index.html** for the complete offline reference.

- [Readable reference](index.html)
- [Markdown reference](FRONTEND_API_REFERENCE.md)
- [OpenAPI specification](openapi.json)
- [JavaScript client example](frontend-client.mjs)
- [Captured request/response examples](examples/manifest.json)

The reference covers the hub's `/api/investigations` routes, full models, report highlighting, retries, recovery,
graph/evidence rendering and current limitations. The hub forwards these routes unchanged to IOC Hunter's
`/v1/investigations`. There are no users and no login. The example payloads are synthetic offline captures, not live
provider results.

To regenerate from the repo root, with a Python environment that has the hub and IOC extraction/API dependencies,
`markdown-it-py` and `jsonschema`:

```text
python services/ioc/scripts/build_frontend_api_docs.py
node services/ioc/scripts/verify_frontend_api_client.mjs
```

The builder exercises the real HTTP routes against temporary replay stores, validates captured responses against
OpenAPI, and rebuilds the Markdown, HTML and examples. Human prose is maintained in
`services/ioc/scripts/templates/frontend-api-reference.md`. No live providers are contacted.
