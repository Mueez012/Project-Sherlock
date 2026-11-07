# Frontend API handoff

Give **Project-Sherlock-Frontend-API.zip** to the frontend developer. Extract it
and open **index.html** for the complete offline reference.

- [Readable reference](index.html)
- [Markdown reference](FRONTEND_API_REFERENCE.md)
- [OpenAPI specification](openapi.json)
- [JavaScript client example](frontend-client.mjs)
- [Captured request/response examples](examples/manifest.json)

The reference covers implemented Hub `/api/investigations` endpoints, full
models, user-identity setup, report highlighting, retries, recovery, graph/evidence
rendering and current limitations. The example payloads are synthetic offline
captures, not live provider results.

The live Hub also serves `/docs` and `/openapi.json`. Its deployment address and
identity configuration must be supplied by the backend owner. No real account
credentials, API keys or application database are included in this package.

To regenerate from a checkout, use a Python environment with the Hub and IOC
extraction/API dependencies, `markdown-it-py` and `jsonschema`, then run:

```text
python scripts/build_frontend_api_docs.py
node scripts/verify_frontend_api_client.mjs
```

The builder exercises the real HTTP routes against temporary replay stores,
validates captured responses against OpenAPI, and rebuilds the Markdown, HTML,
examples and ZIP. Human prose is maintained in
`scripts/templates/frontend-api-reference.md`. No live providers are contacted.
