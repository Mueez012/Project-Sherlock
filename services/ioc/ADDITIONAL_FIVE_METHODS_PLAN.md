# Five original candidates using ordinary OTX search

Date: **10 November 2026**. Status: **implemented; automated checks passed**.
The user authorized these five and testing of all implemented work. The final
catalogue is 48/20/68; 445 tests and 252 subtests passed. Live source limits and
actual outcomes are recorded in [the verification report](METHODS_VERIFICATION_20261110.md).
The five advanced-search VT entries remain deferred. The proposal below is
retained as design context; live completion must not be inferred from it.

## Selected methods and scope

| Original candidate | Acquisition and concrete extraction |
| --- | --- |
| `alienvault.email_to_domain` | Search the supplied email as ordinary pulse text; read matching pulses; return typed domain/hostname indicators |
| `alienvault.email_to_email` | Same discovery; return other typed email indicators, with input echoes removed by the existing client |
| `alienvault.geo_location_to_ipv4` | Search country name/code in pulse text; return typed IPv4 indicators in matching pulses |
| `alienvault.port_to_protocol` | Search the port; inspect returned URL indicators with that explicitly written port; return their application protocol schemes |
| `alienvault.protocol_to_port` | Search the protocol; inspect returned URLs with that scheme; return explicitly written numeric ports |

This is ordinary keyword discovery followed by concrete field extraction.
Email discovery searches the actual supplied email, rather than silently using
only its mailbox domain. Country discovery retrieves IPs from country-related
pulses; it does not enumerate IPs physically located in that country or claim a
new geolocation fact. Relationship admission remains the workflow's task.

The initial port/protocol subset covers source URL schemes supported by existing
URL normalization: HTTP, HTTPS and FTP. For example, a returned
`https://www.python.org:8443/path` explicitly supplies `https` and `8443`.
A URL with no explicit port supplies no port output. These methods do not turn
HTTPS into a transport-TCP observation or use default-port tables. TCP, UDP and
other protocol inputs need a separately observed structured source contract to
provide this narrower scheme-matching operation.

## Source evidence and remaining access checks

The [official OTX SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/OTXv2.py)
documents ordinary `search_pulses(query)`, pulse details and indicator retrieval:

- `GET /api/v1/search/pulses?q=...&page=1&limit=25`
- `GET /api/v1/pulses/{id}`
- `GET /api/v1/pulses/{id}/indicators`

Its [official tests](https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/tests/test_client.py)
include keyword search followed by pulse details and typed indicator rows.
[Indicator definitions](https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/IndicatorTypes.py)
include email, domain, hostname, IPv4 and URL. Port/protocol outputs above are
explicit URL-component extraction, not invented native OTX indicator endpoints.

The [official user guide](https://cybersecurity.att.com/documentation/resources/pdf/otx-user-guide.pdf)
describes Search/Browse text matching across pulse names, descriptions and
other fields/keywords. A provider-published historical example links to
[`/browse/?q=juniper`](https://www.levelblue.com/blogs/levelblue-blog/juniper-screenos-backdoor-eavesdropping).
This establishes ordinary keyword UI discovery as a source feature, not its
current browser response path or anonymous access state.

Browser page navigation and page-generated response capture remain primary.
After authorization to proceed, verify the current search page, query binding,
result links, pulse indicator payload, pagination and account requirements.
The documented ordinary API can use the existing configured OTX-key fallback;
no anonymous API entitlement or premium permission is assumed. No new private
XHR path is inferred from an endpoint template.

## Modular implementation plan

1. Add one source-local `otx_pulses.py` helper for literal keyword preparation,
   source search parsing, pulse references and typed indicator extraction.
2. Extend `alienvault.py` with explicit method declarations and the observed
   browser routes plus the documented configured API alternatives.
3. Reuse `FollowUp` and LookupClient for search -> pulse -> indicator reads,
   including existing pacing, retries, cache, limits and receipts.
4. Reuse IOC normalization and ObservationBuilder. Keep URL component extraction
   narrow and source-backed. Return partial results for capped discovery.
5. Extend the method-correctness field guard without adding graph admission,
   confidence checks, or new workflow policy.
6. Prepare meaningful source fixtures and regression cases; execute tests and
   fresh `cache_ttl=0` live checks only after the user's requested decision.

The earlier count was **43 implemented / 25 candidates / 68 total**.
Completing these five original candidates produced **48 / 20 / 68**.
This plan adds no new HA method IDs and does not relabel HA results as OTX.
