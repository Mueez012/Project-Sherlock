# Additional relationships outside Figure 3 — information only

None of these relationships is enabled in the ontology or method registry.
These are possible investigation relationships when supported by explicit evidence;
they are not assertions that every provider offers a free lookup in both directions.
A shared report/pulse, country, port number or hosting IP is not proof of common
ownership, maliciousness, or communication.

## Complete excluded pair list for the seven existing extraction types

Treat an edge as an unordered type pair, including same-type relationships between
different entities. With domain, ipv4, ipv6, url, md5, sha1 and sha256 there are 28
possible type pairs. Figure 3 permits seven; the following **21** are outside it.

| Excluded pair | Example relationship requiring source evidence |
| --- | --- |
| domain — domain | CNAME, parent/subdomain, MX or NS target |
| domain — md5 | File identified by MD5 contacts or embeds this domain |
| domain — sha1 | File identified by SHA-1 contacts or embeds this domain |
| domain — sha256 | File identified by SHA-256 contacts or embeds this domain |
| ipv4 — url | URL's observed serving/contacted IPv4; distinguish literal URL host from historical observations |
| ipv6 — url | URL's observed serving/contacted IPv6 |
| ipv4 — md5 | File contacts or embeds this IPv4 |
| ipv4 — sha1 | File contacts or embeds this IPv4 |
| ipv4 — sha256 | File contacts or embeds this IPv4 |
| ipv6 — md5 | File contacts or embeds this IPv6 |
| ipv6 — sha1 | File contacts or embeds this IPv6 |
| ipv6 — sha256 | File contacts or embeds this IPv6 |
| url — md5 | File downloaded from, contacting, or embedding the URL |
| url — sha1 | File downloaded from, contacting, or embedding the URL |
| url — sha256 | File downloaded from, contacting, or embedding the URL |
| md5 — md5 | Distinct files related by dropped/parent/bundled-file evidence |
| md5 — sha1 | Different digests explicitly identifying the same file, or distinct related files |
| md5 — sha256 | Different digests explicitly identifying the same file, or distinct related files |
| sha1 — sha1 | Distinct files related by dropped/parent/bundled-file evidence |
| sha1 — sha256 | Different digests explicitly identifying the same file, or distinct related files |
| sha256 — sha256 | Distinct files related by dropped/parent/bundled-file evidence |

The seven allowed type pairs are domain–ipv4, domain–ipv6, domain–url,
ipv4–ipv4, ipv4–ipv6, ipv6–ipv6 and url–url. Allowed type membership still requires
relationship evidence. Equality of a hash of the same algorithm identifies the
same IOC; it is not a new edge. Different digests of one file need an explicit
provider identity record, not merely presence together on a page.

Examples are grounded in the documented [VirusTotal domain relationships](https://docs.virustotal.com/reference/domains-object),
[file attributes and relationships](https://docs.virustotal.com/reference/files),
and [URL attributes and relationships](https://docs.virustotal.com/reference/url-object).
Availability varies by provider and account. Reverse queries are separate capabilities.

## Useful additional relationships involving the new metadata types

These are a design inventory, not implemented methods. IP means IPv4 or IPv6;
hash means MD5, SHA-1 or SHA-256. Some are direct provider facts; others are explicitly
derived paths and should be labelled as such if a future ontology adopts them.

| Excluded relationship | Evidence / interpretation |
| --- | --- |
| IP — port | An observed service or network connection at that IP and port |
| IP — protocol | An observed protocol on that endpoint |
| domain — port | A service observed at that hostname and port |
| domain — protocol | A service/connection observed for that hostname |
| URL — port | Explicit URL port or a documented scheme default, labelled as derivation |
| URL — protocol | URL scheme or observed application protocol; distinguish TCP from HTTP |
| hash — port | A sample's connection record includes a destination/source port |
| hash — protocol | Protocol observed in a sample's network behavior |
| hash — filename | Provider file identity lists the filename |
| hash — CVE | Verified exploit/vulnerability association of the file |
| hash — email | File contains an email address or is an explicitly identified email attachment |
| filename — filename | Rename or created/dropped-file relationship with event provenance |
| filename — domain/IP | A specifically identified file's network behavior; filename alone is ambiguous |
| filename — CVE | A specifically identified file exploits or is affected by a vulnerability |
| email — URL | URL included in a message, with message/report evidence |
| email — IP | Sender/relay/header association; email address alone cannot establish this |
| email — filename | Named attachment in a message |
| IP — CVE | A detected vulnerable service on an endpoint |
| domain — CVE | A detected vulnerable service bound to the hostname |
| URL — CVE | An observed exploit endpoint or vulnerable URL |
| domain — geolocation | Derived from a dated domain→IP→location path, not registrant nationality |
| URL — geolocation | Derived from a dated URL→serving-IP→location path |

[VirusTotal IP objects](https://docs.virustotal.com/reference/ip-object) document
port/service information (some premium). The file object documentation describes
sample network behavior and file names. The other rows above are proposed semantic
uses of explicit service, message, or analysis records, not claims of provider
endpoint availability. These are not automatically justified by IOCFinder output.

Generic co-occurrence is possible for any pair, but has intentionally not been
listed as a proven semantic relation. A future co-occurrence graph would need a
separate relation type and must not be mistaken for a direct ontology connection.
