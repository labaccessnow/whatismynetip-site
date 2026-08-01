# whatismynetip.com

A fast, no-nonsense set of free network tools — what's my IP, subnet math, DNS lookups,
port and TLS checks, dynamic DNS, and short links. No ads, no sign-up for the instant tools.

Live at **https://whatismynetip.com**

## Layout

| Path | What it is |
|---|---|
| `index.html` | The whole static hub — every instant tool runs client-side (subnet calc, DNS-over-HTTPS lookups, MAC/OUI, IP display) |
| `worker/` | `netip-edge`, a Cloudflare Worker: IP API, dynamic DNS, short links, and a daily expiry sweep |
| `probe/` | Stdlib-only Python backend for the checks a Worker can't do — anything needing a raw outbound TCP/TLS connection |

## Backend

There is no public API and no published endpoint list — the backends exist to serve the site's
own page. The Worker answers only the paths the page calls, returns a bare 404 on everything
else including `/`, and the two server-side checks are POST-only, Origin-gated and
Turnstile-verified rather than URLs anyone can paste.

The guards that matter, if you're reading the source:

- The port check only ever connects back to **the caller's own public IP**, never an arbitrary
  target, so it cannot be turned into a scanner or a reflector.
- The TLS check resolves the hostname first and refuses private, loopback, link-local and
  reserved space, then connects to the validated IP with SNI — that closes SSRF and defeats
  DNS rebinding.
- Dynamic DNS is the one unavoidably public surface: routers speak dyndns2 to a URL directly,
  so that path stays reachable. Each user gets their own hostname and token; nothing generic
  is documented on the site.

## Running it

The Worker needs a KV namespace plus three secrets — `CF_API_TOKEN` (DNS:Edit on the zone,
used to create and patch the dynamic-DNS records), `TURNSTILE_SECRET`, and `MAILER_KEY` —
then `wrangler deploy`.

The probe is a single file on `python:3.12-slim` with no dependencies, listening on `:8080`
behind a reverse proxy that sets `X-Real-IP`. Mail delivery for DDNS tokens is configured
entirely by environment — `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAILER_KEY`.
With `SMTP_HOST` unset, `/send-ddns-token` returns 503 instead of silently failing.

## Roadmap

Built: IP display with geo/ASN/reverse-DNS, subnet and CIDR calculator, DNS lookup over DoH,
dynamic DNS, short links, port checker, TLS certificate checker.

Planned: IP-in-subnet checker, IP ↔ binary/hex/integer conversion, IPv6 expand and compress,
MAC/OUI vendor lookup, dual-stack "am I on IPv6?" test, HTTP header and redirect inspector,
DNS propagation across multiple public resolvers, WHOIS, and a request bin for webhook debugging.
