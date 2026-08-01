"""
whatismynetip probe backend — the tier-2 checks a Cloudflare Worker can't do
(originate raw TCP / TLS). Pure Python stdlib (no deps); runs on python:3.12-slim,
volume-mounted, behind BunkerWeb at probe.whatismynetip.com.

  GET  /health           -> liveness
  POST /port             -> TCP-connect to the CALLER's own public IP:port ("is my port open")
  POST /ssl              -> TLS handshake to host:443, return cert subject/issuer/expiry/chain
  POST /send-ddns-token  -> email a DDNS update token (netip-edge Worker only, X-Mailer-Key auth)

The two checks are POST-only, Origin-gated, and Turnstile-verified — they exist to serve the
site's own page, not as a URL anyone can paste. Nothing here is advertised as a public API.

Security:
  * /port only ever targets the caller's own IP (from X-Real-IP that BunkerWeb sets from
    $remote_addr — not client-spoofable), never an arbitrary IP => not a scanner/reflector.
  * /ssl resolves the host and REFUSES private/loopback/link-local/reserved IPs (SSRF guard),
    then connects to the validated IP with SNI (defeats DNS-rebinding).
  * in-memory per-IP rate limit (30/min); short timeouts; single port per request.
"""
import hmac, ipaddress, json, os, re, smtplib, socket, ssl, threading, time, urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = 8080
ALLOW_ORIGIN = "https://whatismynetip.com"
LIMIT, WINDOW = 30, 60.0
_HITS: dict = {}
_LOCK = threading.Lock()

# Mailer (DDNS token delivery). Host + secrets arrive via env (compose env_file, not in git).
# SMTP_HOST is required: with it unset, /send-ddns-token answers 503 rather than mailing nowhere.
MAILER_KEY = os.environ.get("MAILER_KEY", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "noreply@whatismynetip.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
MAIL_LIMIT, MAIL_WINDOW = 60, 3600.0   # global cap: 60 token mails/hour
_MAIL_HITS = [0, 0.0]

# Anti-bot for /port and /ssl. Same posture as the Worker: fails OPEN when no secret is set,
# so a dev instance without Turnstile still works, and closed once the secret is present.
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")


def from_site(headers) -> bool:
    """The checks serve the page, not the world. Browsers send Origin on a cross-origin POST;
    curl sends nothing unless told to. Deliberately soft — drive-by cover, not access control."""
    origin = headers.get("Origin")
    if origin:
        return origin == ALLOW_ORIGIN
    return headers.get("Referer", "").startswith(ALLOW_ORIGIN + "/")


def verify_turnstile(token: str, ip: str) -> bool:
    if not TURNSTILE_SECRET:
        return True
    if not token:
        return False
    try:
        body = json.dumps({"secret": TURNSTILE_SECRET, "response": token, "remoteip": ip}).encode()
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return bool(json.loads(r.read()).get("success"))
    except Exception as e:
        print(f"turnstile error: {e!r}", flush=True)
        return False


def rate_ok(ip: str) -> bool:
    now = time.monotonic()
    with _LOCK:
        c, t = _HITS.get(ip, (0, 0.0))
        if now - t > WINDOW:
            c, t = 0, now
        c += 1
        _HITS[ip] = (c, t)
        return c <= LIMIT


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_reserved or a.is_multicast or a.is_unspecified)


def port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=4):
            return True
    except OSError:
        return False


def ssl_info(host: str, port: int) -> dict:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        ips = list({i[4][0] for i in infos})
    except socket.gaierror:
        return {"host": host, "valid": False, "error": "DNS resolution failed"}
    if not ips or any(not is_public(ip) for ip in ips):
        return {"host": host, "valid": False,
                "error": "host resolves to a private/reserved IP — refused (SSRF guard)"}
    connect_ip = ips[0]
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((connect_ip, port), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto, cipher = ss.version(), ss.cipher()
    except ssl.SSLCertVerificationError as e:
        return {"host": host, "resolved_ip": connect_ip, "valid": False,
                "error": "certificate verification failed: " + str(getattr(e, "verify_message", e))}
    except (OSError, ssl.SSLError) as e:
        return {"host": host, "resolved_ip": connect_ip, "valid": False, "error": str(e)[:140]}
    na = cert.get("notAfter")
    try:
        days = int((ssl.cert_time_to_seconds(na) - datetime.now(timezone.utc).timestamp()) // 86400)
    except Exception:
        days = None
    subj = dict(x[0] for x in cert.get("subject", []))
    iss = dict(x[0] for x in cert.get("issuer", []))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    return {"host": host, "port": port, "resolved_ip": connect_ip, "valid": True,
            "subject_cn": subj.get("commonName"),
            "issuer": iss.get("organizationName") or iss.get("commonName"),
            "not_before": cert.get("notBefore"), "not_after": na, "days_left": days,
            "expired": (days is not None and days < 0), "protocol": proto,
            "cipher": cipher[0] if cipher else None, "sans": sans[:25]}


def mail_rate_ok() -> bool:
    now = time.monotonic()
    with _LOCK:
        if now - _MAIL_HITS[1] > MAIL_WINDOW:
            _MAIL_HITS[0], _MAIL_HITS[1] = 0, now
        _MAIL_HITS[0] += 1
        return _MAIL_HITS[0] <= MAIL_LIMIT


def send_ddns_token(to: str, hostname: str, token: str, ip: str) -> None:
    m = EmailMessage()
    m["From"] = "whatismynetip.com <noreply@whatismynetip.com>"
    m["To"] = to
    m["Subject"] = f"Your Dynamic DNS update token for {hostname}"
    m["Date"] = format_datetime(datetime.now(timezone.utc))
    m["Message-ID"] = make_msgid(domain="whatismynetip.com")
    m.set_content(f"""You claimed the Dynamic DNS hostname:

    {hostname}    (currently -> {ip or 'not set'})

Your update token (keep it secret — it is shown only in this email):

    {token}

Point your router's DynDNS client (dyndns2 protocol) at:

    URL:      https://api.whatismynetip.com/nic/update
    Username: {hostname.split('.')[0]}
    Password: {token}

Or update manually:

    curl -u "{hostname.split('.')[0]}:{token}" \\
      "https://api.whatismynetip.com/nic/update?hostname={hostname}"

Hostnames with no update for 90 days are released automatically.

— whatismynetip.com (this mailbox is not monitored)
""")
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=ctx) as s:
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(m)


class Handler(BaseHTTPRequestHandler):
    server_version = "probe"

    def log_message(self, *a):  # quiet
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", ALLOW_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def client_ip(self) -> str:
        xr = self.headers.get("X-Real-IP", "").strip()
        if xr:
            return xr
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n <= 0:
            return {}
        return json.loads(self.rfile.read(min(n, 4096)))

    def do_POST(self):
        path = urlparse(self.path).path
        if path in ("/port", "/ssl"):
            return self.do_check(path)
        if path != "/send-ddns-token":
            return self._send(404, {"error": "not found"})
        if not (MAILER_KEY and SMTP_HOST and SMTP_PASS):
            return self._send(503, {"error": "mailer not configured"})
        if not hmac.compare_digest(self.headers.get("X-Mailer-Key", ""), MAILER_KEY):
            return self._send(403, {"error": "forbidden"})
        if not mail_rate_ok():
            return self._send(429, {"error": "mail rate limit reached"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            b = json.loads(self.rfile.read(min(n, 4096)))
            to, hostname = str(b["email"]), str(b["hostname"]).lower()
            token, ip = str(b["token"]), str(b.get("ip") or "")
        except Exception:
            return self._send(400, {"error": "invalid JSON body"})
        # fixed template + strict field shapes => no header/content injection surface
        if (not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", to)
                or not re.match(r"^[a-z0-9][a-z0-9-]{1,30}\.whatismynetip\.com$", hostname)
                or not re.match(r"^[0-9a-f]{16,64}$", token)):
            return self._send(400, {"error": "invalid field"})
        try:
            send_ddns_token(to, hostname, token, ip)
            return self._send(200, {"sent": True})
        except Exception as e:
            print(f"mailer error: {e!r}", flush=True)
            return self._send(502, {"error": "mail send failed"})

    def do_check(self, path: str):
        """/port and /ssl — POST from the site's own page, Turnstile-verified. Not a GET API."""
        ip = self.client_ip()
        if not from_site(self.headers):
            return self._send(404, {"error": "not found"})
        if not rate_ok(ip):
            return self._send(429, {"error": "rate limited — try again shortly"})
        try:
            b = self._body()
        except Exception:
            return self._send(400, {"error": "invalid body"})
        if not verify_turnstile(str(b.get("turnstile", "")), ip):
            return self._send(403, {"error": "Bot check failed — reload the page and try again."})

        if path == "/port":
            try:
                port = int(b.get("port", ""))
            except (ValueError, TypeError):
                return self._send(400, {"error": "a numeric port is required"})
            if not (1 <= port <= 65535):
                return self._send(400, {"error": "port out of range"})
            if not is_public(ip) or ":" in ip:
                return self._send(400, {"error": "could not determine a public IPv4 for you"})
            op = port_open(ip, port)
            return self._send(200, {"ip": ip, "port": port, "open": op,
                                    "status": "open" if op else "closed / filtered"})

        host = str(b.get("host", "")).strip().lower().rstrip(".")
        try:
            port = int(b.get("port") or 443)
        except (ValueError, TypeError):
            return self._send(400, {"error": "invalid port"})
        if not re.match(r"^[a-z0-9]([a-z0-9.-]{0,253}[a-z0-9])?$", host) or ".." in host:
            return self._send(400, {"error": "invalid hostname"})
        if not (1 <= port <= 65535):
            return self._send(400, {"error": "port out of range"})
        return self._send(200, ssl_info(host, port))

    def do_GET(self):
        # Liveness only. The checks moved to POST so there is no URL anyone can just paste.
        if urlparse(self.path).path == "/health":
            return self._send(200, {"ok": True, "service": "whatismynetip-probe"})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    print(f"probe backend listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
