#!/usr/bin/env python3
"""
Wolf Eye Web Dashboard — Backend Server v2.1
FastAPI + WebSockets + JSON Persistence + Tunnel Support
"""

import asyncio, csv, json, os, re as _re, signal, socket, subprocess, sys, time, uuid
import re as _re2  # alias used in parse_findings
try:
    import aiohttp as _aiohttp
except ImportError:
    _aiohttp = None
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ─── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent.resolve()
STATIC    = BASE_DIR / "static"
STATIC.mkdir(exist_ok=True)

_env      = os.environ.get("WOLF_ROOT")
WOLF_ROOT = Path(_env).resolve() if _env else BASE_DIR.parent

WOLF_EYE  = WOLF_ROOT / "eye.py"
WOLF_PRO  = WOLF_ROOT / "w0lf.py"

SCANS_DB     = BASE_DIR / "scans.json"
SETTINGS_DB  = BASE_DIR / "settings.json"
TUNNEL_FILE  = BASE_DIR / ".tunnel_url"   # written on startup if tunnel active
MAX_OUTPUT_LINES = 5_000  # per-scan in-memory line cap (~5MB worst case)

DEFAULT_SETTINGS = {
    "wolf_threads": 50, "wolf_top_ports": 1000, "wolf_severity": "",
    "wolf_templates": "", "wolf_wordlist": "", "wolf_output": "output",
    "wolf_detect_waf": False, "wolf_use_nmap": False,
    "wolf_proxychains": False, "wolf_quick": False, "wolf_skip_tools": [],
    "eye_threads": 3, "eye_confidence": 0.7, "eye_vuln_type": "20",
    "eye_output": "wolf_eye_output", "eye_aggressive": False,
    "tg_bot_token": "", "tg_chat_id": "",
    "gemini_api_key": "","gemini_model": "gemini-3.1-flash-lite-preview",
    "oob_ip": "", "oob_port": 8877,
    "theme":             "",
    # tunnel settings (persisted)
    "tunnel_provider": "none",   # none | ngrok | cloudflared | custom
    "tunnel_authtoken": "",      # ngrok auth token (optional)
    "tunnel_custom_url": "",     # user-supplied public URL
}

_ANSI = _re.compile(r'\x1b\[[0-9;]*[A-Za-z]|\x1b[^\x1b]')
def strip_ansi(s: str) -> str:
    return _ANSI.sub('', s)

# ─── Tunnel State ────────────────────────────────────────────────────────────────
tunnel_info: Dict = {"url": None, "provider": None, "proc": None}

def get_local_ip() -> str:
    """Best-effort local network IP (LAN accessible)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

async def start_tunnel(provider: str, authtoken: str = "", port: int = 8080) -> Optional[str]:
    """Try to start a tunnel. Returns public URL or None."""
    if provider == "none":
        return None

    if provider == "ngrok":
        return await _start_ngrok(authtoken, port)

    if provider == "cloudflared":
        return await _start_cloudflared(port)

    return None

async def _start_ngrok(authtoken: str, port: int) -> Optional[str]:
    """Start ngrok tunnel via pyngrok or CLI."""
    # Try pyngrok first
    try:
        from pyngrok import ngrok, conf
        if authtoken:
            conf.get_default().auth_token = authtoken
        tunnel = ngrok.connect(port, "http")
        url = tunnel.public_url
        # prefer https
        url = url.replace("http://", "https://") if url.startswith("http://") else url
        tunnel_info["provider"] = "ngrok (pyngrok)"
        tunnel_info["proc"]     = None   # pyngrok manages its own process
        return url
    except ImportError:
        pass
    except Exception as e:
        print(f"[TUNNEL] pyngrok error: {e}")

    # Try ngrok CLI
    try:
        ngrok_path = None
        for p in ["/usr/local/bin/ngrok", "/usr/bin/ngrok",
                  str(Path.home()/".local/bin/ngrok"), "ngrok"]:
            result = subprocess.run([p, "version"], capture_output=True, timeout=3)
            if result.returncode == 0:
                ngrok_path = p
                break
        if not ngrok_path:
            print("[TUNNEL] ngrok not found (install: pip install pyngrok  or  snap install ngrok)")
            return None

        args = [ngrok_path, "http", str(port), "--log=stdout", "--log-format=json"]
        if authtoken:
            subprocess.run([ngrok_path, "config", "add-authtoken", authtoken],
                           capture_output=True)

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        tunnel_info["proc"] = proc

        # Wait up to 8s for the URL to appear in logs
        deadline = asyncio.get_running_loop().time() + 8
        while asyncio.get_running_loop().time() < deadline:
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                line = raw.decode("utf-8", errors="ignore")
                data = json.loads(line) if line.strip().startswith("{") else {}
                url  = data.get("url") or data.get("Url") or ""
                if url.startswith("http"):
                    tunnel_info["provider"] = "ngrok (CLI)"
                    return url
            except (asyncio.TimeoutError, json.JSONDecodeError):
                continue
            except Exception:
                break
        return None
    except Exception as e:
        print(f"[TUNNEL] ngrok CLI error: {e}")
        return None

async def _start_cloudflared(port: int) -> Optional[str]:
    """Start cloudflare tunnel (quick tunnel — no account needed)."""
    cf_paths = ["cloudflared", "/usr/local/bin/cloudflared",
                str(Path.home()/".local/bin/cloudflared")]
    cf = None
    for p in cf_paths:
        try:
            r = subprocess.run([p, "version"], capture_output=True, timeout=3)
            if r.returncode == 0:
                cf = p
                break
        except Exception:
            continue

    if not cf:
        print("[TUNNEL] cloudflared not found (install: curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared)")
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            cf, "tunnel", "--url", f"http://localhost:{port}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        tunnel_info["proc"] = proc

        # cloudflared prints the URL to stderr/stdout within ~5s
        deadline = asyncio.get_running_loop().time() + 12
        url_pattern = _re.compile(r'https://[a-z0-9\-]+\.trycloudflare\.com')
        while asyncio.get_running_loop().time() < deadline:
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                line = raw.decode("utf-8", errors="ignore")
                m = url_pattern.search(line)
                if m:
                    tunnel_info["provider"] = "cloudflared"
                    return m.group(0)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
        return None
    except Exception as e:
        print(f"[TUNNEL] cloudflared error: {e}")
        return None

def stop_tunnel():
    proc = tunnel_info.get("proc")
    if proc:
        try: proc.terminate()
        except Exception: pass
    # stop pyngrok if it was used
    try:
        from pyngrok import ngrok
        ngrok.kill()
    except Exception:
        pass
    TUNNEL_FILE.unlink(missing_ok=True)

# ─── FastAPI Lifespan ────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application: FastAPI):
    # ── Startup ──
    load_db()
    cfg  = load_settings()
    port = int(os.environ.get("WOLF_PORT", 8080))

    local_ip   = get_local_ip()
    local_url  = f"http://{local_ip}:{port}"
    public_url = None

    provider = os.environ.get("WOLF_TUNNEL", cfg.get("tunnel_provider", "none")).lower()
    authtoken = os.environ.get("NGROK_TOKEN", cfg.get("tunnel_authtoken", ""))
    custom_url = os.environ.get("WOLF_URL", cfg.get("tunnel_custom_url", ""))

    if custom_url:
        public_url = custom_url
        tunnel_info["provider"] = "custom"
    elif provider not in ("", "none"):
        print(f"[TUNNEL] Starting {provider} tunnel on port {port}…")
        public_url = await start_tunnel(provider, authtoken, port)
        if not public_url:
            print(f"[TUNNEL] ⚠  {provider} tunnel failed — local only")

    if public_url:
        tunnel_info["url"] = public_url
        TUNNEL_FILE.write_text(public_url)

    # Print banner
    print()
    print("═" * 58)
    print("  🐺  WOLF EYE DASHBOARD")
    print("═" * 58)
    print(f"  Local       → http://localhost:{port}")
    print(f"  LAN         → {local_url}")
    if public_url:
        print(f"  Public (🌐) → {public_url}  [{tunnel_info.get('provider','')}]")
    else:
        print(f"  Public      → not configured  (see Settings → Tunnel)")
    print("─" * 58)
    print(f"  Wolf Root : {WOLF_ROOT}")
    print(f"  eye.py    : {'✓ found' if WOLF_EYE.exists() else '✗ NOT FOUND'}")
    print(f"  w0lf.py   : {'✓ found' if WOLF_PRO.exists() else '✗ NOT FOUND'}")
    if not WOLF_EYE.exists() or not WOLF_PRO.exists():
        print(f"  Fix       : WOLF_ROOT=/path/to/tools python server.py")
    print("═" * 58)
    print()

    yield

    # ── Shutdown ──
    stop_tunnel()
    save_db()
    print("[INFO] Wolf Eye Dashboard shutdown complete")

# ─── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(title="Wolf Eye Dashboard", version="3.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"],
)

# ─── Scan State ─────────────────────────────────────────────────────────────────
class ScanState:
    def __init__(self, scan_id, target, scan_type, options):
        self.id             = scan_id
        self.target         = target
        self.scan_type      = scan_type
        self.options        = options
        self.status         = "pending"
        self.start_time     = time.time()
        self.end_time: Optional[float]                       = None
        self.process: Optional[asyncio.subprocess.Process]  = None
        self.output_lines: List[str]                         = []
        self.findings: Dict                                  = {}
        self.ws_clients: List[WebSocket]                     = []
        self.output_dir: Optional[Path]                      = None
        self.error_msg: str                                  = ""

    def to_dict(self):
        return {
            "id": self.id, "target": self.target, "scan_type": self.scan_type,
            "options": self.options, "status": self.status,
            "start_time": self.start_time, "end_time": self.end_time,
            "output_lines": self.output_lines[-500:],
            "findings": self.findings, "error_msg": self.error_msg,
        }

    @classmethod
    def from_dict(cls, d):
        s = cls(d["id"], d["target"], d["scan_type"], d.get("options", {}))
        s.status       = d.get("status", "completed")
        s.start_time   = d.get("start_time", 0)
        s.end_time     = d.get("end_time")
        s.output_lines = d.get("output_lines", [])
        s.findings     = d.get("findings", {})
        s.error_msg    = d.get("error_msg", "")
        if s.status in ("running", "pending"):
            s.status = "stopped"
        return s

scans: Dict[str, ScanState] = {}

# ─── OOB Hits Store ──────────────────────────────────────────────────────────────
# Stores last 200 OOB callbacks parsed from scan output lines tagged [OOB]
_oob_hits: List[Dict] = []
MAX_OOB_HITS = 200

def _parse_oob_hit(line: str, scan_id: str, target: str) -> Optional[Dict]:
    """Parse an OOB line from eye.py output into a structured hit dict."""
    import re as _re3
    u = line.upper()
    if "[OOB]" not in u:
        return None
    # Detect type
    cb_type = "DNS" if "DNS" in u else "HTTP"
    # Extract URL/domain if present
    url_match = _re3.search(r'https?://\S+', line)
    domain_match = _re3.search(r'[\w\-]+\.[\w\-]+\.\S+', line)
    endpoint = (url_match.group(0) if url_match else
                domain_match.group(0) if domain_match else "—")
    return {
        "id":        str(uuid.uuid4())[:8],
        "ts":        time.time(),
        "type":      cb_type,
        "line":      line.strip(),
        "endpoint":  endpoint,
        "scan_id":   scan_id,
        "target":    target,
    }

def record_oob_hit(line: str, scan_id: str, target: str):
    hit = _parse_oob_hit(line, scan_id, target)
    if hit:
        _oob_hits.append(hit)
        if len(_oob_hits) > MAX_OOB_HITS:
            _oob_hits.pop(0)

# ─── Persistence ────────────────────────────────────────────────────────────────
def save_db():
    try:
        SCANS_DB.write_text(json.dumps({sid: s.to_dict() for sid, s in scans.items()}, indent=2))
    except Exception as e:
        print(f"[WARN] Could not save scans DB: {e}")

def load_db():
    if not SCANS_DB.exists(): return
    try:
        for sid, d in json.loads(SCANS_DB.read_text()).items():
            scans[sid] = ScanState.from_dict(d)
        print(f"[INFO] Loaded {len(scans)} scans from {SCANS_DB}")
    except Exception as e:
        print(f"[WARN] Could not load scans DB: {e}")

def load_settings() -> dict:
    s = dict(DEFAULT_SETTINGS)
    if SETTINGS_DB.exists():
        try:
            saved = json.loads(SETTINGS_DB.read_text())
            s.update({k: v for k, v in saved.items() if k in DEFAULT_SETTINGS})
        except Exception: pass
    return s

def save_settings(data: dict):
    merged = dict(DEFAULT_SETTINGS)
    merged.update({k: v for k, v in data.items() if k in DEFAULT_SETTINGS})
    SETTINGS_DB.write_text(json.dumps(merged, indent=2))

# ─── Helpers ────────────────────────────────────────────────────────────────────
def classify_level(line: str) -> str:
    u = line.upper()
    if any(x in u for x in ("[CRITICAL]", "[ERROR]", "ERROR:")):  return "ERROR"
    if any(x in u for x in ("[WARN]", "WARNING:")):               return "WARN"
    if any(x in u for x in ("[SUCCESS]", "[VULN]", "[FOUND]")):   return "SUCCESS"
    if "[OOB]" in u:                                               return "OOB"
    return "INFO"

def _walk_eye_output(base: "Path") -> "Optional[Path]":
    """Return the most recently modified sub-directory under wolf_eye_output/<target>/."""
    if not base.exists():
        return None
    subdirs = sorted([d for d in base.iterdir() if d.is_dir()],
                     key=lambda d: d.stat().st_mtime, reverse=True)
    return subdirs[0] if subdirs else base


def find_output_dir(target: str, prefer_eye: bool = True) -> "Optional[Path]":
    """Locate the most relevant output directory for a given target.

    Priority when prefer_eye=True (default — used for Findings):
      1. wolf_eye_output/<target>/  — newest eye.py scan (most recent datetime dir)
      2. output/<target>/full_scan  — Wolf Pro recon

    This ensures eye.py findings are shown even when Wolf Pro data also exists.
    """
    clean = target.replace("http://","").replace("https://","").rstrip("/")
    variants = list(dict.fromkeys([target, clean, clean.replace(".","_")]))

    eye_dir  = None
    wolf_dir = None

    for v in variants:
        # eye.py output: wolf_eye_output/<target>/<datetime>/
        ep = WOLF_ROOT / "wolf_eye_output" / v
        if ep.exists() and eye_dir is None:
            eye_dir = _walk_eye_output(ep)

        # Wolf Pro output: output/<target>/full_scan
        wp = WOLF_ROOT / "output" / v / "full_scan"
        if wp.exists() and wolf_dir is None:
            wolf_dir = wp

    if prefer_eye and eye_dir and eye_dir.exists():
        return eye_dir
    if wolf_dir and wolf_dir.exists():
        return wolf_dir
    return eye_dir  # last resort


def find_wolf_dir(target: str) -> "Optional[Path]":
    """Find Wolf Pro output dir specifically (needed for Shodan CVEs)."""
    clean = target.replace("http://","").replace("https://","").rstrip("/")
    for v in [target, clean, clean.replace(".","_")]:
        wp = WOLF_ROOT / "output" / v / "full_scan"
        if wp.exists():
            return wp
    return None


SEV_MAP = {
    # CRITICAL
    "sql_injection_verified":    "CRITICAL",
    "sql_injection":             "CRITICAL",
    "nosql_injection_verified":  "CRITICAL",
    "command_injection":         "CRITICAL",
    "cmdi_confirmed":            "CRITICAL",
    "xxe_injection_verified":    "CRITICAL",
    "xxe_injection":             "CRITICAL",
    "xxe_confirmed":             "CRITICAL",
    "ssrf_verified":             "CRITICAL",
    "ssrf_blind_confirmed":      "CRITICAL",
    "blind_xss_confirmed":       "CRITICAL",
    "stored_xss":                "CRITICAL",
    "privilege_escalation":      "CRITICAL",
    "api_auth_bypass":           "CRITICAL",
    "api_bola":                  "CRITICAL",
    "jwt_algorithm_confusion":   "CRITICAL",
    "jwt_key_confusion":         "CRITICAL",
    "cors_critical":             "CRITICAL",
    # HIGH
    "reflected_xss_verified":    "HIGH",
    "dom_xss_potential":         "HIGH",
    "xss":                       "HIGH",
    "ssrf":                      "HIGH",
    "ssrf_blind_potential":      "HIGH",
    "cors":                      "HIGH",
    "cors_misconfiguration":     "HIGH",
    "idor_verified":             "HIGH",
    "path_traversal_verified":   "HIGH",
    "jwt_vulnerabilities":       "HIGH",
    "ldap_injection_verified":   "HIGH",
    "zeroday_polyglot":          "HIGH",
    "api_key_leakage":           "HIGH",
    "api_mass_assignment":       "HIGH",
    # MEDIUM
    "open_redirect":             "MEDIUM",
    "clickjacking":              "MEDIUM",
    "csrf":                      "MEDIUM",
    "zeroday_prototype_pollution":"MEDIUM",
    "mass_assignment":           "MEDIUM",
    "insecure_api_endpoints":    "MEDIUM",
    "api_sensitive_endpoints":   "MEDIUM",
    "api_versioning_issues":     "MEDIUM",
    "file_upload":               "MEDIUM",
    "deserialization":           "MEDIUM",
    "host_header":               "MEDIUM",
    "websocket":                 "MEDIUM",
    "graphql":                   "MEDIUM",
    "race_condition":            "MEDIUM",
    "http_request_smuggling":    "MEDIUM",
    "ssti":                      "MEDIUM",
    "template_injection":        "MEDIUM",
    # LOW
    "excessive_data_exposure":   "LOW",
}

def parse_findings(output_dir: Optional[Path]) -> Dict:
    """Parse vulnerability findings from eye.py output directories only.

    Key design decisions:
    1. Only reads files that match known vulnerability filename patterns.
    2. Skips discovery/recon files (URLs, subdomains, IPs, nuclei raw output).
    3. Validates each line: must contain a pipe '|' separator and a non-URL first field.
    4. Strips ANSI codes from both file content and individual lines.
    """
    res = {
        "total": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "by_category": {},
        "items": [],
    }
    if not output_dir or not output_dir.exists():
        return res

    # ── Files to always skip (wolf pro discovery output) ────────────────────
    SKIP_NAMES = {
        # Wolf Pro recon output — URLs, subdomains, IPs (not vulnerabilities)
        "scan_report.txt", "intelligent_targets.txt",
        "intelligent_targets_detailed.txt",
        "live_urls.txt", "all_live_urls.txt",
        "subdomains.txt", "subfinder.txt",
        "httpx_full.txt", "resolved_ips.txt",
        "shodan_cves.csv", "shodan_cves.txt",
        "nuclei.txt",            # nuclei raw output — different format
        "katana.txt",            # crawled URLs
        "katana_api_endpoints.txt",
        "katana_js_files.txt",
        "katana_interesting.txt",
        "waybackurls.txt",       # historical URLs
        "gau.txt",               # all URLs
        "naabu.txt",             # port scan
        "dnsx.txt",              # DNS results
        "subzy_takeovers.txt",
        "vulnerable_subs.txt",
        "js_secrets_found.txt",  # parsed separately if needed
        "js_hidden_endpoints.txt",
        "technology_report.txt",
        "report.html", "report.md",
    }

    # ── Known vulnerability file name patterns ───────────────────────────────
    # Only files whose names match these patterns are treated as findings.
    VULN_PATTERNS = _re2.compile(
        r'(inject|xss|ssrf|xxe|idor|cors|jwt|csrf|redirect|upload|deserializ|'
        r'host_header|clickjack|mass_assign|graphql|race|websocket|smuggl|ssti|'
        r'template_inject|prototype|privilege|api_auth|api_bola|api_key|api_mass|'
        r'api_sensitive|api_rate|api_version|api_excess|zeroday|polyglot|verified|'
        r'confirmed|vuln|finding|nuclei_cve)',
        _re2.IGNORECASE
    )

    for txt in sorted(output_dir.rglob("*.txt")):
        fname_lower = txt.name.lower()
        # Skip known non-finding files
        if txt.name in SKIP_NAMES:
            continue
        # Skip wolf pro data subdirectories (they sit one level down from full_scan/)
        # eye.py output dirs are named after the vuln category e.g. "1/" "sql_injection/"
        # wolf pro dirs include: js_analysis, shodan, waybackurls, katana, gau, etc.
        skip_dirs = {"js_analysis", "shodan", "waybackurls", "katana", "gau",
                     "nuclei", "naabu", "dnsx", "httpx", "subfinder", "subzy",
                     "wayback", "full_scan"}
        if any(p.name in skip_dirs for p in txt.parents):
            continue
        # Only parse files that look like vulnerability output
        if not VULN_PATTERNS.search(fname_lower):
            # Still allow numbered directories (eye.py uses 1/, 2/, etc.)
            if not any(p.name.isdigit() for p in txt.parents):
                continue

        category = txt.parent.name
        fname    = txt.stem
        default_sev = SEV_MAP.get(fname, SEV_MAP.get(category, "MEDIUM"))

        try:
            content = strip_ansi(txt.read_text(errors="ignore")).strip()
        except Exception:
            continue

        for line in content.splitlines():
            line = strip_ansi(line).strip()
            # Skip blank lines and Wolf Eye header comments
            if not line or line.startswith("#"):
                continue
            # ── CRITICAL validation: a genuine finding MUST have pipe separators ──
            # Lines with no pipe are raw URLs / plain text — skip them entirely.
            if "|" not in line:
                continue
            parts = line.split("|")
            raw_type = parts[0].strip()
            # Skip if the "type" field is itself a URL (discovery file leaked in)
            if raw_type.startswith("http://") or raw_type.startswith("https://"):
                continue
            # Skip very short type fields that are likely noise
            if len(raw_type) < 3:
                continue

            # Severity: read from line first, else use file default
            sev = default_sev
            lu  = line.upper()
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if s in lu:
                    sev = s
                    break

            # Extract URL — first field that starts with http
            url = ""
            for p in parts:
                p = p.strip()
                if p.startswith("http://") or p.startswith("https://"):
                    url = p
                    break

            # Clean type: strip ANSI and brackets from nuclei-style "[ip] [template]"
            clean_type = _re2.sub(r"^\[.*?\]\s*", "", raw_type).strip() or raw_type

            # Confidence: second field if it looks like a float
            confidence = 0.75
            if len(parts) > 1:
                cf = parts[1].strip()
                if cf.replace(".", "").isdigit():
                    try:
                        confidence = float(cf)
                    except Exception:
                        pass

            # URL: third field if second was confidence
            if not url and len(parts) > 2:
                candidate = parts[2].strip()
                if candidate.startswith("http"):
                    url = candidate

            details = " | ".join(p.strip() for p in parts[3:]) if len(parts) > 3 else line

            item = {
                "id":         str(uuid.uuid4())[:8],
                "type":       clean_type,
                "confidence": confidence,
                "url":        url,
                "details":    details,
                "severity":   sev,
                "category":   category,
                "file":       fname,
            }
            res["items"].append(item)
            res["total"] += 1
            res["by_severity"][sev] = res["by_severity"].get(sev, 0) + 1
            res["by_category"][category] = res["by_category"].get(category, 0) + 1

    return res


def _norm_cve_row(row: dict) -> dict:
    """Normalize shodan_cves.csv field names.
    w0lf.py columns: IP | CVE | Severity | CVSS_Score | Description | Ports | Hostnames
    """
    lk = {k.strip().lower(): v for k, v in row.items()}
    return {
        "cve_id":      lk.get("cve") or lk.get("cve_id") or "—",
        "ip":          lk.get("ip") or "—",
        "severity":    (lk.get("severity") or "MEDIUM").upper().strip(),
        "cvss":        lk.get("cvss_score") or lk.get("cvss") or "—",
        "description": strip_ansi(lk.get("description") or "—"),
        "ports":       lk.get("ports") or "",
        "hostnames":   lk.get("hostnames") or "",
    }

def parse_cves(output_dir: Optional[Path]) -> List[Dict]:
    if not output_dir: return []
    candidates = [
        output_dir / "shodan_cves.csv",
        output_dir.parent / "shodan_cves.csv",
        output_dir.parent.parent / "shodan_cves.csv",
        output_dir.parent.parent.parent / "shodan_cves.csv",
    ]
    for f in candidates:
        if f.exists():
            try:
                with open(f, errors="ignore") as fh:
                    rows = list(csv.DictReader(fh))
                return [_norm_cve_row(r) for r in rows if r]
            except Exception:
                continue
    return []

# ─── Broadcast ──────────────────────────────────────────────────────────────────
async def broadcast(scan: ScanState, msg: dict):
    dead = []
    for ws in scan.ws_clients:
        try: await ws.send_json(msg)
        except Exception: dead.append(ws)
    for ws in dead:
        if ws in scan.ws_clients: scan.ws_clients.remove(ws)

# ─── Scan Runner ────────────────────────────────────────────────────────────────
async def run_scan(scan: ScanState):
    try:
        scan.status = "running"
        await broadcast(scan, {"type":"status","status":"running"})
        save_db()

        py  = sys.executable
        tgt = scan.target
        opt = scan.options
        cfg = load_settings()

        if scan.scan_type == "recon-only":
            cmd = [py, str(WOLF_PRO), "-d", tgt]
            if cfg.get("wolf_threads",50)!=50:        cmd += ["--threads",    str(cfg["wolf_threads"])]
            if cfg.get("wolf_top_ports",1000)!=1000:  cmd += ["--top-ports",  str(cfg["wolf_top_ports"])]
            if cfg.get("wolf_severity"):               cmd += ["--severity",   cfg["wolf_severity"]]
            if cfg.get("wolf_templates"):              cmd += ["--templates",  cfg["wolf_templates"]]
            if cfg.get("wolf_wordlist"):               cmd += ["--wordlist",   cfg["wolf_wordlist"]]
            if cfg.get("wolf_output","output")!="output": cmd += ["--output", cfg["wolf_output"]]
            if cfg.get("wolf_detect_waf"):             cmd.append("--detect-waf")
            if cfg.get("wolf_use_nmap"):               cmd.append("--use-nmap")
            if cfg.get("wolf_proxychains"):            cmd.append("--proxychains")
            if cfg.get("wolf_quick"):                  cmd.append("--quick")
            for skip in (cfg.get("wolf_skip_tools") or []): cmd.append(f"--skip-{skip}")
        elif scan.scan_type == "eye-only":
            # eye-only: use --auto with -w pointing to existing Wolf Pro output.
            # If no Wolf output exists, the scan will fail with a clear error.
            wolf_dir = find_output_dir(tgt)
            cmd = [py, str(WOLF_EYE), "--auto", "-t", tgt]
            if wolf_dir:
                cmd += ["-w", str(wolf_dir)]
            # Note: without -w, eye.py --auto will try to run Wolf Pro first,
            # which is equivalent to a full pipeline — we warn but let it run.
            if cfg.get("eye_threads",3)!=3:           cmd += ["--threads",    str(cfg["eye_threads"])]
            if cfg.get("eye_confidence",0.7)!=0.7:    cmd += ["--confidence", str(cfg["eye_confidence"])]
            if cfg.get("eye_output","wolf_eye_output")!="wolf_eye_output": cmd += ["-o", cfg["eye_output"]]
            if cfg.get("eye_aggressive"):              cmd.append("--aggressive-fingerprint")
        else:  # full
            cmd = [py, str(WOLF_EYE), "-t", tgt, "--auto"]
            if cfg.get("eye_threads",3)!=3:           cmd += ["--threads",    str(cfg["eye_threads"])]
            if cfg.get("eye_confidence",0.7)!=0.7:    cmd += ["--confidence", str(cfg["eye_confidence"])]
            if cfg.get("eye_output","wolf_eye_output")!="wolf_eye_output": cmd += ["-o", cfg["eye_output"]]
            if cfg.get("eye_aggressive"):              cmd.append("--aggressive-fingerprint")

        # Telegram + OOB — only for eye.py scans (w0lf.py doesn't support these args)
        if scan.scan_type != "recon-only":
            no_tg = opt.get("no_telegram", False)
            tg_token = (cfg.get("tg_bot_token") or "").strip()
            tg_chat  = (cfg.get("tg_chat_id")  or "").strip()
            if no_tg:
                cmd.append("--no-telegram")
            elif tg_token and tg_chat:
                cmd += ["--telegram-bot-token", tg_token,
                        "--telegram-chat-id",   tg_chat]
            else:
                cmd.append("--no-telegram")

            # OOB
            if opt.get("no_oob"):
                cmd.append("--no-oob")
            else:
                oob_ip   = opt.get("oob_ip")   or cfg.get("oob_ip")   or None
                oob_port = opt.get("oob_port") or cfg.get("oob_port") or 8877
                if oob_ip:         cmd += ["--oob-ip",   oob_ip]
                if str(oob_port)!="8877": cmd += ["--oob-port", str(oob_port)]
        else:
            # recon-only: still allow telegram if configured (w0lf.py supports it)
            no_tg = opt.get("no_telegram", False)
            tg_token = (cfg.get("tg_bot_token") or "").strip()
            tg_chat  = (cfg.get("tg_chat_id")  or "").strip()
            if no_tg:
                cmd.append("--no-telegram")
            elif tg_token and tg_chat:
                cmd += ["--telegram-bot-token", tg_token,
                        "--telegram-chat-id",   tg_chat]
            else:
                cmd.append("--no-telegram")
            # OOB args intentionally skipped — w0lf.py does not support them

        tool_path = WOLF_PRO if scan.scan_type == "recon-only" else WOLF_EYE
        if not tool_path.exists():
            msg = f"[ERROR] Tool not found: {tool_path}\n[ERROR] Set WOLF_ROOT env var.\n"
            scan.output_lines.append(msg)
            await broadcast(scan, {"type":"output","line":msg,"level":"ERROR"})
            scan.status = "error"; scan.error_msg = f"Tool not found: {tool_path}"
            scan.end_time = time.time()
            await broadcast(scan, {"type":"completed","status":"error"})
            save_db(); return

        tg_status = "enabled (token found)" if (tg_token and tg_chat and not no_tg) else f"DISABLED (no_tg={no_tg}, token={'yes' if tg_token else 'EMPTY'}, chat={'yes' if tg_chat else 'EMPTY'})"
        info_line = f"[DASHBOARD] Running: {' '.join(cmd)}\n[DASHBOARD] Working dir: {WOLF_ROOT}\n[DASHBOARD] Telegram: {tg_status}\n[DASHBOARD] Settings DB: {SETTINGS_DB}\n"
        if scan.scan_type == "eye-only" and "-w" not in cmd:
            info_line += "[WARN] No existing Wolf Pro output found for this target.\n"
            info_line += "[WARN] eye.py will run Wolf Pro recon first (equivalent to Full Pipeline).\n"
            info_line += "[WARN] TIP: Run 'Recon Only' first, then 'Eye Only' to scan existing results.\n"
        scan.output_lines.append(info_line)
        await broadcast(scan, {"type":"output","line":info_line,"level":"INFO"})

        # Force line-buffered / unbuffered output so the dashboard terminal
        # receives lines immediately instead of waiting for 4KB chunks.
        # PYTHONUNBUFFERED=1  → disables Python's stdout buffering entirely
        # -u flag             → same but baked into the Python command
        # stdbuf -oL          → forces line-buffering for non-Python child tools
        #                       (nuclei, httpx, subfinder, etc.)
        proc_env = os.environ.copy()
        proc_env["PYTHONUNBUFFERED"] = "1"
        proc_env["PYTHONDONTWRITEBYTECODE"] = "1"

        # Insert -u (unbuffered) right after the Python interpreter
        unbuf_cmd = list(cmd)
        if unbuf_cmd and unbuf_cmd[0] == sys.executable and "-u" not in unbuf_cmd:
            unbuf_cmd.insert(1, "-u")

        scan.process = await asyncio.create_subprocess_exec(
            *unbuf_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(WOLF_ROOT),
            env=proc_env,
            start_new_session=True,  # creates new process group → kill_process_tree works
        )

        # Read output line-by-line with a small yield every N lines
        # to keep the event loop responsive for WebSocket sends.
        _line_count = 0
        async for raw in scan.process.stdout:
            if scan.status == "stopped":
                kill_process_tree(scan.process)
                break
            line = strip_ansi(raw.decode("utf-8", errors="replace"))
            if not line.strip():
                continue          # skip blank lines — reduces noise
            scan.output_lines.append(line)
            # Record OOB callbacks for the OOB monitor
            if "[OOB]" in line.upper():
                record_oob_hit(line, scan.id, scan.target)
            # Cap in-memory output to avoid RAM exhaustion on very long scans.
            # The last MAX_OUTPUT_LINES lines are kept; older ones are discarded.
            if len(scan.output_lines) > MAX_OUTPUT_LINES:
                scan.output_lines = scan.output_lines[-MAX_OUTPUT_LINES:]
            _line_count += 1
            if _line_count % 50 == 0:
                save_db()
            if _line_count % 10 == 0:
                await asyncio.sleep(0)  # yield to event loop every 10 lines
            await broadcast(scan, {"type":"output","line":line,"level":classify_level(line)})

        await scan.process.wait()
        await asyncio.sleep(0.8)
        od = find_output_dir(scan.target, prefer_eye=True)
        scan.output_dir = od
        scan.findings   = parse_findings(od)
        if scan.findings.get("total", 0) == 0:
            await asyncio.sleep(2.0)
            od = find_output_dir(scan.target, prefer_eye=True)
            scan.findings = parse_findings(od)
        scan.status   = "completed" if scan.status not in ("stopped","error") else scan.status
        scan.end_time = time.time()
        await broadcast(scan, {"type":"completed","status":scan.status,
                                "findings":scan.findings,"duration":int(scan.end_time-scan.start_time)})
        save_db()

    except Exception as e:
        scan.status = "error"; scan.error_msg = str(e); scan.end_time = time.time()
        err_line = f"[ERROR] Scan crashed: {e}\n"
        scan.output_lines.append(err_line)
        await broadcast(scan, {"type":"error","message":str(e)})
        save_db()

# ─── Models ─────────────────────────────────────────────────────────────────────
class StartScanRequest(BaseModel):
    target:      str
    scan_type:   str  = "full"
    no_oob:      bool = False
    no_telegram: bool = False   # False = use telegram if token in settings
    oob_ip:      Optional[str] = None
    oob_port:    Optional[int] = None


def kill_process_tree(proc):
    """Kill a process and ALL its children (nuclei, subfinder, httpx, etc.)."""
    if not proc:
        return
    pid = proc.pid
    if not pid:
        return
    try:
        # Try killing the entire process group first (most reliable)
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    except Exception:
        # Fallback: kill just the direct process
        try:
            proc.kill()
        except Exception:
            pass
    # Also call terminate as final fallback
    try:
        proc.terminate()
    except Exception:
        pass


# ─── AI Triage (Gemini Flash) ────────────────────────────────────────────────────
async def _call_gemini(api_key: str, prompt: str, model: str,
                       max_tokens: int = 1024, temperature: float = 0.2) -> str:
    """Low-level Gemini API call — returns raw text response."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens}
    }
    if _aiohttp:
        async with _aiohttp.ClientSession() as session:
            async with session.post(url, json=payload,
                                    timeout=_aiohttp.ClientTimeout(total=45)) as r:
                data = await r.json()
    else:
        import urllib.request, json as _json2
        req = urllib.request.Request(
            url, data=_json2.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = _json2.loads(resp.read())

    # Surface API errors clearly
    if "error" in data:
        msg = data["error"].get("message", str(data["error"]))
        raise RuntimeError(msg)

    text = data["candidates"][0]["content"]["parts"][0]["text"]
    text = text.strip()
    # Strip markdown code fences if model wrapped response
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return text.strip()


async def _gemini_triage(api_key: str, finding: dict, target: str,
                         model: str = "gemini-3.1-flash-lite-preview") -> dict:
    """Triage a finding — returns verdict, impact, PoC, attack scenario, remediation.
    Does NOT generate a report body; that is done separately via _gemini_report."""
    prompt = f"""You are an elite bug bounty hunter and security researcher analyzing a vulnerability finding.

TARGET: {target}
VULNERABILITY TYPE: {finding.get('type', 'Unknown')}
SEVERITY: {finding.get('severity', 'UNKNOWN')}
URL: {finding.get('url', 'N/A')}
CONFIDENCE: {int((finding.get('confidence', 0.75)) * 100)}%
DETAILS: {finding.get('details', 'No details')}
CATEGORY: {finding.get('category', 'Unknown')}

Respond ONLY with a valid JSON object. No markdown, no code blocks, no explanation outside JSON.
{{
  "is_real": <0-100 integer, probability this is a real vulnerability not false positive>,
  "exploitability": <0-100 integer, how easily exploitable IF real>,
  "priority": <"P1 - Critical" | "P2 - High" | "P3 - Medium" | "P4 - Low">,
  "false_positive_reason": <string explaining WHY this might be a false positive, or null if likely real>,
  "fp_indicators": [<2-4 short strings listing specific signals that suggest FP, e.g. "Header present but tool missed it", "Endpoint requires auth", or empty array [] if likely real>],
  "verify_steps": [<2-3 short actionable strings to manually confirm this is real, specific to the URL and type>],
  "impact": [<3 specific impact strings for THIS target, not generic>],
  "poc": <ready-to-run curl/python/bash command as single string with real URL>,
  "report_title": <professional bug bounty report title, single line>,
  "attack_scenario": <1 sentence realistic attack scenario for this specific target>,
  "remediation": <1 sentence specific fix recommendation>
}}"""
    try:
        text = await _call_gemini(api_key, prompt, model, max_tokens=1024)
        return json.loads(text)
    except Exception as e:
        return {"error": str(e), "is_real": 50, "exploitability": 50,
                "priority": "P3 - Medium", "false_positive_reason": None,
                "fp_indicators": [], "verify_steps": [],
                "impact": ["Could not analyze — check Gemini API key in Settings"],
                "poc": "# API key not configured or request failed",
                "report_title": finding.get("type", "Vulnerability"),
                "attack_scenario": "Unknown",
                "remediation": "Review manually"}


async def _gemini_report(api_key: str, finding: dict, target: str,
                         triage: dict, report_format: str,
                         model: str = "gemini-3.1-flash-lite-preview") -> dict:
    """Generate a bug bounty report body following the user-supplied format EXACTLY."""
    prompt = f"""You are a professional bug bounty report writer.

VULNERABILITY CONTEXT:
  Target      : {target}
  Type        : {finding.get('type', 'Unknown')}
  Severity    : {finding.get('severity', 'UNKNOWN')}
  URL         : {finding.get('url', 'N/A')}
  Details     : {finding.get('details', 'No details')}
  Priority    : {triage.get('priority', 'P3 - Medium')}
  PoC         : {triage.get('poc', 'N/A')}
  Remediation : {triage.get('remediation', 'N/A')}

USER-SUPPLIED REPORT FORMAT (follow this EXACTLY — preserve every heading, placeholder marker, and structural element):
\"\"\"
{report_format}
\"\"\"

RULES:
1. Replace every placeholder (e.g. [add summary], [add step]) with real content specific to this finding.
2. Preserve ALL markdown headings (##, ###), bullet styles, numbered lists, and any special lines (e.g. lines starting with ==).
3. Do NOT add, remove, or rename any section that the user defined.
4. If the format requests a curl command, use the actual URL from the finding.
5. Output ONLY the completed report text — no JSON, no preamble, no explanation.
"""
    try:
        text = await _call_gemini(api_key, prompt, model,
                                  max_tokens=2048, temperature=0.3)
        return {"report_title": triage.get("report_title", finding.get("type", "Vulnerability")),
                "report_body": text}
    except Exception as e:
        raise RuntimeError(str(e))

# ─── API Routes ─────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    idx = STATIC / "index.html"
    return FileResponse(idx) if idx.exists() else HTMLResponse("<h1>Wolf Eye</h1>")

@app.get("/api/oob/hits")
async def get_oob_hits(scan_id: str = "", limit: int = 50):
    """Return recent OOB callbacks, optionally filtered by scan_id."""
    hits = _oob_hits[-limit:] if not scan_id else [
        h for h in _oob_hits if h["scan_id"] == scan_id
    ][-limit:]
    return {"hits": list(reversed(hits)), "total": len(_oob_hits)}

@app.delete("/api/oob/hits")
async def clear_oob_hits():
    _oob_hits.clear()
    return {"cleared": True}

@app.get("/api/health")
async def health():
    return {
        "status": "ok", "version": "3.0",
        "wolf_root": str(WOLF_ROOT),
        "eye_found": WOLF_EYE.exists(),
        "pro_found": WOLF_PRO.exists(),
        "scans": len(scans),
        "local_ip": get_local_ip(),
        "tunnel_url": tunnel_info.get("url"),
        "tunnel_provider": tunnel_info.get("provider"),
    }

@app.get("/api/tunnel")
async def get_tunnel():
    return {
        "url":      tunnel_info.get("url"),
        "provider": tunnel_info.get("provider"),
        "active":   bool(tunnel_info.get("url")),
        "local_ip": get_local_ip(),
    }

@app.post("/api/tunnel/start")
async def start_tunnel_api(data: dict):
    """Start or restart tunnel at runtime (no server restart needed)."""
    provider  = data.get("provider", "none")
    authtoken = data.get("authtoken", "")
    port      = int(os.environ.get("WOLF_PORT", 8080))

    # Kill existing
    stop_tunnel()
    tunnel_info["url"] = None
    tunnel_info["provider"] = None
    tunnel_info["proc"] = None

    if provider in ("", "none"):
        return {"active": False, "url": None}

    custom = data.get("custom_url","").strip()
    if custom:
        tunnel_info["url"] = custom
        tunnel_info["provider"] = "custom"
        TUNNEL_FILE.write_text(custom)
        return {"active": True, "url": custom, "provider": "custom"}

    url = await start_tunnel(provider, authtoken, port)
    if url:
        tunnel_info["url"] = url
        TUNNEL_FILE.write_text(url)
        return {"active": True, "url": url, "provider": tunnel_info.get("provider")}
    else:
        return {"active": False, "url": None,
                "error": f"{provider} failed — check install & auth"}

@app.post("/api/tunnel/stop")
async def stop_tunnel_api():
    stop_tunnel()
    tunnel_info.update({"url": None, "provider": None, "proc": None})
    return {"active": False}

@app.post("/api/scans")
async def start_scan(req: StartScanRequest):
    t = req.target.strip()
    if not t: raise HTTPException(400, "Target required")
    sid  = str(uuid.uuid4())[:12]
    opts = {"no_oob":req.no_oob,"no_telegram":req.no_telegram,"oob_ip":req.oob_ip,"oob_port":req.oob_port}
    scan = ScanState(sid, t, req.scan_type, opts)
    scans[sid] = scan; save_db()
    asyncio.create_task(run_scan(scan))
    return {"id":sid,"target":t,"status":"pending","scan_type":req.scan_type}

@app.get("/api/scans")
async def list_scans():
    return [{"id":s.id,"target":s.target,"scan_type":s.scan_type,"status":s.status,
             "start_time":s.start_time,"end_time":s.end_time,
             "duration":int((s.end_time or time.time())-s.start_time),
             "findings_count":s.findings.get("total",0),
             "findings_severity":s.findings.get("by_severity",{}),
             "error_msg":s.error_msg,
             "no_oob":s.options.get("no_oob",False)}
            for s in sorted(scans.values(), key=lambda x:x.start_time, reverse=True)]

@app.get("/api/scans/{sid}")
async def get_scan(sid: str):
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Not found")
    return {"id":s.id,"target":s.target,"scan_type":s.scan_type,"status":s.status,
            "start_time":s.start_time,"end_time":s.end_time,
            "duration":int((s.end_time or time.time())-s.start_time),
            "output_count":len(s.output_lines),"findings":s.findings,"error_msg":s.error_msg,
            "no_oob":s.options.get("no_oob",False)}

@app.post("/api/scans/{sid}/stop")
async def stop_scan(sid: str):
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Not found")
    s.status = "stopped"; s.end_time = time.time()
    kill_process_tree(s.process)
    s.process = None
    save_db(); return {"status":"stopped"}

@app.delete("/api/scans/{sid}")
async def delete_scan(sid: str):
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Not found")
    kill_process_tree(s.process)
    del scans[sid]; save_db()
    return {"deleted": True}

@app.get("/api/scans/{sid}/findings")
async def get_findings(sid: str):
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Not found")
    if not s.findings.get("items") or s.findings.get("total", 0) == 0:
        od = find_output_dir(s.target, prefer_eye=True)
        if od:
            fresh = parse_findings(od)
            if fresh.get("total", 0) > 0:
                s.findings = fresh
                save_db()
    return s.findings

@app.get("/api/scans/{sid}/cves")
async def get_cves(sid: str):
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Not found")
    # CVEs come from Shodan which runs in Wolf Pro — search that dir first
    wolf_d = find_wolf_dir(s.target)
    eye_d  = find_output_dir(s.target, prefer_eye=True)
    cvs    = parse_cves(wolf_d) or parse_cves(eye_d) or []
    return {"cves": cvs, "total": len(cvs)}

@app.get("/api/scans/{sid}/output")
async def get_output(sid: str, offset: int = 0):
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Not found")
    return {"lines": s.output_lines[offset:], "total": len(s.output_lines)}

@app.websocket("/ws/{sid}")
async def ws_endpoint(ws: WebSocket, sid: str):
    await ws.accept()
    s = scans.get(sid)
    if not s:
        await ws.send_json({"type":"error","message":"Scan not found"})
        await ws.close(); return

    for line in s.output_lines:
        try: await ws.send_json({"type":"output","line":strip_ansi(line),"level":classify_level(line)})
        except Exception: return

    await ws.send_json({"type":"status","status":s.status})

    if s.status in ("completed","stopped","error"):
        if s.findings.get("total",0) > 0:
            await ws.send_json({"type":"completed","status":s.status,"findings":s.findings})
        await ws.close(); return

    s.ws_clients.append(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if ws in s.ws_clients: s.ws_clients.remove(ws)


@app.post("/api/triage/{sid}/{finding_idx}")
async def triage_finding(sid: str, finding_idx: int, data: dict = {}):
    """AI triage a single finding. Does NOT generate report body."""
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Scan not found")
    items = s.findings.get("items", [])
    if finding_idx < 0 or finding_idx >= len(items):
        raise HTTPException(404, "Finding not found")

    cfg     = load_settings()
    api_key = cfg.get("gemini_api_key", "").strip()
    model   = cfg.get("gemini_model", "gemini-3.1-flash-lite-preview").strip() or "gemini-3.1-flash-lite-preview"

    if not api_key:
        raise HTTPException(400, "Gemini API key not configured. Go to Settings → AI Triage.")

    finding = items[finding_idx]
    result  = await _gemini_triage(api_key, finding, s.target, model)
    return {"finding_idx": finding_idx, "scan_id": sid, "triage": result}


@app.post("/api/triage/{sid}/{finding_idx}/report")
async def triage_report(sid: str, finding_idx: int, data: dict):
    """Generate a bug bounty report following the user-supplied format exactly."""
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Scan not found")
    items = s.findings.get("items", [])
    if finding_idx < 0 or finding_idx >= len(items):
        raise HTTPException(404, "Finding not found")

    report_format = (data.get("report_format") or "").strip()
    if not report_format:
        raise HTTPException(400, "report_format is required.")

    triage_data = data.get("triage") or {}

    cfg     = load_settings()
    api_key = cfg.get("gemini_api_key", "").strip()
    model   = cfg.get("gemini_model", "gemini-3.1-flash-lite-preview").strip() or "gemini-3.1-flash-lite-preview"

    if not api_key:
        raise HTTPException(400, "Gemini API key not configured. Go to Settings → AI Triage.")

    finding = items[finding_idx]
    try:
        result = await _gemini_report(api_key, finding, s.target, triage_data, report_format, model)
    except RuntimeError as e:
        raise HTTPException(500, str(e))

    return {"finding_idx": finding_idx, "scan_id": sid, "report": result}

@app.post("/api/triage/{sid}/bulk")
async def triage_bulk(sid: str, data: dict):
    """Triage multiple findings (max 10 at once)."""
    s = scans.get(sid)
    if not s: raise HTTPException(404, "Scan not found")
    cfg     = load_settings()
    api_key = cfg.get("gemini_api_key", "").strip()
    model   = cfg.get("gemini_model", "gemini-3.1-flash-lite-preview").strip() or "gemini-3.1-flash-lite-preview"
    if not api_key:
        raise HTTPException(400, "Gemini API key not configured.")
    items   = s.findings.get("items", [])
    indices = [i for i in data.get("indices", []) if 0 <= i < len(items)][:10]
    tasks   = [_gemini_triage(api_key, items[i], s.target, model) for i in indices]
    results = await asyncio.gather(*tasks)
    return {"results": [{"finding_idx": i, "triage": r} for i, r in zip(indices, results)]}

# ─── Settings Auth ──────────────────────────────────────────────────────────────
_SETTINGS_TOKEN = os.environ.get("WOLF_SETTINGS_TOKEN", "")

def _check_settings_auth(request_token: str = ""):
    """Validate settings token if one is configured via WOLF_SETTINGS_TOKEN env var."""
    if _SETTINGS_TOKEN and request_token != _SETTINGS_TOKEN:
        raise HTTPException(401, "Unauthorized — set WOLF_SETTINGS_TOKEN env var to protect settings")

@app.get("/api/settings")
async def get_settings(token: str = ""):
    _check_settings_auth(token)
    return load_settings()

@app.post("/api/settings")
async def post_settings(data: dict, token: str = ""):
    _check_settings_auth(token)
    try:
        save_settings(data)
        return {"saved": True, "settings": load_settings()}
    except Exception as e:
        raise HTTPException(500, str(e))

# ─── Static files ───────────────────────────────────────────────────────────────
if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

# ─── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("WOLF_PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
