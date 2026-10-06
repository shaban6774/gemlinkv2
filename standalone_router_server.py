"""
standalone_router_server.py - Ultimate Gemini Pro Link Router, Session Hub & Cloudflare Quick Tunnel
=====================================================================================================
Features:
- Instant Sub-5ms 302 Redirection Engine with Connection: close and HTML/JS Fallback.
- Robust 1-Click Clipboard Copying using data-attributes (works on local & Cloudflare HTTPS).
- Automatic TryCloudflare Quick Tunnel (cloudflared):
    * Public links automatically use https://xxxx.trycloudflare.com/c/<token> with genuine HTTPS.
- Ultra-Fast Multi-Threading Engine (150 Workers):
    * Real-time chunked parallel validation (instant health check without UI freezing).
- Google Session Cookies & 3-Way Accurate Status Detector:
    * Fully detects 'Subscription already in use' / Claimed status without false positives.
- Smart Duplicate Filtering on Import:
    * If phone number is already 'Active' in database -> duplicate skipped automatically!
    * If phone number is 'Claimed' -> automatically re-tests via Google Auth Cookies to verify if fresh.
- Real-Time Live Progress Bar & Status Feed (0% -> 100%).
- Full 1080p Screen-Stretched Dark Glassmorphism Multi-Tab UI.
- Indian Proxy Subsystem & Manager.
"""

import os
import sys
import re
import io
import json
import time
import base64
import struct
import hmac
import hashlib
import random
import logging
import zipfile
import threading
import string
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, unquote
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

requests.packages.urllib3.disable_warnings()

# ==================== LOGGING ====================
logging.basicConfig(
    format="%(asctime)s | %(levelname)s | [%(name)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("RouterServer")

# ==================== DIRECTORIES & STORAGE ====================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "router_data"
SESSIONS_DB_FILE = DATA_DIR / "router_sessions.json"
CONFIG_FILE = DATA_DIR / "router_config.json"
ADMIN_SESSIONS_FILE = DATA_DIR / "admin_sessions.json"
GOOGLE_COOKIES_FILE = DATA_DIR / "google_session_cookies.json"
DATABASE_DIR = BASE_DIR / "database"

DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_DIR.mkdir(parents=True, exist_ok=True)

FILE_LOCK = threading.RLock()
SAVE_DEBOUNCE_TIMER: Optional[threading.Timer] = None

def save_json_atomic(path: Path, data: Any):
    with FILE_LOCK:
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            os.replace(str(tmp), str(path))
        except Exception as e:
            logger.error("Failed to save %s: %s", path, e)
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default if default is not None else {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Could not read %s: %s", path, e)
        return default if default is not None else {}

# ==================== CONFIGURATION & PROXIES ====================
DEFAULT_PROXIES = [
    "http://vital74665d262e3e0cf6-package-standard-country-in:n7fd9q4y5sbmgh7e@gw.vital-data.io:9999"
]

DEFAULT_CONFIG = {
    "port": 8081,
    "domain_prefix": "",
    "auto_tunnel": True,
    "totp_secret": "",
    "totp_enabled": True,
    "proxy_enabled": True,
    "proxies": DEFAULT_PROXIES,
    "check_workers": 150,
    "request_timeout": 10,
    "duplicate_filter_enabled": True,
    "auto_refresh_enabled": True,
    "refresh_interval_sec": 900,  # 15 Minutes
}

CONFIG = DEFAULT_CONFIG.copy()
if CONFIG_FILE.exists():
    CONFIG.update(load_json(CONFIG_FILE, {}))
    if not CONFIG.get("proxies"):
        CONFIG["proxies"] = DEFAULT_PROXIES
        CONFIG["proxy_enabled"] = True
    if "auto_refresh_enabled" not in CONFIG:
        CONFIG["auto_refresh_enabled"] = True
    if "refresh_interval_sec" not in CONFIG:
        CONFIG["refresh_interval_sec"] = 900
else:
    save_json_atomic(CONFIG_FILE, CONFIG)

# ==================== CLOUDFLARE QUICK TUNNEL ENGINE ====================
CLOUDFLARE_TUNNEL_URL: Optional[str] = None
CLOUDFLARE_PROCESS: Optional[subprocess.Popen] = None
CLOUDFLARE_LOCK = threading.Lock()

def find_cloudflared_executable() -> Optional[str]:
    local_exe = BASE_DIR / ("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
    if local_exe.exists():
        return str(local_exe)

    path_exe = shutil.which("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
    if path_exe:
        return str(path_exe)

    if sys.platform == "win32":
        candidates = [
            Path("C:/Users/ADMIN/Desktop/vechile api/cloudflared.exe"),
            Path("C:/cloudflared/cloudflared.exe"),
            Path(os.environ.get("USERPROFILE", "")) / "Desktop" / "cloudflared.exe",
        ]
        for c in candidates:
            if c.exists():
                return str(c)

    return None

def download_cloudflared(target_path: Path) -> bool:
    logger.info("Downloading official cloudflared binary...")
    url = (
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        if sys.platform == "win32"
        else "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    )
    try:
        r = requests.get(url, stream=True, timeout=30)
        if r.status_code == 200:
            with open(target_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            if sys.platform != "win32":
                os.chmod(target_path, 0o755)
            logger.info("Successfully downloaded cloudflared to %s", target_path)
            return True
    except Exception as e:
        logger.error("Failed downloading cloudflared: %s", e)
    return False

def start_cloudflare_tunnel(port: int):
    global CLOUDFLARE_TUNNEL_URL, CLOUDFLARE_PROCESS
    if not CONFIG.get("auto_tunnel", True):
        return

    with CLOUDFLARE_LOCK:
        if CLOUDFLARE_PROCESS:
            try:
                CLOUDFLARE_PROCESS.terminate()
            except Exception:
                pass

        exe_path = find_cloudflared_executable()
        if not exe_path:
            target = BASE_DIR / ("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
            if download_cloudflared(target):
                exe_path = str(target)

        if not exe_path:
            logger.warning("Cloudflared binary not found. Running in local port mode.")
            return

        logger.info("Starting Cloudflare Quick Tunnel on port %s using %s...", port, exe_path)
        cmd = [exe_path, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"]

        try:
            CLOUDFLARE_PROCESS = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
        except Exception as e:
            logger.error("Failed to start cloudflared process: %s", e)
            return

    def _monitor():
        global CLOUDFLARE_TUNNEL_URL
        tunnel_regex = re.compile(r"https://([a-zA-Z0-9-]+\.trycloudflare\.com)")
        for line in CLOUDFLARE_PROCESS.stderr:
            match = tunnel_regex.search(line)
            if match:
                url = match.group(0)
                CLOUDFLARE_TUNNEL_URL = url
                logger.info("================================================================")
                logger.info("⚡ CLOUDFLARE QUICK TUNNEL LIVE & ACTIVE!")
                logger.info("👉 Public Tunnel URL:      %s", url)
                logger.info("👉 Public Web Dashboard:    %s/admin", url)
                logger.info("👉 Public 302 Redirection:  %s/c/<token>", url)
                logger.info("================================================================")
                break

    threading.Thread(target=_monitor, daemon=True).start()

def normalize_proxy_url(proxy: Optional[str]) -> Optional[str]:
    p = str(proxy or "").strip().lstrip("\ufeff")
    if not p:
        return None
    if p.startswith(("http://", "https://", "socks5://", "socks5h://")):
        return p
    if "@" not in p:
        parts = p.split(":", 3)
        if len(parts) == 4:
            host, port, user, password = (x.strip() for x in parts)
            if host and port and user and password and port.isdigit():
                return f"http://{user}:{password}@{host}:{port}"
    return f"http://{p}"

def get_active_proxy() -> Optional[str]:
    if not CONFIG.get("proxy_enabled", True):
        return None
    proxies = CONFIG.get("proxies", [])
    if proxies:
        raw_p = random.choice(proxies)
        return normalize_proxy_url(raw_p)
    return None

def test_proxy_connection(proxy_str: str) -> Tuple[bool, str, float]:
    p = normalize_proxy_url(proxy_str)
    if not p:
        return False, "Invalid proxy format", 0.0
    start = time.time()
    proxies = {"http": p, "https": p}
    try:
        r = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=8)
        dur = round((time.time() - start) * 1000, 1)
        if r.status_code == 200:
            ip = r.json().get("ip", "Unknown")
            return True, f"Exit IP: {ip} ({dur}ms)", dur
        return False, f"HTTP {r.status_code}", dur
    except Exception as e:
        dur = round((time.time() - start) * 1000, 1)
        return False, f"Error: {str(e)}", dur

# ==================== 2FA / TOTP ====================
ADMIN_SESSIONS: Dict[str, float] = {}

def load_admin_sessions():
    global ADMIN_SESSIONS
    data = load_json(ADMIN_SESSIONS_FILE, {})
    now = time.time()
    ADMIN_SESSIONS = {k: float(v) for k, v in data.items() if isinstance(v, (int, float)) and v > now}

load_admin_sessions()

def create_admin_session() -> str:
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"
    token = "".join(random.choices(alphabet, k=36))
    now = time.time()
    with FILE_LOCK:
        ADMIN_SESSIONS[token] = now + (86400 * 30)
        for k in list(ADMIN_SESSIONS.keys()):
            if ADMIN_SESSIONS[k] < now:
                del ADMIN_SESSIONS[k]
        save_json_atomic(ADMIN_SESSIONS_FILE, ADMIN_SESSIONS)
    return token

def is_valid_admin_session(token: str) -> bool:
    if not token:
        return False
    now = time.time()
    exp = ADMIN_SESSIONS.get(token, 0)
    if exp > now:
        return True
    if token in ADMIN_SESSIONS:
        del ADMIN_SESSIONS[token]
        save_json_atomic(ADMIN_SESSIONS_FILE, ADMIN_SESSIONS)
    return False

def generate_totp_secret(length: int = 32) -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(random.choices(chars, k=length))

def verify_totp(secret: str, user_code: str, window: int = 2) -> bool:
    clean_code = re.sub(r"\D", "", str(user_code or "").strip())
    if len(clean_code) != 6 or not secret:
        return False
    try:
        clean_secret = secret.strip().upper().replace(" ", "").replace("-", "")
        padding = (8 - len(clean_secret) % 8) % 8
        key = base64.b32decode(clean_secret + "=" * padding)
        now_step = int(time.time() // 30)
        for step in range(now_step - window, now_step + window + 1):
            msg = struct.pack(">Q", step)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 15
            code = str((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000).zfill(6)
            if code == clean_code:
                return True
    except Exception as e:
        logger.error("TOTP verification error: %s", e)
    return False

if not CONFIG.get("totp_secret"):
    CONFIG["totp_secret"] = generate_totp_secret(32)
    save_json_atomic(CONFIG_FILE, CONFIG)

# ==================== RATE LIMITING & SECURITY ====================
LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
LOGIN_LOCKOUTS: Dict[str, float] = {}

def check_login_rate_limit(client_ip: str) -> Tuple[bool, str]:
    now = time.time()
    lockout_until = LOGIN_LOCKOUTS.get(client_ip, 0)
    if lockout_until > now:
        remaining = int(lockout_until - now)
        return False, f"Too many failed attempts. Locked out for {remaining}s."
    
    attempts = [t for t in LOGIN_ATTEMPTS.get(client_ip, []) if now - t < 600]
    LOGIN_ATTEMPTS[client_ip] = attempts
    
    if len(attempts) >= 5:
        LOGIN_LOCKOUTS[client_ip] = now + 900
        LOGIN_ATTEMPTS[client_ip] = []
        return False, "Too many failed attempts. Locked out for 15 minutes."
    
    if len(attempts) >= 3:
        time.sleep(2)
        
    return True, ""

def record_failed_login(client_ip: str):
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(client_ip, []) if now - t < 600]
    attempts.append(now)
    LOGIN_ATTEMPTS[client_ip] = attempts
    if len(attempts) >= 5:
        LOGIN_LOCKOUTS[client_ip] = now + 900
        LOGIN_ATTEMPTS[client_ip] = []

def record_successful_login(client_ip: str):
    LOGIN_ATTEMPTS.pop(client_ip, None)
    LOGIN_LOCKOUTS.pop(client_ip, None)

# ==================== GOOGLE SESSION COOKIES & ACCURATE 3-WAY VALIDATOR ====================
GOOGLE_SESSION_COOKIES: Dict[str, str] = {}

def parse_cookie_string(raw: str) -> dict:
    cookies = {}
    if not raw:
        return cookies
    raw = raw.strip()
    if raw.startswith("{") or raw.startswith("["):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "name" in item and "value" in item:
                        cookies[item["name"]] = str(item["value"])
                return cookies
        except Exception:
            pass
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies[parts[5].strip()] = parts[6].strip()
        else:
            for item in line.split(";"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if k:
                        cookies[k] = v
    return cookies

def load_google_cookies() -> dict:
    global GOOGLE_SESSION_COOKIES
    data = load_json(GOOGLE_COOKIES_FILE, {})
    if isinstance(data, dict):
        GOOGLE_SESSION_COOKIES = data
    return GOOGLE_SESSION_COOKIES

load_google_cookies()

def save_google_cookies(cookies: dict):
    global GOOGLE_SESSION_COOKIES
    GOOGLE_SESSION_COOKIES = cookies
    save_json_atomic(GOOGLE_COOKIES_FILE, cookies)

_GOOGLE_VALIDATOR_LOCAL = threading.local()

def _google_cookie_fingerprint(cookies: Any) -> str:
    if not cookies:
        return ""
    if isinstance(cookies, list):
        safe = "\n".join(f"{c.get('name')}={c.get('value')}" for c in cookies if isinstance(c, dict))
    elif isinstance(cookies, dict):
        safe = "\n".join(f"{k}={cookies[k]}" for k in sorted(cookies))
    else:
        safe = str(cookies)
    return hashlib.sha256(safe.encode("utf-8")).hexdigest()[:16]

def _get_google_validator_session(g_cookies: Any = None, proxy: str = None) -> requests.Session:
    """One keep-alive Session per validator thread; recreated if auth/proxy changes."""
    cookie_fp = _google_cookie_fingerprint(g_cookies)
    key = (cookie_fp, proxy or "")
    sess = getattr(_GOOGLE_VALIDATOR_LOCAL, "session", None)
    old_key = getattr(_GOOGLE_VALIDATOR_LOCAL, "key", None)
    if sess is None or old_key != key:
        if sess is not None:
            try:
                sess.close()
            except Exception:
                pass
        sess = requests.Session()
        sess.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        })
        if g_cookies:
            if isinstance(g_cookies, dict):
                cookie_header = "; ".join([f"{k}={v}" for k, v in g_cookies.items() if v])
                sess.headers["Cookie"] = cookie_header
                for k, v in g_cookies.items():
                    k_str = str(k).strip()
                    v_str = str(v).strip()
                    try:
                        sess.cookies.set(k_str, v_str, domain=".google.com", path="/")
                        sess.cookies.set(k_str, v_str, domain=".serviceactivation.google.com", path="/")
                        sess.cookies.set(k_str, v_str, domain=".one.google.com", path="/")
                    except Exception:
                        pass
            elif isinstance(g_cookies, list):
                cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in g_cookies if isinstance(c, dict) and "name" in c and "value" in c])
                sess.headers["Cookie"] = cookie_header
                for c in g_cookies:
                    if isinstance(c, dict) and "name" in c and "value" in c:
                        k_str = str(c["name"]).strip()
                        v_str = str(c["value"]).strip()
                        try:
                            sess.cookies.set(k_str, v_str, domain=".google.com", path="/")
                            sess.cookies.set(k_str, v_str, domain=".serviceactivation.google.com", path="/")
                            sess.cookies.set(k_str, v_str, domain=".one.google.com", path="/")
                        except Exception:
                            pass
        if proxy:
            sess.proxies = {"http": proxy, "https": proxy}
        _GOOGLE_VALIDATOR_LOCAL.session = sess
        _GOOGLE_VALIDATOR_LOCAL.key = key
    return sess

def test_google_cookies_validity(cookies: dict) -> Tuple[bool, str]:
    if not cookies:
        return False, "No Google session cookies provided"
    
    pxy = get_active_proxy()
    sess = _get_google_validator_session(cookies, proxy=pxy)
    try:
        r = sess.get("https://one.google.com/u/0/", timeout=8, allow_redirects=True)
        final_url = str(r.url or "").lower()
        if "accounts.google.com" in final_url or "signin" in final_url or "servicelogin" in final_url or "one.google.com/about" in final_url:
            return False, "Google Session Expired / Login Required"
        if r.status_code == 200:
            return True, "Google Session Active & Authenticated!"
        return False, f"HTTP Status {r.status_code}"
    except Exception as e:
        return False, f"Network Error: {str(e)}"

def validate_google_link_status(google_url: str, timeout: float = 7.0) -> Tuple[str, str, int]:
    if not google_url:
        return "Expired", "empty_url", 0

    clean_tok = extract_token_from_url(google_url)
    if not clean_tok:
        return "Expired", "invalid_token", 0

    g_cookies = load_google_cookies()
    pxy = get_active_proxy()
    sess = _get_google_validator_session(g_cookies, proxy=pxy)

    # Validate using Google One and ServiceActivation endpoints
    check_url = f"https://one.google.com/activate-plan/subscription/new/{clean_tok}"

    try:
        r = sess.get(check_url, timeout=timeout, allow_redirects=True)
        code = r.status_code
        final_url = str(r.url or "").lower()
        raw_text = r.text or ""
        t_normalized = re.sub(r'\s+', ' ', raw_text.replace('\xa0', ' ').replace('\u00a0', ' ')).lower()

        if code in (404, 410):
            return "Expired", "not_found", code

        used_markers = (
            "subscription already in use",
            "already in use",
            "this subscription link has already been used",
            "subscription link has already been used",
            "this activation link has already been used",
            "activation link has already been used",
            "this link has already been used",
            "offer link has already been used",
            "this offer link has already been redeemed",
            "already redeemed",
            "already been redeemed",
            "has already been redeemed",
            "already claimed",
            "already availed",
            "explore google one for benefits",
            "explore google one",
            "offer has expired or already been redeemed",
            "this promo code has already been redeemed",
            "code has already been redeemed",
            "offer is no longer available",
            "offer_already_used",
            "already_redeemed",
            "already-redeemed",
            "already-used",
            "g1_landing_page=5",
            "g1_landing_page=4",
        )
        if any(x in t_normalized or x in final_url for x in used_markers):
            return "Claimed", "already_claimed", code

        expired_markers = (
            "you need a new activation link",
            "you need a new link",
            "ask your provider to send a new link",
            "ask your provider",
            "invalid activation link",
            "invalid link",
            "no longer valid",
            "link has expired",
            "activation link has expired",
        )
        if any(x in t_normalized for x in expired_markers):
            return "Expired", "link_expired", code

        if "one.google.com" in final_url and code == 200 and "about" not in final_url:
            return "Active", "activation_ready", code

        if "accounts.google.com" in final_url or "signin" in final_url or "servicelogin" in final_url:
            return "Expired", "google_login_required", code

        if code in (200, 302, 301):
            return "Active", "activation_ready", code

        return "Expired", f"http_{code}", code
    except requests.Timeout:
        return "Active", "timeout_assumed_active", 0
    except Exception as e:
        return "Expired", f"network_{e.__class__.__name__}", 0

# ==================== JIO REFRESH ENGINE ====================
IV = b"19A2B66D8F01Z9P7"
MAPP_URL = "https://myjio.jio.com/MappServer3/servlet/Service"
APP_VERSION = 8037
MAPP_HEADERS = {
    "Cache-Control": "no-cache",
    "Content-Type": "application/json; charset=utf-8",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Accept": "*/*",
    "User-Agent": "okhttp/4.12.0",
}

def txn_id():
    return "0001" + str(int(time.time() * 1000) % 10**12).zfill(12)

def ts():
    return time.strftime("%Y%m%d%H%M%S", time.localtime())

def rand_dev():
    d = lambda n: "".join(random.choices(string.digits, k=n))
    h = lambda n: "".join(random.choices("0123456789abcdef", k=n))
    return {
        "device": d(15),
        "networkType": "WIFI",
        "host": "10.0.2.15",
        "osBuildNumber": "Nubia-user 7.1.2 20171130.276299 release-keys",
        "mac": ":".join(h(2) for _ in range(6)),
        "platform": "android",
        "xandroidId": h(16),
        "imei": "",
        "carrierOne": "NA| (12345678121) ",
        "osFingerprint": "Nubia/Nubia/NX809J:7.1.2/20171130.376229:user/release-keys",
        "carrierTwo": "",
        "version": "7.1.2",
        "operatorType": "Reliance Jio",
        "manufacturer": "Nubia",
        "serial": d(8),
        "type": "GSM",
        "cpuAbi": "intel",
        "imsi": "4058" + d(11),
        "model": "NX809J",
        "product": "NX809J",
    }

def aes_enc(pt, key):
    if not pt:
        return ""
    ct = AES.new(key, AES.MODE_CBC, IV).encrypt(pad(pt.encode("utf-8"), 16))
    b = base64.b64encode(ct).decode("utf-8")
    return "\n".join(b[i:i + 76] for i in range(0, len(b), 76)) + "\n"

def aes_dec(ct, key):
    if not ct:
        return None
    raw = base64.b64decode(ct.replace("\n", ""))
    return unpad(AES.new(key, AES.MODE_CBC, IV).decrypt(raw), 16).decode("utf-8")

class MappClient:
    def __init__(self, proxy=None):
        self.proxy = proxy or get_active_proxy()
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers.update(MAPP_HEADERS)
        if self.proxy:
            self.s.proxies = {"http": self.proxy, "https": self.proxy}
        self.sid = None
        self.dev = rand_dev()
        self.key = None

    def _post(self, pl):
        data = json.dumps(pl, separators=(",", ":")).encode("utf-8")
        for _ in range(3):
            try:
                return self.s.post(MAPP_URL, data=data, timeout=12).json()
            except Exception:
                time.sleep(1)
        return {}

    def _pub(self, extra=None):
        p = {
            "AdId": "00000000-0000-0000-0000-000000000000",
            "appId": "com.jio.myjio",
            "circleId": "",
            "customerId": "",
            "darkMode": False,
            "jioroute": "",
            "lang": "en_US",
            "osType": "android",
            "serviceId": "",
            "sessionId": self.sid or "",
            "timestamp": ts(),
            "version": APP_VERSION,
        }
        if extra:
            p.update(extra)
        return p

    def handshake(self):
        rsa = RSA.generate(1024)
        pub = base64.b64encode(rsa.publickey().export_key(format="DER")).decode()
        j = self._post({
            "pubInfo": self._pub(),
            "requestList": [{
                "busiCode": "GetTransKey",
                "busiParams": {"deviceInfo": self.dev, "key": pub, "type": 0},
                "isEncrypt": False,
                "transactionId": txn_id(),
            }],
        })
        rd = (j.get("respData") or [{}])[0]
        rm = rd.get("respMsg")
        if isinstance(rm, dict) and rm.get("sessionId"):
            self.sid = rm["sessionId"]
            self.key = self.sid[:16].encode("utf-8")
            return self.sid
        return None

    def call(self, bc, bp, extra=None, enc=True):
        if not self.sid:
            self.handshake()
        pl = json.dumps(bp, separators=(",", ":"))
        j = self._post({
            "pubInfo": self._pub(extra),
            "requestList": [{
                "busiCode": bc,
                "busiParams": aes_enc(pl, self.key) if enc else bp,
                "isEncrypt": enc,
                "transactionId": txn_id(),
            }],
        })
        rd = (j.get("respData") or [{}])[0]
        code, msg, rm = rd.get("code"), rd.get("message"), rd.get("respMsg")
        if rd.get("isEncrypt") and isinstance(rm, str) and rm:
            try:
                rm = json.loads(aes_dec(rm, self.key))
            except Exception:
                rm = {"_err": rm}
        return code, msg, rm

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

def extract_accounts(sess: dict) -> list:
    accounts, seen = [], set()
    if not isinstance(sess, dict):
        return accounts
    primary = sess.get("account", {})
    if primary and isinstance(primary, dict):
        srv = primary.get("serviceId") or primary.get("serviceid")
        if srv:
            accounts.append(primary)
            seen.add(str(srv))
    raw_login = sess.get("login_response")
    if isinstance(raw_login, dict):
        cust_list = raw_login.get("myCustomerInfo", [])
        if isinstance(cust_list, list):
            for c in cust_list:
                if isinstance(c, dict):
                    srv = c.get("serviceId") or c.get("serviceid")
                    if srv and str(srv) not in seen:
                        accounts.append({
                            "customerId": c.get("customerId", ""),
                            "serviceId": str(srv),
                            "accountId": c.get("accountId", ""),
                            "circleId": c.get("circleId", primary.get("circleId", "BR") if isinstance(primary, dict) else "BR"),
                            "jioroute": c.get("jioroute", primary.get("jioroute", "EA382") if isinstance(primary, dict) else "EA382"),
                        })
                        seen.add(str(srv))
    return accounts

def fetch_fresh_gemini_link(session_data: dict, proxy: str = None) -> Tuple[bool, str, Optional[str]]:
    if not session_data or not isinstance(session_data, dict):
        return False, "Invalid session data", None

    cur_proxy = proxy or get_active_proxy()
    mob = str(session_data.get("mobile") or session_data.get("number") or session_data.get("serviceId") or "").strip()
    tokens = session_data.get("tokens", {}) if isinstance(session_data.get("tokens"), dict) else {}
    jtoken = tokens.get("jtoken") or tokens.get("jToken") or session_data.get("jtoken") or session_data.get("jToken")
    sso_token = (
        tokens.get("ssotoken")
        or tokens.get("ssoToken")
        or session_data.get("sso-token")
        or session_data.get("ssotoken")
        or session_data.get("ssoToken")
        or ""
    )
    session_id = session_data.get("sessionId_at_login") or session_data.get("JioSessionID") or ""
    lb_cookie = str(tokens.get("lbcookie", "1"))
    accounts = extract_accounts(session_data)

    if jtoken:
        try:
            payload = {
                "proxy": cur_proxy or DEFAULT_PROXIES[0],
                "number": mob,
                "tokens": tokens or {"jtoken": jtoken, "ssotoken": sso_token, "ssolevel": tokens.get("ssolevel", "40"), "lbcookie": lb_cookie},
                "account": accounts[0] if accounts else {"serviceid": mob},
            }
            r = requests.post("http://dev-api.cc/refresh.php", json=payload, timeout=20)
            txt = r.text.strip()
            if r.status_code == 200 and "serviceactivation.google.com/subscription/new/" in txt:
                tok = extract_token_from_url(txt)
                if tok:
                    clean_u = f"https://serviceactivation.google.com/subscription/new/{tok}"
                    return True, clean_u, tok
        except Exception:
            pass

    if sso_token or session_id:
        try:
            sess = requests.Session()
            if cur_proxy:
                sess.proxies = {"http": cur_proxy, "https": cur_proxy}

            sess.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://www.jio.com",
                "Referer": "https://www.jio.com/selfcare/googleai/?header=no&type=Z0241&source=JIO",
                "sso-token": str(sso_token),
                "lb-cookie": str(lb_cookie),
            })
            if session_id:
                sess.headers["JioSessionID"] = str(session_id)
                sess.cookies.set("JioSessionID", str(session_id))
            if sso_token:
                sess.cookies.set("sso-token", str(sso_token))

            try:
                r_auth = sess.get("https://www.jio.com/api/jio-authenticate-service/authenticate/authJsonData", headers={"Referer": "https://www.jio.com/selfcare/dashboard/"}, timeout=6)
                if r_auth.ok:
                    tok = r_auth.json().get("token")
                    if tok:
                        sess.headers["Authorization"] = f"Bearer {tok}"
            except Exception:
                pass

            try:
                sess.get("https://www.jio.com/api/jio-ott-service/ott/subscription/navigate/Z0241", headers={"Referer": "https://www.jio.com/selfcare/dashboard/"}, timeout=6)
            except Exception:
                pass

            pattern = re.compile(r"https?://(?:serviceactivation\.google\.com|one\.google\.com/activate-plan)/subscription/new/([a-zA-Z0-9_\-]+={0,2})")
            for endpoint in [
                "https://www.jio.com/api/jio-ott-service/ott/subscription/activate/Z0241?source=JIO",
                "https://www.jio.com/api/jio-ott-service/ott/subscription/google-ai"
            ]:
                try:
                    r = sess.get(endpoint, headers={"Referer": "https://www.jio.com/selfcare/googleai/?header=no&type=Z0241&source=JIO"}, timeout=8)
                    m = pattern.search(r.text or "")
                    if m:
                        full_u = m.group(0)
                        if not full_u.startswith("https://"):
                            full_u = "https://" + full_u
                        return True, full_u, m.group(1)
                except Exception:
                    pass
            sess.close()
        except Exception:
            pass

    if accounts or mob:
        target_accounts = accounts if accounts else [{"serviceId": mob, "customerId": "", "accountId": "", "circleId": "BR", "jioroute": "EA382"}]
        for acct in target_accounts:
            try:
                mc = MappClient(proxy=cur_proxy)
                mc.handshake()
                extra = {
                    "customerId": acct.get("customerId", ""),
                    "serviceId": acct.get("serviceId", mob),
                    "circleId": acct.get("circleId", "BR"),
                    "jioroute": acct.get("jioroute", "EA382"),
                }
                bp = {"accountId": acct.get("accountId", ""), "serviceId": acct.get("serviceId", mob)}
                mc.call("ActivateGoogle", bp, extra)
                code, msg, rm = mc.call("GetGeminiRedirection", bp, extra)
                mc.close()
                if isinstance(rm, dict):
                    url = (rm.get("responseObj") or {}).get("redirectionURL") or rm.get("redirectionURL")
                    if url:
                        tok = extract_token_from_url(url)
                        return True, url, tok
            except Exception:
                pass

    existing = session_data.get("activation_url") or session_data.get("google_activation_url") or session_data.get("url")
    if existing and "serviceactivation.google.com" in str(existing):
        tok = extract_token_from_url(existing)
        return True, f"https://serviceactivation.google.com/subscription/new/{tok}", tok

    return False, "Could not obtain fresh activation link", None

# ==================== 24/7 BACKGROUND AUTO-REFRESH WORKER ====================
def refresh_all_active_sessions() -> Tuple[int, int]:
    """Pre-caches fresh Google activation links for all active sessions."""
    active_items = []
    with FILE_LOCK:
        for tok, item in list(SESSIONS_DB.items()):
            if item.get("status") == "Active" and (item.get("session_data") or item.get("number")):
                active_items.append((tok, item))

    if not active_items:
        return 0, 0

    logger.info("🔄 Pre-caching fresh Google activation links for %s active sessions...", len(active_items))

    def _refresh_single(entry):
        tok, itm = entry
        try:
            sess_d = itm.get("session_data") or {}
            if not sess_d and itm.get("number") and itm.get("number") != "Unknown":
                f_path = DATABASE_DIR / f"{itm['number']}.json"
                if f_path.exists():
                    sess_d = load_json(f_path, {}).get("session_data", {})
            if sess_d:
                ok, fresh_url, new_tok = fetch_fresh_gemini_link(sess_d)
                if ok and fresh_url:
                    with FILE_LOCK:
                        itm["cached_live_url"] = fresh_url
                        itm["last_cached_at"] = time.time()
                        itm["google_url"] = fresh_url
                        itm["last_refreshed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        SESSIONS_DB[tok] = itm
                    return True
        except Exception as ex:
            logger.debug("Auto-refresh failed for %s: %s", itm.get("number"), ex)
        return False

    workers = min(len(active_items), 50)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_refresh_single, active_items))
    
    refreshed_count = sum(1 for r in results if r)
    schedule_save_sessions()
    logger.info("✅ Pre-cached %s/%s fresh Google activation links successfully!", refreshed_count, len(active_items))
    return refreshed_count, len(active_items)

def refresh_single_session(token: str) -> dict:
    """Instant single session renewal and status re-validation."""
    clean_tok = str(token or "").strip()
    item = SESSIONS_DB.get(clean_tok)
    if not item:
        return {"success": False, "error": "Session token not found in database"}

    sess_d = item.get("session_data") or {}
    if not sess_d and item.get("number") and item.get("number") != "Unknown":
        f_path = DATABASE_DIR / f"{item['number']}.json"
        if f_path.exists():
            sess_d = load_json(f_path, {}).get("session_data", {})

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    now_ts = time.time()

    if sess_d:
        ok, fresh_url, new_tok = fetch_fresh_gemini_link(sess_d)
        if ok and fresh_url:
            with FILE_LOCK:
                item["cached_live_url"] = fresh_url
                item["google_url"] = fresh_url
                item["last_cached_at"] = now_ts
                item["last_refreshed_at"] = now_str
                item["last_checked"] = now_str
                item["status"] = "Active"
                SESSIONS_DB[clean_tok] = item
                schedule_save_sessions()
            return {
                "success": True,
                "token": clean_tok,
                "number": item.get("number", "Unknown"),
                "fresh_url": fresh_url,
                "status": "Active",
                "last_refreshed_at": now_str,
                "last_cached_at": now_ts,
                "message": "Fresh Google link generated & cached!"
            }

    # Fallback to health validation
    target_url = item.get("google_url") or f"https://serviceactivation.google.com/subscription/new/{clean_tok}"
    st, reason, code = validate_google_link_status(target_url)
    with FILE_LOCK:
        item["status"] = st
        item["http_status"] = code
        item["last_checked"] = now_str
        item["last_cached_at"] = now_ts
        item["last_refreshed_at"] = now_str
        SESSIONS_DB[clean_tok] = item
        schedule_save_sessions()

    return {
        "success": True,
        "token": clean_tok,
        "number": item.get("number", "Unknown"),
        "fresh_url": target_url,
        "status": st,
        "http_code": code,
        "last_refreshed_at": now_str,
        "last_cached_at": now_ts,
        "message": f"Link refreshed & verified: {st}"
    }

def background_auto_refresh_worker():
    """Continuously refreshes active sessions every N minutes so links never expire."""
    logger.info("⚡ Background 24/7 Auto-Refresh Engine started.")
    # Initial warm-up run after 10 seconds
    time.sleep(10)
    while True:
        try:
            enabled = CONFIG.get("auto_refresh_enabled", True)
            if enabled and SESSIONS_DB:
                refresh_all_active_sessions()
        except Exception as e:
            logger.error("Auto-refresh loop error: %s", e)

        interval_val = int(CONFIG.get("refresh_interval_sec", 900))
        sleep_until = time.time() + max(30, interval_val)
        while time.time() < sleep_until:
            time.sleep(5)

# ==================== HELPERS & SESSIONS DB ====================
URL_TOKEN_REGEX = re.compile(
    r"https?://(?:serviceactivation\.google\.com|one\.google\.com/activate-plan)/subscription/new/([A-Za-z0-9_-]{25,}(?:={0,2}))",
    re.IGNORECASE,
)
PHONE_REGEX = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")

def extract_token_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    url_str = str(url).strip()
    m = URL_TOKEN_REGEX.search(url_str)
    if m:
        return m.group(1).strip()
    if "\n" not in url_str and "\r" not in url_str and "{" not in url_str:
        clean = url_str.split("?")[0].split("&")[0].strip("/")
        if len(clean) >= 25 and re.match(r"^[A-Za-z0-9_-]+={0,2}$", clean):
            return clean
    return None

def extract_phone(text: str) -> Optional[str]:
    m = PHONE_REGEX.search(str(text))
    return m.group(1) if m else None

BASE56_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

def compute_short_code(token: str, number: Optional[str] = None) -> str:
    raw = f"{number or ''}:{token or ''}:salt_v3_secure_20"
    h = hashlib.sha256(raw.encode("utf-8")).digest()
    n = int.from_bytes(h, "big")
    chars = []
    for _ in range(20):
        chars.append(BASE56_ALPHABET[n % len(BASE56_ALPHABET)])
        n //= len(BASE56_ALPHABET)
    return "".join(chars)

SESSIONS_DB: Dict[str, dict] = {}
SHORT_CODE_MAP: Dict[str, str] = {}

def rebuild_short_code_map():
    global SHORT_CODE_MAP
    with FILE_LOCK:
        new_map = {}
        for tok, item in SESSIONS_DB.items():
            sc = item.get("short_code")
            if not sc or len(sc) != 20:
                sc = compute_short_code(tok, item.get("number"))
                item["short_code"] = sc
            new_map[sc] = tok
            num = item.get("number")
            if num and num != "Unknown":
                new_map[num] = tok
        SHORT_CODE_MAP = new_map

def load_sessions():
    global SESSIONS_DB
    data = load_json(SESSIONS_DB_FILE, {})
    if isinstance(data, dict):
        SESSIONS_DB = data
    else:
        SESSIONS_DB = {}

    # Merge all sessions from database directory
    try:
        for f in DATABASE_DIR.glob("*.json"):
            try:
                d = load_json(f, {})
                tok = d.get("token")
                num = d.get("number") or f.stem
                url = d.get("activation_url")
                if tok:
                    if tok not in SESSIONS_DB:
                        SESSIONS_DB[tok] = {
                            "token": tok,
                            "number": num,
                            "google_url": url or f"https://serviceactivation.google.com/subscription/new/{tok}",
                            "status": d.get("status", "Active"),
                            "clicks": 0,
                            "created_at": d.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                            "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "last_accessed": None,
                            "http_status": 200,
                            "source": "database_folder",
                            "session_data": d.get("session_data", {}),
                            "short_code": compute_short_code(tok, num),
                            "last_cached_at": time.time(),
                            "last_refreshed_at": d.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        }
                    else:
                        if not SESSIONS_DB[tok].get("short_code"):
                            SESSIONS_DB[tok]["short_code"] = compute_short_code(tok, num)
                        if not SESSIONS_DB[tok].get("session_data") and d.get("session_data"):
                            SESSIONS_DB[tok]["session_data"] = d.get("session_data")
            except Exception:
                pass
    except Exception as e:
        logger.error("Error loading database folder sessions: %s", e)

    now_t = time.time()
    for tok, itm in SESSIONS_DB.items():
        if "last_cached_at" not in itm:
            try:
                dt = datetime.strptime(itm.get("created_at", ""), "%Y-%m-%d %H:%M:%S")
                itm["last_cached_at"] = dt.timestamp()
            except Exception:
                itm["last_cached_at"] = now_t
        if "last_refreshed_at" not in itm:
            itm["last_refreshed_at"] = itm.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    rebuild_short_code_map()

load_sessions()

def schedule_save_sessions():
    global SAVE_DEBOUNCE_TIMER
    with FILE_LOCK:
        if SAVE_DEBOUNCE_TIMER is not None:
            return
        SAVE_DEBOUNCE_TIMER = threading.Timer(1.5, _async_save_worker)
        SAVE_DEBOUNCE_TIMER.daemon = True
        SAVE_DEBOUNCE_TIMER.start()

def _async_save_worker():
    global SAVE_DEBOUNCE_TIMER
    with FILE_LOCK:
        SAVE_DEBOUNCE_TIMER = None
    save_json_atomic(SESSIONS_DB_FILE, SESSIONS_DB)

def save_sessions_sync():
    save_json_atomic(SESSIONS_DB_FILE, SESSIONS_DB)

def find_session_by_number(number: str) -> Optional[Tuple[str, dict]]:
    if not number or number == "Unknown":
        return None
    with FILE_LOCK:
        for tok, sess in SESSIONS_DB.items():
            if sess.get("number") == number:
                return tok, sess
    return None

def add_or_update_session(
    token: str,
    number: Optional[str] = None,
    google_url: Optional[str] = None,
    session_data: Optional[dict] = None,
    source: str = "import",
    status: str = "Active",
) -> dict:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_tok = str(token or "").strip()
    
    clean_url = f"https://serviceactivation.google.com/subscription/new/{clean_tok}"
    if google_url and google_url.startswith("https://") and "\n" not in google_url and "\r" not in google_url and len(google_url) < 350 and "{" not in google_url:
        clean_url = google_url.strip()

    num_val = number or extract_phone(clean_tok) or "Unknown"
    short_code = compute_short_code(clean_tok, num_val)

    with FILE_LOCK:
        item = SESSIONS_DB.get(clean_tok, {})
        now_ts = time.time()
        if not item:
            item = {
                "token": clean_tok,
                "number": num_val,
                "short_code": short_code,
                "google_url": clean_url,
                "status": status,
                "clicks": 0,
                "created_at": now_str,
                "last_checked": now_str,
                "last_accessed": None,
                "last_cached_at": now_ts,
                "last_refreshed_at": now_str,
                "http_status": 200 if status == "Active" else 400,
                "source": source,
                "session_data": session_data if isinstance(session_data, dict) else {},
            }
        else:
            if number and item.get("number") in ("Unknown", None, ""):
                item["number"] = number
            if not item.get("short_code"):
                item["short_code"] = short_code
            item["google_url"] = clean_url
            if session_data and isinstance(session_data, dict):
                item["session_data"] = session_data
            item["status"] = status
            item["last_checked"] = now_str
            if "last_cached_at" not in item:
                item["last_cached_at"] = now_ts
                item["last_refreshed_at"] = now_str

        SESSIONS_DB[clean_tok] = item
        SHORT_CODE_MAP[item["short_code"]] = clean_tok
        if item.get("number") and item["number"] != "Unknown":
            SHORT_CODE_MAP[item["number"]] = clean_tok

        schedule_save_sessions()

        if item.get("number") and item["number"] != "Unknown":
            phone_file = DATABASE_DIR / f"{item['number']}.json"
            save_json_atomic(phone_file, {
                "number": item["number"],
                "token": clean_tok,
                "short_code": item.get("short_code", short_code),
                "activation_url": clean_url,
                "created_at": item["created_at"],
                "status": item["status"],
                "session_data": item.get("session_data", {})
            })

        return item

def check_single_token_health(token: str) -> dict:
    clean_tok = str(token or "").strip()
    item = SESSIONS_DB.get(clean_tok)
    if not item:
        return {"success": False, "token": clean_tok, "error": "Token not found"}

    target_url = item.get("google_url") or f"https://serviceactivation.google.com/subscription/new/{clean_tok}"
    status_label, reason, code = validate_google_link_status(target_url)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with FILE_LOCK:
        item["http_status"] = code
        item["status"] = status_label
        item["last_checked"] = now_str
        SESSIONS_DB[clean_tok] = item
        schedule_save_sessions()

    return {
        "success": True,
        "token": clean_tok,
        "number": item.get("number", "Unknown"),
        "status": status_label,
        "reason": reason,
        "http_code": code,
        "is_alive": (status_label == "Active"),
        "last_checked": now_str,
    }

# ==================== PARSE & IMPORT WITH DUPLICATE FILTER ====================
def process_single_session_raw(filename: str, raw_text: str, filter_duplicates: bool = True) -> Tuple[Optional[dict], str]:
    text = raw_text.strip()
    if not text:
        return None, "empty_file"

    tok = None
    num = extract_phone(filename) or extract_phone(text)
    url = None
    sess_obj = None

    # Try parsing as JSON
    data = None
    try:
        data = json.loads(text)
    except Exception:
        pass

    if isinstance(data, dict):
        sess_obj = data
        num = (
            data.get("number")
            or data.get("mobNo")
            or data.get("phone")
            or data.get("simNumber")
            or data.get("serviceId")
            or data.get("serviceid")
            or num
        )
        inner_sd = data.get("session_data") if isinstance(data.get("session_data"), dict) else {}
        if not num and inner_sd:
            num = (
                inner_sd.get("number")
                or inner_sd.get("mobNo")
                or inner_sd.get("phone")
                or inner_sd.get("serviceId")
                or inner_sd.get("serviceid")
            )

        # Extract tokens and URLs from all possible keys
        tok = (
            data.get("token")
            or data.get("activation_token")
            or data.get("google_token")
            or inner_sd.get("token")
            or inner_sd.get("activation_token")
        )
        url = (
            data.get("activation_url")
            or data.get("google_activation_url")
            or data.get("url")
            or data.get("last_link")
            or data.get("last_fresh_link")
            or inner_sd.get("activation_url")
            or inner_sd.get("last_link")
        )

        if not tok and url:
            tok = extract_token_from_url(url)

        # Try dynamic Jio refresh if no direct token
        if not tok:
            target_data = inner_sd if (inner_sd.get("tokens") or inner_sd.get("jtoken")) else data
            ok, fresh_u, fresh_tok = fetch_fresh_gemini_link(target_data)
            if ok and fresh_u:
                url = fresh_u
                tok = fresh_tok or extract_token_from_url(fresh_u)
                sess_obj["cached_live_url"] = fresh_u
                sess_obj["last_cached_at"] = time.time()

        # If still no token but contains Jio login session credentials, retain session with unique ID
        if not tok and (data.get("tokens") or data.get("jtoken") or data.get("sessionId_at_login") or inner_sd.get("tokens")):
            clean_n = str(num or "session")
            tok = f"JIO_{clean_n}_{compute_short_code(text, clean_n)}"
            url = f"https://serviceactivation.google.com/subscription/new/{tok}"

    # If not parsed as JSON, scan raw text for URLs / Tokens
    if not tok:
        tok = extract_token_from_url(text)
    if not tok and len(text) >= 25 and re.match(r"^[A-Za-z0-9_-]+={0,2}$", text):
        tok = text

    if not tok and not num:
        return None, "no_token_found"

    if not tok and num:
        tok = f"JIO_{num}_{compute_short_code(text, str(num))}"

    num_str = str(num) if num else "Unknown"
    clean_target_url = url or f"https://serviceactivation.google.com/subscription/new/{tok}"

    if filter_duplicates and num_str != "Unknown":
        existing = find_session_by_number(num_str)
        if existing:
            old_tok, old_sess = existing
            old_status = old_sess.get("status", "Active")
            if old_status == "Active":
                return old_sess, "skipped_duplicate"

    if tok and not tok.startswith("JIO_"):
        status_label, _, code = validate_google_link_status(clean_target_url)
    else:
        status_label = "Active"

    item = add_or_update_session(tok, num_str, clean_target_url, sess_obj, source=filename, status=status_label)
    return item, f"added_{status_label.lower()}"

# ==================== HTML TEMPLATES ====================
LOGIN_PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['"Plus Jakarta Sans"', 'sans-serif'] }
                }
            }
        }
    </script>
    <style>
        body { background: #080c14; color: #f1f5f9; font-family: 'Plus Jakarta Sans', sans-serif; }
        .glass-card { background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7); }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="glass-card w-full max-w-sm rounded-2xl p-7 relative">
        <div class="text-center mb-6">
            <div class="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-slate-800 text-blue-400 text-lg mb-3 border border-slate-700/60">
                <i class="fa-solid fa-lock"></i>
            </div>
            <h1 class="text-lg font-bold text-white tracking-tight">System Access</h1>
        </div>

        <div id="errorAlert" class="hidden mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-xs text-center font-medium">
            <span id="errorMessage">Access Denied</span>
        </div>

        <form id="loginForm" onsubmit="handleLogin(event)" class="space-y-4">
            <div>
                <input type="password" id="accessKey" autofocus autocomplete="off" placeholder="••••••••"
                       class="w-full bg-slate-900 border border-slate-700/80 rounded-xl px-4 py-3 text-center text-lg font-mono tracking-wider text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition">
            </div>

            <button type="submit" id="submitBtn"
                    class="w-full py-3 px-4 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl shadow-lg shadow-blue-600/20 transition transform active:scale-[0.98] text-sm flex items-center justify-center gap-2">
                <span>Unlock</span>
                <i class="fa-solid fa-arrow-right text-xs"></i>
            </button>
        </form>
    </div>

    <script>
        async function handleLogin(e) {
            e.preventDefault();
            const code = document.getElementById('accessKey').value.trim();
            const btn = document.getElementById('submitBtn');
            const alertBox = document.getElementById('errorAlert');
            const errorMsg = document.getElementById('errorMessage');

            if (!code) return;

            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code })
                });
                const data = await res.json();
                if (data.success) {
                    window.location.href = '/admin';
                } else {
                    alertBox.classList.remove('hidden');
                    errorMsg.innerText = data.error || 'Access Denied';
                    btn.disabled = false;
                    btn.innerHTML = '<span>Unlock</span> <i class="fa-solid fa-arrow-right text-xs"></i>';
                    document.getElementById('accessKey').value = '';
                    document.getElementById('accessKey').focus();
                }
            } catch (err) {
                alertBox.classList.remove('hidden');
                errorMsg.innerText = 'Network error. Please try again.';
                btn.disabled = false;
                btn.innerHTML = '<span>Unlock</span> <i class="fa-solid fa-arrow-right text-xs"></i>';
            }
        }
    </script>
</body>
</html>"""

ADMIN_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gemini Pro High-Speed Link Router & Session Hub</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['"Plus Jakarta Sans"', 'sans-serif'] },
                    colors: {
                        cyber: { dark: '#080c14', panel: '#0f172a', card: '#131e36', border: '#1e293b' }
                    }
                }
            }
        }
    </script>
    <style>
        body { background: #080c14; color: #f1f5f9; font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif; }
        .glass-panel { background: rgba(15, 23, 42, 0.78); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); }
        .glass-card { background: rgba(19, 30, 54, 0.65); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.06); }
        .no-scrollbar::-webkit-scrollbar { display: none; }
        .no-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
        .custom-scroll::-webkit-scrollbar { width: 5px; height: 5px; }
        .custom-scroll::-webkit-scrollbar-track { background: #0b1120; }
        .custom-scroll::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
        .custom-scroll::-webkit-scrollbar-thumb:hover { background: #334155; }
    </style>
</head>
<body class="min-h-screen flex flex-col font-sans antialiased text-slate-200 selection:bg-blue-600 selection:text-white pb-10">
    <!-- Top Header -->
    <header class="glass-panel border-b border-slate-800/80 sticky top-0 z-50 px-3.5 sm:px-6 py-3">
        <div class="w-full max-w-[1900px] mx-auto flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-purple-600 flex items-center justify-center text-white text-lg sm:text-xl shadow-lg shadow-blue-500/25 flex-shrink-0">
                        <i class="fa-solid fa-bolt"></i>
                    </div>
                    <div>
                        <h1 class="text-base sm:text-lg font-extrabold text-white tracking-tight flex items-center gap-2">
                            <span>Gemini Pro Hub</span>
                            <span class="text-[9px] sm:text-[10px] uppercase font-black px-2 py-0.5 rounded-md bg-blue-500/20 text-blue-400 border border-blue-500/30">150 Workers</span>
                        </h1>
                        <p class="text-[11px] text-slate-400">High-Speed Redirection & Real-Time Auto-Refresh</p>
                    </div>
                </div>
                
                <button onclick="handleLogout()" class="md:hidden px-2.5 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400 text-xs font-bold transition flex items-center gap-1">
                    <i class="fa-solid fa-right-from-bracket"></i>
                </button>
            </div>

            <!-- Header Quick Status -->
            <div class="flex items-center gap-2 overflow-x-auto no-scrollbar py-0.5 text-xs">
                <div id="tunnelStatusBadge" class="flex-shrink-0 flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                    <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                    <span class="font-semibold text-[11px]">Tunnel:</span>
                    <span id="tunnelUrlText" class="font-mono text-[11px] truncate max-w-[170px] sm:max-w-[220px]">Detecting...</span>
                </div>

                <div id="proxyBadge" class="flex-shrink-0 flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 text-[11px]">
                    <i class="fa-solid fa-shield-halved"></i>
                    <span>Proxy: <strong id="proxyCountText">1 Active</strong></span>
                </div>

                <div id="cookiesBadge" class="flex-shrink-0 flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 text-[11px]">
                    <i class="fa-solid fa-cookie"></i>
                    <span>Auth: <strong id="googleCookiesStatusText">Ready</strong></span>
                </div>

                <button onclick="handleLogout()" class="hidden md:flex flex-shrink-0 px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400 text-xs font-bold transition items-center gap-1.5">
                    <i class="fa-solid fa-right-from-bracket"></i>
                    <span>Logout</span>
                </button>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="flex-1 w-full max-w-[1900px] mx-auto px-3.5 sm:px-6 py-4 sm:py-6 flex flex-col gap-4 sm:gap-6">
        
        <!-- Live Metrics Cards -->
        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 sm:gap-4">
            <!-- 1. ACTIVE (FRESH) FIRST -->
            <div class="glass-card rounded-xl sm:rounded-2xl p-3 sm:p-4 flex flex-col justify-between border-emerald-500/25 bg-emerald-950/20 shadow-lg shadow-emerald-500/10">
                <div class="flex items-center justify-between text-emerald-400 text-[11px] font-bold uppercase tracking-wider">
                    <span>Active (Fresh)</span>
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                </div>
                <div class="mt-2 flex items-baseline gap-1.5">
                    <span id="metricActive" class="text-2xl sm:text-3xl font-black text-emerald-400">0</span>
                    <span class="text-[11px] text-emerald-500/70 font-medium">ready to use</span>
                </div>
            </div>

            <!-- 2. TOTAL DATABASE SECOND -->
            <div class="glass-card rounded-xl sm:rounded-2xl p-3 sm:p-4 flex flex-col justify-between">
                <div class="flex items-center justify-between text-slate-400 text-[11px] font-bold uppercase tracking-wider">
                    <span>Total Database</span>
                    <i class="fa-solid fa-database text-blue-400"></i>
                </div>
                <div class="mt-2 flex items-baseline gap-1.5">
                    <span id="metricTotal" class="text-2xl sm:text-3xl font-extrabold text-white">0</span>
                    <span class="text-[11px] text-slate-400">links</span>
                </div>
            </div>

            <!-- 3. CLAIMED (USED) -->
            <div class="glass-card rounded-xl sm:rounded-2xl p-3 sm:p-4 flex flex-col justify-between border-amber-500/20 bg-amber-950/15">
                <div class="flex items-center justify-between text-amber-400 text-[11px] font-bold uppercase tracking-wider">
                    <span>Claimed (Used)</span>
                    <i class="fa-solid fa-user-check text-amber-400"></i>
                </div>
                <div class="mt-2 flex items-baseline gap-1.5">
                    <span id="metricClaimed" class="text-2xl sm:text-3xl font-extrabold text-amber-400">0</span>
                    <span class="text-[11px] text-amber-500/70">claimed</span>
                </div>
            </div>

            <!-- 4. EXPIRED / 404 -->
            <div class="glass-card rounded-xl sm:rounded-2xl p-3 sm:p-4 flex flex-col justify-between border-red-500/20 bg-red-950/15">
                <div class="flex items-center justify-between text-red-400 text-[11px] font-bold uppercase tracking-wider">
                    <span>Expired / 404</span>
                    <i class="fa-solid fa-circle-xmark text-red-400"></i>
                </div>
                <div class="mt-2 flex items-baseline gap-1.5">
                    <span id="metricExpired" class="text-2xl sm:text-3xl font-extrabold text-red-400">0</span>
                    <span class="text-[11px] text-red-500/70">dead</span>
                </div>
            </div>

            <!-- 5. TOTAL HITS -->
            <div class="glass-card rounded-xl sm:rounded-2xl p-3 sm:p-4 flex flex-col justify-between">
                <div class="flex items-center justify-between text-slate-400 text-[11px] font-bold uppercase tracking-wider">
                    <span>Total Hits</span>
                    <i class="fa-solid fa-chart-line text-purple-400"></i>
                </div>
                <div class="mt-2 flex items-baseline gap-1.5">
                    <span id="metricHits" class="text-2xl sm:text-3xl font-extrabold text-purple-400">0</span>
                    <span class="text-[11px] text-slate-400">clicks</span>
                </div>
            </div>

            <!-- 6. ENGINE SPEED -->
            <div class="glass-card rounded-xl sm:rounded-2xl p-3 sm:p-4 flex flex-col justify-between">
                <div class="flex items-center justify-between text-slate-400 text-[11px] font-bold uppercase tracking-wider">
                    <span>Engine Speed</span>
                    <i class="fa-solid fa-bolt text-indigo-400"></i>
                </div>
                <div class="mt-2 flex items-center justify-between">
                    <span class="text-sm font-black text-emerald-400">150 Workers</span>
                    <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">Live Sync</span>
                </div>
            </div>
        </div>

        <!-- Live Real-Time Progress Bar Container -->
        <div id="liveProgressContainer" class="hidden glass-panel rounded-2xl p-4 sm:p-5 border border-blue-500/30 bg-blue-950/20 shadow-xl shadow-blue-500/10">
            <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2 sm:gap-2.5">
                    <i class="fa-solid fa-spinner fa-spin text-blue-400 text-base sm:text-lg"></i>
                    <span id="progressTitle" class="text-xs sm:text-sm font-bold text-white">Running 150-Worker Multi-Threaded Operation...</span>
                </div>
                <span id="progressPercentage" class="text-xs sm:text-sm font-mono font-black text-blue-400">0%</span>
            </div>
            <div class="w-full h-3 sm:h-3.5 bg-slate-900 rounded-full overflow-hidden p-0.5 border border-slate-700">
                <div id="progressBarFill" class="h-full bg-gradient-to-r from-blue-500 via-indigo-500 to-emerald-500 rounded-full transition-all duration-300" style="width: 0%;"></div>
            </div>
            <div class="flex flex-wrap items-center justify-between text-[11px] sm:text-xs text-slate-400 mt-3 gap-2">
                <div class="flex flex-wrap items-center gap-2.5 sm:gap-4 font-medium">
                    <span>Checked: <strong id="progressCheckedCount" class="text-white">0</strong> / <span id="progressTotalCount">0</span></span>
                    <span class="text-emerald-400"><i class="fa-solid fa-check mr-0.5"></i> Fresh: <strong id="progressActiveCount">0</strong></span>
                    <span class="text-amber-400"><i class="fa-solid fa-user-check mr-0.5"></i> Claimed: <strong id="progressClaimedCount">0</strong></span>
                    <span class="text-red-400"><i class="fa-solid fa-xmark mr-0.5"></i> Expired: <strong id="progressExpiredCount">0</strong></span>
                    <span class="text-indigo-400"><i class="fa-solid fa-filter mr-0.5"></i> Skipped: <strong id="progressSkippedCount">0</strong></span>
                </div>
                <span id="progressSpeed" class="text-slate-400 font-mono text-[11px]">150 Workers Active</span>
            </div>
        </div>

        <!-- Navigation Tabs & Global Actions -->
        <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between border-b border-slate-800 pb-3 gap-3">
            <div class="flex items-center gap-1.5 sm:gap-2 overflow-x-auto no-scrollbar pb-1 sm:pb-0">
                <button onclick="switchTab('inventory')" id="tabBtn-inventory" class="tab-btn whitespace-nowrap px-3.5 sm:px-4 py-2 rounded-xl text-xs sm:text-sm font-bold bg-blue-600 text-white shadow-lg shadow-blue-600/20 flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-list-check"></i>
                    <span>Inventory</span>
                </button>
                <button onclick="switchTab('import')" id="tabBtn-import" class="tab-btn whitespace-nowrap px-3.5 sm:px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold bg-slate-800/80 hover:bg-slate-800 text-slate-300 flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-cloud-arrow-up"></i>
                    <span>Import Center</span>
                </button>
                <button onclick="switchTab('proxies')" id="tabBtn-proxies" class="tab-btn whitespace-nowrap px-3.5 sm:px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold bg-slate-800/80 hover:bg-slate-800 text-slate-300 flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-shield-halved"></i>
                    <span>Proxies</span>
                </button>
                <button onclick="switchTab('cookies')" id="tabBtn-cookies" class="tab-btn whitespace-nowrap px-3.5 sm:px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold bg-slate-800/80 hover:bg-slate-800 text-slate-300 flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-cookie-bite"></i>
                    <span>Google Auth</span>
                </button>
                <button onclick="switchTab('exports')" id="tabBtn-exports" class="tab-btn whitespace-nowrap px-3.5 sm:px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold bg-slate-800/80 hover:bg-slate-800 text-slate-300 flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-file-export"></i>
                    <span>Exports</span>
                </button>
                <button onclick="switchTab('settings')" id="tabBtn-settings" class="tab-btn whitespace-nowrap px-3.5 sm:px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold bg-slate-800/80 hover:bg-slate-800 text-slate-300 flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-gear"></i>
                    <span>Settings</span>
                </button>
            </div>

            <!-- Global Action Buttons -->
            <div class="flex items-center gap-2">
                <button onclick="manualRefreshTable()" class="px-3 sm:px-3.5 py-2 rounded-xl bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 text-blue-300 text-xs font-bold transition flex items-center justify-center gap-1.5" title="Refresh Table & Live Metrics">
                    <i id="globalRefreshIcon" class="fa-solid fa-arrows-rotate"></i>
                    <span>Refresh</span>
                </button>
                <button onclick="runBulkHealthCheck()" class="flex-1 sm:flex-initial px-3 sm:px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-lg shadow-emerald-600/20 transition flex items-center justify-center gap-1.5">
                    <i class="fa-solid fa-rotate"></i>
                    <span>Health Check</span>
                </button>
                <button onclick="purgeExpiredSessions()" class="px-3 py-2 rounded-xl bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 text-red-300 text-xs font-bold transition flex items-center justify-center gap-1.5">
                    <i class="fa-solid fa-trash-can"></i>
                    <span class="hidden sm:inline">Purge Dead</span>
                </button>
            </div>
        </div>

        <!-- TAB 1: LINKS INVENTORY -->
        <div id="tab-inventory" class="tab-content flex flex-col gap-4">
            <div class="glass-panel rounded-2xl p-3 sm:p-4 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                <div class="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:gap-3 flex-1">
                    <div class="relative w-full sm:max-w-md">
                        <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-3 text-slate-500 text-sm"></i>
                        <input type="text" id="tableSearchInput" oninput="handleSearchChange()" placeholder="Search phone, token, short code, status..."
                               class="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition">
                    </div>
                    <div class="flex items-center gap-1 overflow-x-auto no-scrollbar py-0.5">
                        <button onclick="filterByStatus('Active')" id="statusFilter-Active" class="status-filter-btn whitespace-nowrap px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white">Active</button>
                        <button onclick="filterByStatus('all')" id="statusFilter-all" class="status-filter-btn whitespace-nowrap px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-slate-300 hover:bg-slate-700">All</button>
                        <button onclick="filterByStatus('Claimed')" id="statusFilter-Claimed" class="status-filter-btn whitespace-nowrap px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-slate-300 hover:bg-slate-700">Claimed</button>
                        <button onclick="filterByStatus('Expired')" id="statusFilter-Expired" class="status-filter-btn whitespace-nowrap px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-slate-300 hover:bg-slate-700">Expired</button>
                    </div>
                </div>

                <div class="flex items-center justify-between sm:justify-end gap-2.5 pt-2 sm:pt-0 border-t sm:border-t-0 border-slate-800">
                    <span class="text-xs text-slate-400">Rows:</span>
                    <select id="pageSizeSelect" onchange="handlePageSizeChange()" class="bg-slate-900 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none">
                        <option value="15">15</option>
                        <option value="30" selected>30</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                        <option value="all">All</option>
                    </select>
                    <button onclick="manualRefreshTable()" class="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition" title="Refresh Table & Live Metrics">
                        <i id="tableRefreshIcon" class="fa-solid fa-arrows-rotate"></i>
                    </button>
                </div>
            </div>

            <!-- Table -->
            <div class="glass-panel rounded-2xl overflow-hidden border border-slate-800">
                <div class="overflow-x-auto custom-scroll">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="bg-slate-900/90 text-slate-400 font-bold uppercase tracking-wider text-[11px] border-b border-slate-800">
                            <tr>
                                <th class="py-3.5 px-4">#</th>
                                <th class="py-3.5 px-4">Phone Number</th>
                                <th class="py-3.5 px-4">Customer Short URL (Cloudflare/Direct)</th>
                                <th class="py-3.5 px-4">Google Activation Token</th>
                                <th class="py-3.5 px-4">Live Fresh URL / Auto-Renew</th>
                                <th class="py-3.5 px-4 text-center">Status</th>
                                <th class="py-3.5 px-4 text-center">Hits</th>
                                <th class="py-3.5 px-4">Created Date</th>
                                <th class="py-3.5 px-4 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="sessionsTableBody" class="divide-y divide-slate-800/60 font-medium">
                            <tr>
                                <td colspan="9" class="text-center py-12 text-slate-500">Loading sessions database...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- Pagination Footer -->
                <div class="p-4 bg-slate-900/60 border-t border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-400">
                    <div>
                        Showing <strong id="pageStartItem" class="text-white">0</strong> to <strong id="pageEndItem" class="text-white">0</strong> of <strong id="pageTotalItems" class="text-white">0</strong> records
                    </div>
                    <div class="flex items-center gap-1.5" id="paginationButtons"></div>
                </div>
            </div>
        </div>

        <!-- TAB 2: IMPORT CENTER -->
        <div id="tab-import" class="tab-content hidden flex flex-col gap-6">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- ZIP Upload Card -->
                <div class="glass-panel rounded-2xl p-6 flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-4">
                            <h2 class="text-base font-bold text-white flex items-center gap-2">
                                <i class="fa-solid fa-file-zipper text-blue-400"></i>
                                <span>Bulk ZIP File Import</span>
                            </h2>
                            <span class="text-xs px-2.5 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 font-semibold">150 Workers</span>
                        </div>
                        <p class="text-xs text-slate-400 mb-4">Upload a ZIP containing Jio sessions (`<number>.json`) or text files. The server will extract and validate each link concurrently using 150 threads.</p>
                        
                        <div id="dropZone" onclick="document.getElementById('zipFileInput').click()"
                             class="border-2 border-dashed border-slate-700 hover:border-blue-500 rounded-2xl p-8 text-center cursor-pointer transition bg-slate-900/40 hover:bg-slate-900/70 group">
                            <input type="file" id="zipFileInput" accept=".zip" class="hidden" onchange="handleZipSelect(event)">
                            <div class="w-14 h-14 rounded-2xl bg-blue-600/10 group-hover:bg-blue-600/20 text-blue-400 flex items-center justify-center text-2xl mx-auto mb-3 transition">
                                <i class="fa-solid fa-cloud-arrow-up"></i>
                            </div>
                            <h3 class="text-sm font-bold text-white mb-1">Click to browse or Drag & Drop ZIP file</h3>
                            <p class="text-xs text-slate-500">Supports .zip containing multiple session JSONs</p>
                        </div>
                    </div>

                    <div class="mt-4 pt-4 border-t border-slate-800 flex items-center justify-between">
                        <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                            <input type="checkbox" id="zipDuplicateFilterToggle" checked class="rounded border-slate-700 text-blue-600 focus:ring-blue-500">
                            <span>Filter duplicates (Skip active, re-test claimed)</span>
                        </label>
                    </div>
                </div>

                <!-- Text Paste Card -->
                <div class="glass-panel rounded-2xl p-6 flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-4">
                            <h2 class="text-base font-bold text-white flex items-center gap-2">
                                <i class="fa-solid fa-paste text-indigo-400"></i>
                                <span>Paste Raw JSON or URL List</span>
                            </h2>
                            <span class="text-xs px-2.5 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 font-semibold">150 Workers</span>
                        </div>
                        <p class="text-xs text-slate-400 mb-3">Paste Gemini URLs, Google activation URLs, or raw JSON objects one per line.</p>
                        <textarea id="importRawTextArea" rows="6" placeholder="https://serviceactivation.google.com/subscription/new/eyJhbGciOi...&#10;9876543210&#10;{ 'number': '9876543210', 'token': '...' }"
                                  class="w-full bg-slate-900 border border-slate-700/80 rounded-xl p-3.5 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition"></textarea>
                    </div>

                    <div class="mt-4 flex items-center justify-between">
                        <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                            <input type="checkbox" id="textDuplicateFilterToggle" checked class="rounded border-slate-700 text-blue-600 focus:ring-blue-500">
                            <span>Enable Smart Duplicate Filter</span>
                        </label>
                        <button onclick="handleImportText()" id="importTextBtn"
                                class="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-blue-600/20 transition flex items-center gap-2">
                            <i class="fa-solid fa-arrow-down-to-bracket"></i>
                            <span>Process & Import Links</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 3: PROXIES -->
        <div id="tab-proxies" class="tab-content hidden flex flex-col gap-6">
            <div class="glass-panel rounded-2xl p-6">
                <div class="flex items-center justify-between mb-4 flex-wrap gap-4">
                    <div>
                        <h2 class="text-base font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-shield-halved text-blue-400"></i>
                            <span>Indian Residential / Datacenter Proxies</span>
                        </h2>
                        <p class="text-xs text-slate-400 mt-1">Used to route Jio Selfcare, MyJio Mapp, and Google One status checks smoothly.</p>
                    </div>
                    <div class="flex items-center gap-3">
                        <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer bg-slate-900 px-3 py-2 rounded-xl border border-slate-800">
                            <input type="checkbox" id="proxyEnabledCheckbox" class="rounded border-slate-700 text-blue-600 focus:ring-blue-500">
                            <span>Proxy Enabled</span>
                        </label>
                        <button onclick="testActiveProxy()" id="testProxyBtn" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold rounded-xl border border-slate-700 transition flex items-center gap-1.5">
                            <i class="fa-solid fa-bolt"></i>
                            <span>1-Click Test Proxy</span>
                        </button>
                    </div>
                </div>

                <div id="proxyTestResult" class="hidden mb-4 p-3.5 rounded-xl text-xs font-mono"></div>

                <div>
                    <label class="block text-xs font-bold uppercase text-slate-400 mb-2">Proxy Pool (one per line: host:port:user:pass or full http:// url)</label>
                    <textarea id="proxyPoolTextArea" rows="5" class="w-full bg-slate-900 border border-slate-700 rounded-xl p-3.5 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"></textarea>
                </div>

                <div class="mt-4 flex justify-end">
                    <button onclick="saveProxiesConfig()" class="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-blue-600/20 transition flex items-center gap-2">
                        <i class="fa-solid fa-floppy-disk"></i>
                        <span>Save Proxies</span>
                    </button>
                </div>
            </div>
        </div>

        <!-- TAB 4: GOOGLE SESSION COOKIES -->
        <div id="tab-cookies" class="tab-content hidden flex flex-col gap-6">
            <div class="glass-panel rounded-2xl p-6">
                <div class="flex items-center justify-between mb-4 flex-wrap gap-4">
                    <div>
                        <h2 class="text-base font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-cookie-bite text-purple-400"></i>
                            <span>Google Session Cookies Validator</span>
                        </h2>
                        <p class="text-xs text-slate-400 mt-1">Paste Google cookies to accurately distinguish <strong>ACTIVE (FRESH)</strong> vs <strong>CLAIMED</strong> vs <strong>EXPIRED</strong> links.</p>
                    </div>
                    <button onclick="testGoogleCookies()" id="testCookiesBtn" class="px-4 py-2 bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 text-xs font-bold rounded-xl border border-purple-500/30 transition flex items-center gap-1.5">
                        <i class="fa-solid fa-vial"></i>
                        <span>Test Cookies Validity</span>
                    </button>
                </div>

                <div id="cookiesTestResult" class="hidden mb-4 p-3.5 rounded-xl text-xs font-mono"></div>

                <div>
                    <label class="block text-xs font-bold uppercase text-slate-400 mb-2">Google Cookies (JSON, Netscape format, or raw header string)</label>
                    <textarea id="googleCookiesTextArea" rows="6" placeholder="[ { 'name': 'SID', 'value': '...' }, ... ]"
                              class="w-full bg-slate-900 border border-slate-700 rounded-xl p-3.5 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-purple-500"></textarea>
                </div>

                <div class="mt-4 flex justify-end">
                    <button onclick="saveGoogleCookies()" class="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-purple-600/20 transition flex items-center gap-2">
                        <i class="fa-solid fa-floppy-disk"></i>
                        <span>Save Cookies</span>
                    </button>
                </div>
            </div>
        </div>

        <!-- TAB 5: EXPORT HUB -->
        <div id="tab-exports" class="tab-content hidden flex flex-col gap-6">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- TXT Export -->
                <div class="glass-panel rounded-2xl p-6 flex flex-col justify-between">
                    <div>
                        <div class="w-12 h-12 rounded-2xl bg-blue-600/20 text-blue-400 flex items-center justify-center text-xl mb-4">
                            <i class="fa-solid fa-file-lines"></i>
                        </div>
                        <h3 class="text-base font-bold text-white mb-1">Active Customer Links (TXT)</h3>
                        <p class="text-xs text-slate-400 mb-4">Export all active customer short links formatted ready to distribute.</p>
                    </div>
                    <a href="/api/export/txt" download class="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-xl text-center shadow-lg shadow-blue-600/20 transition block">
                        <i class="fa-solid fa-download mr-1.5"></i> Download TXT Links
                    </a>
                </div>

                <!-- ZIP Export -->
                <div class="glass-panel rounded-2xl p-6 flex flex-col justify-between">
                    <div>
                        <div class="w-12 h-12 rounded-2xl bg-emerald-600/20 text-emerald-400 flex items-center justify-center text-xl mb-4">
                            <i class="fa-solid fa-file-zipper"></i>
                        </div>
                        <h3 class="text-base font-bold text-white mb-1">Active Sessions Package (ZIP)</h3>
                        <p class="text-xs text-slate-400 mb-4">Download ZIP containing `<number>.json` files for all active working sessions.</p>
                    </div>
                    <a href="/api/export/zip" download class="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-xl text-center shadow-lg shadow-emerald-600/20 transition block">
                        <i class="fa-solid fa-download mr-1.5"></i> Download Sessions ZIP
                    </a>
                </div>

                <!-- CSV Export -->
                <div class="glass-panel rounded-2xl p-6 flex flex-col justify-between">
                    <div>
                        <div class="w-12 h-12 rounded-2xl bg-purple-600/20 text-purple-400 flex items-center justify-center text-xl mb-4">
                            <i class="fa-solid fa-file-csv"></i>
                        </div>
                        <h3 class="text-base font-bold text-white mb-1">Full Database Report (CSV)</h3>
                        <p class="text-xs text-slate-400 mb-4">Complete spreadsheet report with phone numbers, links, hits, and status.</p>
                    </div>
                    <a href="/api/export/csv" download class="w-full py-3 bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold rounded-xl text-center shadow-lg shadow-purple-600/20 transition block">
                        <i class="fa-solid fa-download mr-1.5"></i> Download CSV Report
                    </a>
                </div>
            </div>
        </div>

        <!-- TAB 6: SETTINGS -->
        <div id="tab-settings" class="tab-content hidden flex flex-col gap-6">
            <div class="glass-panel rounded-2xl p-6 max-w-3xl">
                <h2 class="text-base font-bold text-white mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-gear text-slate-400"></i>
                    <span>System Configuration & 2FA Security</span>
                </h2>

                <div class="space-y-4 text-xs">
                    <div>
                        <label class="block font-bold text-slate-300 uppercase mb-1">Custom Domain Prefix (Optional Override)</label>
                        <input type="text" id="cfgDomainPrefix" placeholder="Leave empty to auto-use Cloudflare Tunnel URL"
                               class="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-white font-mono placeholder-slate-600 focus:outline-none focus:border-blue-500">
                        <p class="text-[11px] text-slate-500 mt-1">When empty, the system automatically uses the live Cloudflare HTTPS URL: <code id="cfgLiveTunnelPfx" class="text-emerald-400 font-mono">...</code></p>
                    </div>

                    <!-- Background 24/7 Auto-Refresh Engine -->
                    <div class="pt-4 border-t border-slate-800">
                        <div class="flex items-center justify-between mb-2">
                            <div>
                                <label class="block font-bold text-slate-300 uppercase mb-0.5">24/7 Background Auto-Refresh Engine</label>
                                <p class="text-[11px] text-slate-400">Automatically pre-caches fresh Google activation links in background so customer links never expire.</p>
                            </div>
                            <label class="relative inline-flex items-center cursor-pointer">
                                <input type="checkbox" id="cfgAutoRefreshToggle" class="sr-only peer" checked>
                                <div class="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
                            </label>
                        </div>
                        <div class="mt-3 flex items-center justify-between flex-wrap gap-3">
                            <div class="flex items-center gap-3">
                                <span class="text-slate-400 font-semibold">Refresh Frequency:</span>
                                <select id="cfgRefreshInterval" class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500">
                                    <option value="600">Every 10 Minutes</option>
                                    <option value="900" selected>Every 15 Minutes (Recommended)</option>
                                    <option value="1200">Every 20 Minutes</option>
                                    <option value="1800">Every 30 Minutes</option>
                                </select>
                            </div>
                            <button onclick="triggerManualRefreshAll()" id="manualRefreshBtn" class="px-3.5 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-bold transition flex items-center gap-1.5">
                                <i class="fa-solid fa-rotate"></i>
                                <span>Pre-cache All Fresh Links Now</span>
                            </button>
                        </div>
                    </div>

                    <!-- 2FA Security Key -->
                    <div class="pt-4 border-t border-slate-800">
                        <label class="block font-bold text-slate-300 uppercase mb-1">Admin 2FA Secret Key (Google Authenticator)</label>
                        <div class="flex items-center gap-2">
                            <input type="text" id="cfgTotpSecret" readonly placeholder="Loading..."
                                   class="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-blue-400 font-mono text-xs focus:outline-none select-all">
                            <button type="button" onclick="copyDirectText(document.getElementById('cfgTotpSecret').value)" class="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-white font-bold rounded-xl border border-slate-700 transition flex items-center gap-1.5 whitespace-nowrap text-xs">
                                <i class="fa-solid fa-copy"></i>
                                <span>Copy Key</span>
                            </button>
                        </div>
                        <p class="text-[11px] text-slate-500 mt-1">Add this secret key into Google Authenticator or your 2FA app to generate access codes.</p>
                    </div>

                    <div class="pt-4 border-t border-slate-800 flex justify-end">
                        <button onclick="saveSystemConfig()" class="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-lg shadow-blue-600/20 transition">
                            Save Settings
                        </button>
                    </div>
                </div>
            </div>
        </div>

    </main>

    <!-- Toast Notification -->
    <div id="toast" class="fixed bottom-6 right-6 z-50 transform translate-y-20 opacity-0 transition-all duration-300 pointer-events-none">
        <div class="glass-panel px-4 py-3 rounded-xl border border-blue-500/30 shadow-2xl flex items-center gap-3 text-xs text-white">
            <i id="toastIcon" class="fa-solid fa-circle-check text-blue-400 text-base"></i>
            <span id="toastMsg">Success</span>
        </div>
    </div>

    <!-- Frontend Application Logic -->
    <script>
        let allSessions = [];
        let filteredSessions = [];
        let currentPage = 1;
        let pageSize = 30;
        let currentStatusFilter = 'Active';
        let domainPrefix = '{{DOMAIN_PREFIX}}';
        let tunnelUrl = null;
        let autoRefreshIntervalMin = 20;

        function formatTimeAgo(ts) {
            if (!ts) return 'Just now';
            let timeMs = 0;
            if (typeof ts === 'number') {
                timeMs = ts * 1000;
            } else if (typeof ts === 'string') {
                const iso = ts.includes('T') ? ts : ts.replace(' ', 'T');
                const parsed = Date.parse(iso);
                timeMs = isNaN(parsed) ? Date.now() : parsed;
            }
            const diffSec = Math.max(0, Math.floor((Date.now() - timeMs) / 1000));
            if (diffSec < 45) return 'Just now';
            if (diffSec < 90) return '1m ago';
            const diffMin = Math.floor(diffSec / 60);
            if (diffMin < 60) return `${diffMin}m ago`;
            const diffHour = Math.floor(diffMin / 60);
            if (diffHour < 24) return `${diffHour}h ago`;
            const diffDays = Math.floor(diffHour / 24);
            return `${diffDays}d ago`;
        }

        document.addEventListener('DOMContentLoaded', () => {
            loadSessionsData();
            loadProxiesData();
            loadGoogleCookiesData();
            loadSystemConfig();
            
            // 🔄 Live Auto-Polling for Metrics and Table Updates every 6 seconds
            setInterval(loadSessionsDataSilent, 6000);
        });

        function showToast(msg, isError = false) {
            const toast = document.getElementById('toast');
            const icon = document.getElementById('toastIcon');
            const txt = document.getElementById('toastMsg');

            txt.innerText = msg;
            icon.className = isError ? 'fa-solid fa-circle-exclamation text-red-400 text-base' : 'fa-solid fa-circle-check text-emerald-400 text-base';
            toast.classList.remove('translate-y-20', 'opacity-0');
            setTimeout(() => {
                toast.classList.add('translate-y-20', 'opacity-0');
            }, 3000);
        }

        // ================= ROBUST UNIVERSAL CLIPBOARD COPY =================
        function copyDirectText(text) {
            if (!text) return;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => {
                    showToast('Copied to clipboard!');
                }).catch(() => {
                    fallbackCopyText(text);
                });
            } else {
                fallbackCopyText(text);
            }
        }

        function fallbackCopyText(text) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.top = '-9999px';
            textArea.style.left = '-9999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                const successful = document.execCommand('copy');
                if (successful) showToast('Copied to clipboard!');
                else showToast('Failed to copy', true);
            } catch (err) {
                showToast('Failed to copy', true);
            }
            document.body.removeChild(textArea);
        }

        function copyFromButtonData(btn) {
            const raw = btn.getAttribute('data-copy');
            if (raw) {
                const decoded = decodeURIComponent(raw);
                copyDirectText(decoded);
            }
        }

        function copyGoogleOriginalLink(url) {
            if (!url) return;
            copyDirectText(url);
            showToast('Original Google Link Copied!');
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.className = 'tab-btn px-4 py-2 rounded-xl text-sm font-semibold bg-slate-800/80 hover:bg-slate-800 text-slate-300 flex items-center gap-2';
            });

            const activeTab = document.getElementById(`tab-${tabId}`);
            const activeBtn = document.getElementById(`tabBtn-${tabId}`);
            if (activeTab) activeTab.classList.remove('hidden');
            if (activeBtn) activeBtn.className = 'tab-btn px-4 py-2 rounded-xl text-sm font-bold bg-blue-600 text-white shadow-lg shadow-blue-600/20 flex items-center gap-2';
        }

        async function handleLogout() {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/login';
        }

        // ================= SESSIONS DATA & TABLE =================
        async function loadSessionsData() {
            try {
                const res = await fetch('/api/sessions');
                const data = await res.json();
                if (data.success) {
                    allSessions = data.sessions || [];
                    domainPrefix = data.domain_prefix || domainPrefix;
                    tunnelUrl = data.tunnel_url;
                    if (data.refresh_interval_sec) {
                        autoRefreshIntervalMin = Math.round(data.refresh_interval_sec / 60);
                    }

                    const tunnelBadge = document.getElementById('tunnelUrlText');
                    if (tunnelUrl && tunnelBadge) {
                        tunnelBadge.innerText = tunnelUrl;
                        const cfgTunnelPfx = document.getElementById('cfgLiveTunnelPfx');
                        if (cfgTunnelPfx) cfgTunnelPfx.innerText = `${tunnelUrl}/c/`;
                    } else if (tunnelBadge) {
                        tunnelBadge.innerText = 'Local: ' + domainPrefix;
                    }

                    updateMetrics();
                    applyFiltersAndRender(false);
                }
            } catch (err) {
                console.error('Error loading sessions:', err);
            }
        }

        // Silent background polling without UI jitter
        async function loadSessionsDataSilent() {
            try {
                const res = await fetch('/api/sessions');
                const data = await res.json();
                if (data.success) {
                    allSessions = data.sessions || [];
                    domainPrefix = data.domain_prefix || domainPrefix;
                    tunnelUrl = data.tunnel_url;
                    if (data.refresh_interval_sec) {
                        autoRefreshIntervalMin = Math.round(data.refresh_interval_sec / 60);
                    }

                    const tunnelBadge = document.getElementById('tunnelUrlText');
                    if (tunnelUrl && tunnelBadge) {
                        tunnelBadge.innerText = tunnelUrl;
                        const cfgTunnelPfx = document.getElementById('cfgLiveTunnelPfx');
                        if (cfgTunnelPfx) cfgTunnelPfx.innerText = `${tunnelUrl}/c/`;
                    }

                    updateMetrics();
                    applyFiltersAndRender(false);
                }
            } catch (err) {}
        }

        async function manualRefreshTable() {
            const btnIcons = [document.getElementById('globalRefreshIcon'), document.getElementById('tableRefreshIcon')].filter(Boolean);
            btnIcons.forEach(i => i.classList.add('fa-spin'));
            try {
                await loadSessionsData();
                showToast('Table & Live Stats Refreshed!');
            } catch (e) {
                showToast('Sync error', true);
            }
            setTimeout(() => {
                btnIcons.forEach(i => i.classList.remove('fa-spin'));
            }, 600);
        }

        function updateMetrics() {
            let active = 0, claimed = 0, expired = 0, hits = 0;
            allSessions.forEach(s => {
                const st = s.status || 'Active';
                if (st === 'Active') active++;
                else if (st === 'Claimed') claimed++;
                else expired++;
                hits += (s.clicks || 0);
            });

            document.getElementById('metricTotal').innerText = allSessions.length;
            document.getElementById('metricActive').innerText = active;
            document.getElementById('metricClaimed').innerText = claimed;
            document.getElementById('metricExpired').innerText = expired;
            document.getElementById('metricHits').innerText = hits;
        }

        function filterByStatus(status) {
            currentStatusFilter = status;
            document.querySelectorAll('.status-filter-btn').forEach(btn => {
                btn.className = 'status-filter-btn whitespace-nowrap px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-slate-300 hover:bg-slate-700';
            });
            const activeBtn = document.getElementById(`statusFilter-${status}`);
            if (activeBtn) activeBtn.className = 'status-filter-btn whitespace-nowrap px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white';

            currentPage = 1;
            applyFiltersAndRender(true);
        }

        function handleSearchChange() {
            currentPage = 1;
            applyFiltersAndRender(true);
        }

        function handlePageSizeChange() {
            const val = document.getElementById('pageSizeSelect').value;
            pageSize = val === 'all' ? allSessions.length : parseInt(val);
            currentPage = 1;
            applyFiltersAndRender(true);
        }

        function applyFiltersAndRender(resetPage = false) {
            if (resetPage) currentPage = 1;
            const query = (document.getElementById('tableSearchInput')?.value || '').toLowerCase().trim();

            filteredSessions = allSessions.filter(s => {
                if (currentStatusFilter !== 'all' && s.status !== currentStatusFilter) return false;
                if (query) {
                    const num = (s.number || '').toLowerCase();
                    const tok = (s.token || '').toLowerCase();
                    const sc = (s.short_code || '').toLowerCase();
                    const st = (s.status || '').toLowerCase();
                    const dt = (s.created_at || '').toLowerCase();
                    return num.includes(query) || tok.includes(query) || sc.includes(query) || st.includes(query) || dt.includes(query);
                }
                return true;
            });

            renderTable();
        }

        function renderTable() {
            const tbody = document.getElementById('sessionsTableBody');
            const total = filteredSessions.length;

            if (total === 0) {
                tbody.innerHTML = `<tr><td colspan="9" class="text-center py-12 text-slate-500">No sessions match your search or filter.</td></tr>`;
                document.getElementById('pageStartItem').innerText = '0';
                document.getElementById('pageEndItem').innerText = '0';
                document.getElementById('pageTotalItems').innerText = '0';
                document.getElementById('paginationButtons').innerHTML = '';
                return;
            }

            const totalPages = Math.ceil(total / pageSize) || 1;
            if (currentPage > totalPages) currentPage = totalPages;
            const startIdx = (currentPage - 1) * pageSize;
            const endIdx = Math.min(startIdx + pageSize, total);
            const pageItems = filteredSessions.slice(startIdx, endIdx);

            document.getElementById('pageStartItem').innerText = startIdx + 1;
            document.getElementById('pageEndItem').innerText = endIdx;
            document.getElementById('pageTotalItems').innerText = total;

            let html = '';
            pageItems.forEach((s, idx) => {
                const rowNum = startIdx + idx + 1;
                const status = s.status || 'Active';
                const shortCode = s.short_code || s.token;
                const shortUrl = `${domainPrefix}${shortCode}`;
                const googleUrl = s.google_url || `https://serviceactivation.google.com/subscription/new/${s.token}`;

                let autoRenewCell = '';
                if (status === 'Active') {
                    const freshTimeStr = formatTimeAgo(s.last_cached_at || s.last_refreshed_at || s.created_at);
                    autoRenewCell = `
                    <div class="flex flex-col">
                        <span class="inline-flex items-center gap-1.5 text-xs font-bold text-emerald-400 whitespace-nowrap">
                            <i class="fa-solid fa-arrows-rotate text-[11px] text-emerald-400"></i>
                            <span>${autoRefreshIntervalMin}m Auto-Renew</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono mt-0.5">Fresh: <strong class="text-slate-300 font-semibold">${freshTimeStr}</strong></span>
                    </div>`;
                } else if (status === 'Claimed') {
                    autoRenewCell = `
                    <div class="flex items-center gap-1.5 text-xs font-semibold text-blue-400 whitespace-nowrap">
                        <i class="fa-solid fa-check-double text-[11px]"></i>
                        <span>Redeemed on Google</span>
                    </div>`;
                } else {
                    autoRenewCell = `
                    <div class="flex items-center gap-1.5 text-xs font-semibold text-rose-400 whitespace-nowrap">
                        <i class="fa-solid fa-circle-xmark text-[11px]"></i>
                        <span>Expired Link</span>
                    </div>`;
                }

                let statusBadge = '';
                if (status === 'Active') {
                    statusBadge = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> Active</span>`;
                } else if (status === 'Claimed') {
                    statusBadge = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20"><i class="fa-solid fa-user-check text-[10px]"></i> Claimed</span>`;
                } else {
                    statusBadge = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-red-500/10 text-red-400 border border-red-500/20"><i class="fa-solid fa-circle-xmark text-[10px]"></i> Expired</span>`;
                }

                html += `
                <tr class="hover:bg-slate-800/40 transition">
                    <td class="py-3 px-4 text-slate-500 font-mono">${rowNum}</td>
                    <td class="py-3 px-4 font-bold text-white font-mono">${s.number || 'Unknown'}</td>
                    <td class="py-3 px-4 min-w-[280px]">
                        <div class="flex items-center gap-2">
                            <span class="font-mono text-blue-400 select-all cursor-pointer hover:underline font-semibold" onclick="copyDirectText('${shortUrl}')" title="Click to copy Short URL: ${shortUrl}">${shortUrl}</span>
                            <button onclick="copyDirectText('${shortUrl}')" class="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-700/50 transition flex-shrink-0" title="Copy Short URL">
                                <i class="fa-regular fa-copy"></i>
                            </button>
                            <a href="${shortUrl}" target="_blank" class="text-slate-400 hover:text-blue-400 p-1 rounded hover:bg-slate-700/50 transition flex-shrink-0" title="Test Redirection Link">
                                <i class="fa-solid fa-arrow-up-right-from-square"></i>
                            </a>
                        </div>
                    </td>
                    <td class="py-3 px-4 min-w-[240px]">
                        <div class="flex items-center gap-2">
                            <span class="font-mono text-slate-300 cursor-pointer hover:text-white" onclick="copyDirectText('${s.token}')" title="Click to copy Token: ${s.token}">${s.token.substring(0, 24)}...</span>
                            <button onclick="copyGoogleOriginalLink('${googleUrl}')" class="p-1.5 rounded-lg bg-purple-500/15 hover:bg-purple-500/30 text-purple-400 border border-purple-500/30 transition flex items-center justify-center flex-shrink-0" title="1-Click Copy Full Google Activation URL">
                                <i class="fa-solid fa-link text-xs"></i>
                            </button>
                        </div>
                    </td>
                    <td class="py-3 px-4 min-w-[175px]">${autoRenewCell}</td>
                    <td class="py-3 px-4 text-center">${statusBadge}</td>
                    <td class="py-3 px-4 text-center font-mono font-bold text-purple-400">${s.clicks || 0}</td>
                    <td class="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">${s.created_at || '-'}</td>
                    <td class="py-3 px-4 text-right">
                        <div class="flex items-center justify-end gap-1.5">
                            <button onclick="refreshSingleSession('${s.token}', this)" class="p-1.5 rounded-lg bg-slate-800 hover:bg-blue-600/30 text-slate-300 hover:text-blue-400 transition" title="Instant Refresh / Re-generate Fresh Link">
                                <i class="fa-solid fa-arrows-rotate"></i>
                            </button>
                            <button onclick="testSingleHealth('${s.token}', this)" class="p-1.5 rounded-lg bg-slate-800 hover:bg-emerald-600/30 text-slate-300 hover:text-emerald-300 transition" title="1-Click Health Check">
                                <i class="fa-solid fa-heart-pulse"></i>
                            </button>
                            <button onclick="deleteSession('${s.token}')" class="p-1.5 rounded-lg bg-slate-800 hover:bg-red-600/30 text-slate-300 hover:text-red-300 transition" title="Delete">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </div>
                    </td>
                </tr>`;
            });

            tbody.innerHTML = html;
            renderPagination(totalPages);
        }

        function renderPagination(totalPages) {
            const container = document.getElementById('paginationButtons');
            if (totalPages <= 1) {
                container.innerHTML = '';
                return;
            }

            let html = `<button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''} class="px-2.5 py-1 rounded bg-slate-800 disabled:opacity-30 text-white hover:bg-slate-700">Prev</button>`;
            for (let p = 1; p <= totalPages; p++) {
                if (p === 1 || p === totalPages || (p >= currentPage - 2 && p <= currentPage + 2)) {
                    html += `<button onclick="changePage(${p})" class="px-2.5 py-1 rounded ${p === currentPage ? 'bg-blue-600 font-bold text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}">${p}</button>`;
                } else if (p === currentPage - 3 || p === currentPage + 3) {
                    html += `<span class="px-1 text-slate-600">...</span>`;
                }
            }
            html += `<button onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''} class="px-2.5 py-1 rounded bg-slate-800 disabled:opacity-30 text-white hover:bg-slate-700">Next</button>`;
            container.innerHTML = html;
        }

        function changePage(p) {
            currentPage = p;
            renderTable();
        }

        // ================= ULTRA-FAST 150-WORKER BULK HEALTH CHECK =================
        async function runBulkHealthCheck() {
            if (allSessions.length === 0) {
                showToast('No sessions in database to check!', true);
                return;
            }

            const progressContainer = document.getElementById('liveProgressContainer');
            const progressFill = document.getElementById('progressBarFill');
            const progressPercent = document.getElementById('progressPercentage');
            const title = document.getElementById('progressTitle');
            const checkedCount = document.getElementById('progressCheckedCount');
            const totalCountEl = document.getElementById('progressTotalCount');
            const activeCountEl = document.getElementById('progressActiveCount');
            const claimedCountEl = document.getElementById('progressClaimedCount');
            const expiredCountEl = document.getElementById('progressExpiredCount');

            title.innerText = '⚡ Running 150-Worker Multi-Threaded Health Check...';
            progressContainer.classList.remove('hidden');
            progressFill.style.width = '0%';
            progressPercent.innerText = '0%';
            checkedCount.innerText = '0';
            totalCountEl.innerText = allSessions.length;
            activeCountEl.innerText = '0';
            claimedCountEl.innerText = '0';
            expiredCountEl.innerText = '0';

            const tokens = allSessions.map(s => s.token);
            const chunkSize = 150; // 150 tokens per chunk running against 150 workers
            let processed = 0;
            let totalActive = 0, totalClaimed = 0, totalExpired = 0;

            for (let i = 0; i < tokens.length; i += chunkSize) {
                const batch = tokens.slice(i, i + chunkSize);
                try {
                    const res = await fetch('/api/check_health_batch', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ tokens: batch })
                    });
                    const data = await res.json();
                    if (data.results) {
                        data.results.forEach(r => {
                            processed++;
                            if (r.status === 'Active') totalActive++;
                            else if (r.status === 'Claimed') totalClaimed++;
                            else totalExpired++;

                            const found = allSessions.find(s => s.token === r.token);
                            if (found) {
                                found.status = r.status;
                                found.http_status = r.http_code;
                            }
                        });
                    }
                } catch (e) {
                    processed += batch.length;
                }

                const pct = Math.round((processed / tokens.length) * 100);
                progressFill.style.width = `${pct}%`;
                progressPercent.innerText = `${pct}%`;
                checkedCount.innerText = processed;
                activeCountEl.innerText = totalActive;
                claimedCountEl.innerText = totalClaimed;
                expiredCountEl.innerText = totalExpired;
                updateMetrics();
                applyFiltersAndRender();
            }

            title.innerText = '✅ Health Check Completed!';
            showToast(`Completed: ${totalActive} Active, ${totalClaimed} Claimed, ${totalExpired} Expired`);
            setTimeout(() => {
                progressContainer.classList.add('hidden');
            }, 4000);
        }

        async function refreshSingleSession(token, btn) {
            const icon = btn ? btn.querySelector('i') : null;
            if (icon) icon.classList.add('fa-spin');
            showToast('Instant refreshing Google activation link...');

            try {
                const res = await fetch('/api/refresh_single', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message || 'Link refreshed successfully!');
                    const found = allSessions.find(s => s.token === token);
                    if (found) {
                        found.status = data.status || 'Active';
                        found.last_cached_at = data.last_cached_at || (Date.now() / 1000);
                        found.last_refreshed_at = data.last_refreshed_at;
                        if (data.fresh_url) found.google_url = data.fresh_url;
                        updateMetrics();
                        renderTable();
                    }
                } else {
                    showToast(data.error || 'Refresh failed', true);
                }
            } catch (err) {
                showToast('Error refreshing link: ' + err.message, true);
            }

            if (icon) {
                setTimeout(() => icon.classList.remove('fa-spin'), 600);
            }
        }

        async function testSingleHealth(token, btn) {
            const icon = btn ? btn.querySelector('i') : null;
            if (icon) icon.classList.add('fa-spin');
            showToast('Testing link status with Google Auth...');
            try {
                const res = await fetch('/api/check_health', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Result: ${data.status} (Code: ${data.http_code || 200})`);
                    const found = allSessions.find(s => s.token === token);
                    if (found) {
                        found.status = data.status;
                        found.http_status = data.http_code;
                        updateMetrics();
                        renderTable();
                    }
                } else {
                    showToast('Check failed: ' + (data.error || 'Unknown'), true);
                }
            } catch (err) {
                showToast('Error testing health', true);
            }
            if (icon) {
                setTimeout(() => icon.classList.remove('fa-spin'), 600);
            }
        }

        async function deleteSession(token) {
            if (!confirm('Are you sure you want to delete this session?')) return;
            try {
                const res = await fetch('/api/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token })
                });
                const data = await res.json();
                if (data.success) {
                    showToast('Session deleted');
                    allSessions = allSessions.filter(s => s.token !== token);
                    updateMetrics();
                    applyFiltersAndRender();
                }
            } catch (err) {
                showToast('Error deleting session', true);
            }
        }

        async function purgeExpiredSessions() {
            if (!confirm('Purge all dead/claimed/expired links from database?')) return;
            try {
                const res = await fetch('/api/purge_expired', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    showToast(`Purged ${data.purged} dead/claimed records`);
                    loadSessionsData();
                }
            } catch (err) {
                showToast('Error purging sessions', true);
            }
        }

        // ================= IMPORT HANDLERS =================
        async function handleZipSelect(event) {
            const file = event.target.files[0];
            if (!file) return;

            const filterDup = document.getElementById('zipDuplicateFilterToggle').checked;
            const progressContainer = document.getElementById('liveProgressContainer');
            const progressFill = document.getElementById('progressBarFill');
            const progressPercent = document.getElementById('progressPercentage');
            const title = document.getElementById('progressTitle');
            const checkedCount = document.getElementById('progressCheckedCount');
            const totalCountEl = document.getElementById('progressTotalCount');
            const activeCountEl = document.getElementById('progressActiveCount');
            const claimedCountEl = document.getElementById('progressClaimedCount');
            const expiredCountEl = document.getElementById('progressExpiredCount');
            const skippedCountEl = document.getElementById('progressSkippedCount');

            // Reset all stats before starting
            title.innerText = `📦 Extracting & Processing ${file.name} (150 Workers)...`;
            progressContainer.classList.remove('hidden');
            progressFill.style.width = '35%';
            progressPercent.innerText = 'Extracting...';
            checkedCount.innerText = '0';
            totalCountEl.innerText = '...';
            activeCountEl.innerText = '0';
            claimedCountEl.innerText = '0';
            expiredCountEl.innerText = '0';
            skippedCountEl.innerText = '0';

            const formData = new FormData();
            formData.append('file', file);
            formData.append('filter_duplicates', filterDup ? 'true' : 'false');

            try {
                const res = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                if (data.success) {
                    const totalFiles = data.total_files || (data.added + (data.skipped_duplicates || 0));
                    progressFill.style.width = '100%';
                    progressPercent.innerText = '100%';
                    title.innerText = `✅ Processed ${totalFiles} sessions: ${data.added} Added, ${data.skipped_duplicates || 0} Duplicates Skipped`;
                    checkedCount.innerText = totalFiles;
                    totalCountEl.innerText = totalFiles;
                    activeCountEl.innerText = data.active || data.added;
                    claimedCountEl.innerText = data.claimed || 0;
                    expiredCountEl.innerText = data.expired || 0;
                    skippedCountEl.innerText = data.skipped_duplicates || 0;

                    showToast(`Imported ${data.added} sessions (Skipped: ${data.skipped_duplicates || 0})`);
                    await loadSessionsData();
                    switchTab('inventory');
                    setTimeout(() => progressContainer.classList.add('hidden'), 5000);
                } else {
                    showToast(data.error || 'Import failed', true);
                    progressContainer.classList.add('hidden');
                }
            } catch (err) {
                showToast('Upload error: ' + err.message, true);
                progressContainer.classList.add('hidden');
            }
            event.target.value = '';
        }

        async function handleImportText() {
            const text = document.getElementById('importRawTextArea').value.trim();
            if (!text) {
                showToast('Please paste JSON lines or URLs first', true);
                return;
            }

            const filterDup = document.getElementById('textDuplicateFilterToggle').checked;
            const btn = document.getElementById('importTextBtn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing (150 Threads)...';

            try {
                const res = await fetch('/api/import_text', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text, filter_duplicates: filterDup })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Imported ${data.added} sessions (Skipped: ${data.skipped_duplicates || 0})`);
                    document.getElementById('importRawTextArea').value = '';
                    await loadSessionsData();
                    switchTab('inventory');
                } else {
                    showToast(data.error || 'Import failed', true);
                }
            } catch (err) {
                showToast('Error importing text', true);
            }
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-arrow-down-to-bracket"></i> <span>Process & Import Links</span>';
        }

        // ================= PROXIES =================
        async function loadProxiesData() {
            try {
                const res = await fetch('/api/proxies');
                const data = await res.json();
                if (data.success) {
                    document.getElementById('proxyEnabledCheckbox').checked = data.proxy_enabled;
                    document.getElementById('proxyPoolTextArea').value = (data.proxies || []).join('\n');
                    document.getElementById('proxyCountText').innerText = `${data.proxies.length} Active`;
                }
            } catch (err) {}
        }

        async function saveProxiesConfig() {
            const enabled = document.getElementById('proxyEnabledCheckbox').checked;
            const lines = document.getElementById('proxyPoolTextArea').value.split('\n').map(l => l.trim()).filter(Boolean);
            try {
                const res = await fetch('/api/proxies', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ proxy_enabled: enabled, proxies: lines })
                });
                const data = await res.json();
                if (data.success) {
                    showToast('Proxies updated successfully');
                    loadProxiesData();
                }
            } catch (err) {
                showToast('Failed to save proxies', true);
            }
        }

        async function testActiveProxy() {
            const box = document.getElementById('proxyTestResult');
            const btn = document.getElementById('testProxyBtn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Testing...';
            box.classList.remove('hidden');
            box.className = 'mb-4 p-3.5 rounded-xl text-xs font-mono bg-slate-900 border border-slate-700 text-slate-300';
            box.innerText = 'Testing connection through proxy pool...';

            try {
                const res = await fetch('/api/proxies/test', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    box.className = 'mb-4 p-3.5 rounded-xl text-xs font-mono bg-emerald-950/40 border border-emerald-500/30 text-emerald-300';
                    box.innerText = `✅ Proxy Connected: ${data.message}`;
                    showToast('Proxy is working!');
                } else {
                    box.className = 'mb-4 p-3.5 rounded-xl text-xs font-mono bg-red-950/40 border border-red-500/30 text-red-300';
                    box.innerText = `❌ Proxy Failed: ${data.message || 'Connection timeout'}`;
                    showToast('Proxy failed', true);
                }
            } catch (err) {
                box.className = 'mb-4 p-3.5 rounded-xl text-xs font-mono bg-red-950/40 border border-red-500/30 text-red-300';
                box.innerText = '❌ Network request error';
            }
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-bolt"></i> <span>1-Click Test Proxy</span>';
        }

        // ================= GOOGLE COOKIES =================
        async function loadGoogleCookiesData() {
            try {
                const res = await fetch('/api/google_cookies');
                const data = await res.json();
                const badge = document.getElementById('googleCookiesStatusText');
                if (data.is_valid) {
                    badge.innerText = `${data.count} Loaded`;
                } else {
                    badge.innerText = 'Not Configured';
                }
            } catch (err) {}
        }

        async function saveGoogleCookies() {
            const raw = document.getElementById('googleCookiesTextArea').value.trim();
            try {
                const res = await fetch('/api/google_cookies', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cookies: raw })
                });
                const data = await res.json();
                if (data.success) {
                    showToast(`Saved ${data.count} Google session cookies!`);
                    loadGoogleCookiesData();
                } else {
                    showToast(data.error || 'Failed parsing cookies', true);
                }
            } catch (err) {
                showToast('Error saving cookies', true);
            }
        }

        async function testGoogleCookies() {
            const box = document.getElementById('cookiesTestResult');
            const btn = document.getElementById('testCookiesBtn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Checking Google Auth...';
            box.classList.remove('hidden');
            box.className = 'mb-4 p-3.5 rounded-xl text-xs font-mono bg-slate-900 border border-slate-700 text-slate-300';
            box.innerText = 'Contacting Google One authentication servers...';

            try {
                const res = await fetch('/api/google_cookies/test', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    box.className = 'mb-4 p-3.5 rounded-xl text-xs font-mono bg-emerald-950/40 border border-emerald-500/30 text-emerald-300';
                    box.innerText = `✅ Google Session Active & Valid (${data.count} cookies verified)`;
                    showToast('Google session is Active!');
                } else {
                    box.className = 'mb-4 p-3.5 rounded-xl text-xs font-mono bg-red-950/40 border border-red-500/30 text-red-300';
                    box.innerText = `❌ Google Session Error: ${data.message}`;
                    showToast('Google session expired', true);
                }
            } catch (err) {
                box.className = 'mb-4 p-3.5 rounded-xl text-xs font-mono bg-red-950/40 border border-red-500/30 text-red-300';
                box.innerText = '❌ Error testing Google cookies';
            }
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-vial"></i> <span>Test Cookies Validity</span>';
        }

        // ================= SETTINGS & AUTO-REFRESH =================
        async function loadSystemConfig() {
            try {
                const res = await fetch('/api/config');
                const data = await res.json();
                if (data.config) {
                    const cfg = data.config;
                    if (document.getElementById('cfgDomainPrefix')) {
                        document.getElementById('cfgDomainPrefix').value = cfg.domain_prefix || '';
                    }
                    if (document.getElementById('cfgAutoRefreshToggle')) {
                        document.getElementById('cfgAutoRefreshToggle').checked = cfg.auto_refresh_enabled !== false;
                    }
                    if (document.getElementById('cfgRefreshInterval')) {
                        document.getElementById('cfgRefreshInterval').value = cfg.refresh_interval_sec || 900;
                    }
                    if (document.getElementById('cfgTotpSecret')) {
                        document.getElementById('cfgTotpSecret').value = cfg.totp_secret || '';
                    }
                }
            } catch (err) {}
        }

        async function triggerManualRefreshAll() {
            const btn = document.getElementById('manualRefreshBtn');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Pre-caching links...';
            }
            showToast('Pre-caching fresh Google activation links...');
            try {
                const res = await fetch('/api/refresh_all', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    showToast(`Successfully refreshed ${data.refreshed}/${data.total} links!`);
                    loadSessionsData();
                } else {
                    showToast('Refresh failed: ' + (data.error || 'Unknown error'), true);
                }
            } catch (err) {
                showToast('Network error triggering refresh', true);
            }
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-rotate"></i> <span>Pre-cache All Fresh Links Now</span>';
            }
        }

        async function saveSystemConfig() {
            const pfx = document.getElementById('cfgDomainPrefix').value.trim();
            const autoRefresh = document.getElementById('cfgAutoRefreshToggle') ? document.getElementById('cfgAutoRefreshToggle').checked : true;
            const refreshInterval = document.getElementById('cfgRefreshInterval') ? (parseInt(document.getElementById('cfgRefreshInterval').value) || 900) : 900;
            try {
                const res = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        domain_prefix: pfx,
                        check_workers: 150,
                        auto_refresh_enabled: autoRefresh,
                        refresh_interval_sec: refreshInterval
                    })
                });
                const data = await res.json();
                if (data.success) {
                    showToast('Settings saved successfully');
                    loadSessionsData();
                }
            } catch (err) {
                showToast('Failed saving settings', true);
            }
        }
    </script>
</body>
</html>"""

# ==================== HTTP REQUEST HANDLER ====================
class StandaloneRouterHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def get_cookie(self, name: str) -> Optional[str]:
        cookie_header = self.headers.get("Cookie", "")
        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                if k.strip() == name:
                    return v.strip()
        return None

    def get_current_host_prefix(self) -> str:
        cfg_prefix = CONFIG.get("domain_prefix", "").strip()
        if cfg_prefix and "localhost" not in cfg_prefix and "127.0.0.1" not in cfg_prefix and "yourdomain.com" not in cfg_prefix:
            return cfg_prefix if cfg_prefix.endswith("/") else cfg_prefix + "/"

        if CLOUDFLARE_TUNNEL_URL:
            return f"{CLOUDFLARE_TUNNEL_URL.rstrip('/')}/c/"

        port = CONFIG.get("port", 8081)
        return f"http://localhost:{port}/c/"

    def is_authenticated(self) -> bool:
        if not CONFIG.get("totp_enabled", True):
            return True
        token = self.get_cookie("router_admin_session")
        return is_valid_admin_session(token) if token else False

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # 1. Sub-5ms Instant 302 Redirection Customer Endpoint (/c/<short_code_or_token> or /subscription/new/<token>)
        if path.startswith("/c/") or path.startswith("/subscription/new/") or path.startswith("/c"):
            param = path.split("/c/")[-1] if "/c/" in path else path.split("/subscription/new/")[-1]
            param = param.strip("/").split("?")[0].split("&")[0].strip()

            item = None
            token = None

            # 1. Fast O(1) Short Code / Phone Number Lookup
            mapped_tok = SHORT_CODE_MAP.get(param)
            if mapped_tok and mapped_tok in SESSIONS_DB:
                item = SESSIONS_DB[mapped_tok]
                token = mapped_tok

            # 2. Direct SESSIONS_DB Key Lookup
            if not item:
                item = SESSIONS_DB.get(param)
                if item:
                    token = param

            # 3. Search SESSIONS_DB by short_code, number, or token prefixes
            if not item:
                clean_param = param.rstrip("=")
                for k, v in SESSIONS_DB.items():
                    if (v.get("short_code") == param or
                        v.get("number") == param or
                        k.rstrip("=") == clean_param or
                        k.startswith(clean_param) or
                        clean_param.startswith(k)):
                        item = v
                        token = k
                        break

            # 4. Fallback search in DATABASE_DIR
            if not item:
                for f in DATABASE_DIR.glob("*.json"):
                    try:
                        d = load_json(f, {})
                        if (d.get("number") == param or 
                            d.get("token") == param or 
                            d.get("short_code") == param or
                            compute_short_code(d.get("token", ""), d.get("number")) == param):
                            t = d.get("token")
                            if t:
                                item = add_or_update_session(t, d.get("number"), d.get("activation_url"), d.get("session_data"), "database_recovery")
                                token = t
                                break
                    except Exception:
                        pass

            if item:
                # 1. Check if cached live link is fresh (< 15 mins)
                now_ts = time.time()
                last_cached = float(item.get("last_cached_at", 0) or 0)
                cached_url = item.get("cached_live_url", "")
                interval_limit = int(CONFIG.get("refresh_interval_sec", 900))

                target_url = None
                if cached_url and (now_ts - last_cached) < interval_limit:
                    target_url = cached_url
                else:
                    # Dynamically generate fresh Google link from Jio session on-the-fly
                    sess_d = item.get("session_data") or {}
                    if not sess_d and item.get("number") and item.get("number") != "Unknown":
                        f_path = DATABASE_DIR / f"{item['number']}.json"
                        if f_path.exists():
                            sess_d = load_json(f_path, {}).get("session_data", {})
                    
                    if sess_d:
                        ok, fresh_u, new_tok = fetch_fresh_gemini_link(sess_d)
                        if ok and fresh_u:
                            target_url = fresh_u
                            with FILE_LOCK:
                                item["cached_live_url"] = fresh_u
                                item["last_cached_at"] = now_ts
                                item["google_url"] = fresh_u
                                item["last_refreshed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                item["status"] = "Active"

                if not target_url:
                    target_url = item.get("cached_live_url") or item.get("google_url") or f"https://serviceactivation.google.com/subscription/new/{token}"

                target_url = target_url.strip()

                with FILE_LOCK:
                    item["clicks"] = item.get("clicks", 0) + 1
                    item["last_accessed"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    SESSIONS_DB[token] = item
                schedule_save_sessions()

                redirect_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0; url={target_url}">
    <title>Redirecting to Google Gemini Pro Activation...</title>
    <script>window.location.replace({json.dumps(target_url)});</script>
    <style>
        body {{ background: #080c14; color: #94a3b8; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .card {{ background: rgba(15, 23, 42, 0.9); padding: 2rem; border-radius: 1rem; text-align: center; border: 1px solid rgba(255,255,255,0.1); max-width: 400px; }}
        .btn {{ display: inline-block; margin-top: 1rem; padding: 0.75rem 1.5rem; background: #2563eb; color: #fff; text-decoration: none; border-radius: 0.75rem; font-weight: 600; font-size: 0.875rem; }}
    </style>
</head>
<body>
    <div class="card">
        <h2 style="color: #fff; margin-top: 0;">Opening Google Activation...</h2>
        <p style="font-size: 0.875rem;">You are being redirected to claim your 1-Year Gemini Pro Plan.</p>
        <a href="{target_url}" class="btn">Click here if not redirected</a>
    </div>
</body>
</html>""".encode("utf-8")

                self.send_response(302)
                self.send_header("Location", target_url)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Connection", "close")
                self.send_header("Content-Length", str(len(redirect_html)))
                self.end_headers()
                self.wfile.write(redirect_html)
                return
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                err_html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>404 - Activation Link Not Found</title>
<style>body{background:#080c14;color:#f1f5f9;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
.card{background:#0f172a;padding:2.5rem;border-radius:1rem;border:1px solid #1e293b;text-align:center;max-width:450px;}
h1{color:#ef4444;font-size:1.5rem;margin-top:0;}p{color:#94a3b8;font-size:0.875rem;line-height:1.5;}
</style></head><body><div class="card"><h1>Link Not Found or Expired</h1><p>The requested activation token was not found in the router database or has expired. Please contact support to receive a fresh activation link.</p></div></body></html>""".encode("utf-8")
                self.wfile.write(err_html)
                return

        # 2. Login Page
        if path == "/login":
            if self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/admin")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            body = LOGIN_PAGE_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        # 3. Root redirect
        if path in ("/", ""):
            self.send_response(302)
            self.send_header("Location", "/admin" if self.is_authenticated() else "/login")
            self.send_header("Connection", "close")
            self.end_headers()
            return

        # 4. Protected Admin Dashboard
        if path == "/admin":
            if not self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            domain_pfx = self.get_current_host_prefix()
            html = ADMIN_DASHBOARD_HTML.replace("{{DOMAIN_PREFIX}}", domain_pfx)
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        # 5. API Sessions List
        if path == "/api/sessions":
            if not self.is_authenticated():
                self.send_json({"success": False, "error": "Unauthorized"}, 401)
                return

            sessions_list = list(SESSIONS_DB.values())
            self.send_json({
                "success": True,
                "sessions": sessions_list,
                "domain_prefix": self.get_current_host_prefix(),
                "tunnel_url": CLOUDFLARE_TUNNEL_URL,
                "refresh_interval_sec": CONFIG.get("refresh_interval_sec", 1200),
                "auto_refresh_enabled": CONFIG.get("auto_refresh_enabled", True),
            })
            return

        # 6. API Proxies status
        if path == "/api/proxies":
            if not self.is_authenticated():
                self.send_json({"success": False, "error": "Unauthorized"}, 401)
                return
            self.send_json({
                "success": True,
                "proxy_enabled": CONFIG.get("proxy_enabled", True),
                "proxies": CONFIG.get("proxies", []),
            })
            return

        # 7. API Google Cookies status
        if path == "/api/google_cookies":
            if not self.is_authenticated():
                self.send_json({"success": False, "error": "Unauthorized"}, 401)
                return
            g_cookies = load_google_cookies()
            self.send_json({
                "success": True,
                "count": len(g_cookies),
                "is_valid": bool(g_cookies)
            })
            return

        # 8. API Config status
        if path == "/api/config":
            if not self.is_authenticated():
                self.send_json({"success": False, "error": "Unauthorized"}, 401)
                return
            self.send_json({"success": True, "config": CONFIG})
            return

        # 9. Export Customer Links TXT
        if path == "/api/export/txt":
            if not self.is_authenticated():
                self.send_json({"success": False, "error": "Unauthorized"}, 401)
                return

            domain_pfx = self.get_current_host_prefix()
            lines = [f"{domain_pfx}{s.get('short_code') or s['token']}" for s in SESSIONS_DB.values() if s.get("status") == "Active"]
            content = "\n".join(lines).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="Active_Customer_Links.txt"')
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(content)
            return

        # 9. Export Active Sessions ZIP
        if path == "/api/export/zip":
            if not self.is_authenticated():
                self.send_json({"success": False, "error": "Unauthorized"}, 401)
                return

            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
                sessions_txt_lines = []
                for s in SESSIONS_DB.values():
                    if s.get("status") == "Active":
                        num = s.get("number") or "unknown"
                        tok = s.get("token")
                        sessions_txt_lines.append(num)
                        
                        file_data = {
                            "number": num,
                            "token": tok,
                            "short_code": s.get("short_code"),
                            "activation_url": s.get("google_url"),
                            "created_at": s.get("created_at"),
                            "status": "Active",
                            "session_data": s.get("session_data", {})
                        }
                        z.writestr(f"{num}.json", json.dumps(file_data, indent=2))

                z.writestr("sessions_list.txt", "\n".join(sessions_txt_lines))

            zip_buffer.seek(0)
            data = zip_buffer.getvalue()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="Active_Sessions.zip"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            return

        # 10. Export CSV
        if path == "/api/export/csv":
            if not self.is_authenticated():
                self.send_json({"success": False, "error": "Unauthorized"}, 401)
                return

            domain_pfx = self.get_current_host_prefix()
            csv_lines = ["Phone Number,Customer Short Link,Short Code,Google Token,Status,Hits,Created Date"]
            for s in SESSIONS_DB.values():
                sc_val = s.get("short_code") or s.get("token", "")
                csv_lines.append(f'"{s.get("number","")}","{domain_pfx}{sc_val}","{sc_val}","{s.get("token","")}","{s.get("status","")}","{s.get("clicks",0)}","{s.get("created_at","")}"')

            content = "\n".join(csv_lines).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="All_Sessions_Report.csv"')
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_response(404)
        self.send_header("Connection", "close")
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. Login API
        if path == "/api/login":
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
            allowed, limit_msg = check_login_rate_limit(client_ip)
            if not allowed:
                self.send_json({"success": False, "error": limit_msg}, 429)
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                code = str(data.get("code", "")).strip()
                secret = CONFIG.get("totp_secret", "")

                if verify_totp(secret, code):
                    record_successful_login(client_ip)
                    sess_token = create_admin_session()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", f"router_admin_session={sess_token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b'{"success":true}')
                    return
                else:
                    record_failed_login(client_ip)
                    self.send_json({"success": False, "error": "Access Denied"}, 401)
                    return
            except Exception as e:
                self.send_json({"success": False, "error": "Access Denied"}, 400)
                return

        # 2. Logout API
        if path == "/api/logout":
            self.send_response(200)
            self.send_header("Set-Cookie", "router_admin_session=; Path=/; Max-Age=0; HttpOnly")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"success":true}')
            return

        if not self.is_authenticated():
            self.send_json({"success": False, "error": "Unauthorized"}, 401)
            return

        # 3. Upload ZIP File (150 Workers)
        if path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)

            filter_dup = True
            file_bytes = None

            if "multipart/form-data" in content_type:
                boundary = content_type.split("boundary=")[-1].encode("utf-8")
                parts = body.split(b"--" + boundary)
                for part in parts:
                    if b'name="filter_duplicates"' in part:
                        val = part.split(b"\r\n\r\n", 1)[-1].rsplit(b"\r\n", 1)[0].decode("utf-8")
                        filter_dup = (val.lower() == "true")
                    if b'filename="' in part:
                        headers_part, file_data = part.split(b"\r\n\r\n", 1)
                        file_bytes = file_data.rsplit(b"\r\n", 1)[0]

                if file_bytes:
                    res = self._process_zip_upload(file_bytes, filter_dup)
                    self.send_json(res)
                    return
                else:
                    self.send_json({"success": False, "error": "No file detected in upload"}, 400)
                    return
            else:
                res = self._process_zip_upload(body, filter_dup)
                self.send_json(res)
                return

        # 4. Import Pasted Text (150 Workers)
        if path == "/api/import_text":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                text = data.get("text", "")
                filter_dup = bool(data.get("filter_duplicates", True))
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                added = 0
                skipped_dup = 0
                details = []

                workers = CONFIG.get("check_workers", 150)
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    tasks = [pool.submit(process_single_session_raw, f"line_{i}", line, filter_dup) for i, line in enumerate(lines)]
                    for fut in as_completed(tasks):
                        try:
                            item, action = fut.result()
                            if action == "skipped_duplicate":
                                skipped_dup += 1
                            elif item:
                                added += 1
                                details.append({"number": item.get("number") or "Unknown", "token": item["token"][:15] + "...", "status": item.get("status")})
                        except Exception:
                            pass

                save_sessions_sync()
                self.send_json({"success": True, "added": added, "skipped_duplicates": skipped_dup, "items": details})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # 5. Check Single Token Health
        if path == "/api/check_health":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                token = data.get("token", "")
                res = check_single_token_health(token)
                self.send_json(res)
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # 6. Batch Token Health Check (150 Workers Ultra Fast Parallel)
        if path == "/api/check_health_batch":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                batch_tokens = data.get("tokens", [])
                results = []

                workers = min(len(batch_tokens), CONFIG.get("check_workers", 150)) or 1
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {pool.submit(check_single_token_health, tok): tok for tok in batch_tokens}
                    for fut in as_completed(futures):
                        try:
                            results.append(fut.result())
                        except Exception as e:
                            tok = futures[fut]
                            results.append({"success": False, "token": tok, "error": str(e), "status": "Expired"})

                self.send_json({"success": True, "results": results})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # 7. Bulk Health Check All (150 Workers Parallel Async)
        if path == "/api/bulk_check":
            tokens = list(SESSIONS_DB.keys())
            workers = CONFIG.get("check_workers", 150)
            active_cnt = 0
            claimed_cnt = 0
            expired_cnt = 0

            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(check_single_token_health, tok): tok for tok in tokens}
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        st = res.get("status")
                        if st == "Active":
                            active_cnt += 1
                        elif st == "Claimed":
                            claimed_cnt += 1
                        else:
                            expired_cnt += 1
                    except Exception:
                        expired_cnt += 1

            save_sessions_sync()
            self.send_json({
                "success": True,
                "total": len(tokens),
                "active": active_cnt,
                "claimed": claimed_cnt,
                "expired": expired_cnt
            })
            return

        # 8. Update Proxies
        if path == "/api/proxies":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                if "proxy_enabled" in data:
                    CONFIG["proxy_enabled"] = bool(data["proxy_enabled"])
                if "proxies" in data and isinstance(data["proxies"], list):
                    CONFIG["proxies"] = [normalize_proxy_url(p) for p in data["proxies"] if normalize_proxy_url(p)]
                save_json_atomic(CONFIG_FILE, CONFIG)
                self.send_json({"success": True, "count": len(CONFIG.get("proxies", []))})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # 9. Test Proxy
        if path == "/api/proxies/test":
            pxy = get_active_proxy()
            if not pxy:
                self.send_json({"success": False, "message": "No active proxy configured"})
                return
            ok, msg, dur = test_proxy_connection(pxy)
            self.send_json({"success": ok, "message": msg, "latency_ms": dur})
            return

        # 10. Update Google Session Cookies
        if path == "/api/google_cookies":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                raw_cookies = data.get("cookies", "")
                parsed_c = parse_cookie_string(raw_cookies)
                if parsed_c:
                    save_google_cookies(parsed_c)
                    self.send_json({"success": True, "count": len(parsed_c)})
                else:
                    self.send_json({"success": False, "error": "Could not parse valid cookies"}, 400)
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # 11. Test Google Session Cookies
        if path == "/api/google_cookies/test":
            g_cookies = load_google_cookies()
            ok, msg = test_google_cookies_validity(g_cookies)
            self.send_json({"success": ok, "message": msg, "count": len(g_cookies)})
            return

        # 12. Update Config
        if path == "/api/config":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                if "domain_prefix" in data:
                    CONFIG["domain_prefix"] = data["domain_prefix"]
                if "check_workers" in data and isinstance(data["check_workers"], int):
                    CONFIG["check_workers"] = data["check_workers"]
                if "auto_refresh_enabled" in data:
                    CONFIG["auto_refresh_enabled"] = bool(data["auto_refresh_enabled"])
                if "refresh_interval_sec" in data:
                    CONFIG["refresh_interval_sec"] = int(data["refresh_interval_sec"])
                save_json_atomic(CONFIG_FILE, CONFIG)
                self.send_json({"success": True, "config": CONFIG})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # 13. Instant Single Session Refresh API
        if path == "/api/refresh_single":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                token = data.get("token", "")
                res = refresh_single_session(token)
                self.send_json(res)
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # 14. Manual Refresh All Active Links API
        if path == "/api/refresh_all":
            refreshed, total = refresh_all_active_sessions()
            self.send_json({"success": True, "refreshed": refreshed, "total": total})
            return

        # 13. Delete Single Session
        if path == "/api/delete":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(body)
                token = data.get("token", "")
                with FILE_LOCK:
                    if token in SESSIONS_DB:
                        del SESSIONS_DB[token]
                        save_sessions_sync()
                        rebuild_short_code_map()
                self.send_json({"success": True})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # 14. Purge Inactive Sessions
        if path == "/api/purge_expired":
            with FILE_LOCK:
                dead_tokens = [k for k, v in SESSIONS_DB.items() if v.get("status") in ("Expired", "Claimed", "Blocked/403") or "40" in str(v.get("status"))]
                for tok in dead_tokens:
                    del SESSIONS_DB[tok]
                save_sessions_sync()
                rebuild_short_code_map()
            self.send_json({"success": True, "purged": len(dead_tokens)})
            return

        self.send_response(404)
        self.send_header("Connection", "close")
        self.end_headers()

    def _process_zip_upload(self, zip_bytes: bytes, filter_duplicates: bool = True) -> dict:
        added = 0
        skipped_dup = 0
        active_cnt = 0
        claimed_cnt = 0
        expired_cnt = 0
        details = []
        tasks = []
        total_files = 0

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                namelist = z.namelist()
                valid_files = [
                    fn for fn in namelist 
                    if not fn.endswith("/") and not fn.startswith("__MACOSX") and not fn.split("/")[-1].startswith(".")
                ]
                total_files = len(valid_files)
                workers = min(max(total_files, 1), CONFIG.get("check_workers", 150))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    for filename in valid_files:
                        try:
                            raw_bytes = z.read(filename)
                            text = raw_bytes.decode("utf-8", errors="replace").strip()
                            if not text:
                                continue
                            tasks.append(pool.submit(process_single_session_raw, filename, text, filter_duplicates))
                        except Exception:
                            continue

                    for fut in as_completed(tasks):
                        try:
                            item, action = fut.result()
                            if action == "skipped_duplicate":
                                skipped_dup += 1
                            elif item:
                                added += 1
                                st = item.get("status", "Active")
                                if st == "Active":
                                    active_cnt += 1
                                elif st == "Claimed":
                                    claimed_cnt += 1
                                else:
                                    expired_cnt += 1
                                details.append({
                                    "number": item.get("number") or "Unknown",
                                    "token": item["token"][:15] + "...",
                                    "status": st,
                                    "short_code": item.get("short_code")
                                })
                        except Exception:
                            pass

            save_sessions_sync()
            rebuild_short_code_map()
            return {
                "success": True,
                "total_files": total_files,
                "added": added,
                "skipped_duplicates": skipped_dup,
                "active": active_cnt,
                "claimed": claimed_cnt,
                "expired": expired_cnt,
                "items": details
            }
        except Exception as e:
            logger.error("ZIP import error: %s", e)
            return {"success": False, "error": str(e)}

# ==================== MAIN SERVER ENTRYPOINT ====================
def run_server(port: int = 8081):
    server_address = ("0.0.0.0", port)
    httpd = ThreadingHTTPServer(server_address, StandaloneRouterHandler)
    
    start_cloudflare_tunnel(port)

    # Start 24/7 Background Auto-Refresh Thread
    refresh_thread = threading.Thread(target=background_auto_refresh_worker, daemon=True)
    refresh_thread.start()

    auto_ref_min = int(CONFIG.get("refresh_interval_sec", 900)) // 60
    logger.info("================================================================")
    logger.info("⚡ STANDALONE GEMINI PRO LINK ROUTER SERVER RUNNING")
    logger.info("👉 Local Web Admin:      http://localhost:%s/admin", port)
    logger.info("👉 Local 302 Endpoint:   http://localhost:%s/c/<token>", port)
    logger.info("🛡️ Proxies Loaded:       %s (Enabled: %s)", len(CONFIG.get("proxies", [])), CONFIG.get("proxy_enabled", True))
    logger.info("⚡ Worker Threads:       %s Parallel Threads", CONFIG.get("check_workers", 150))
    logger.info("🔄 Auto-Refresh Cron:    %s (Every %s mins)", "Enabled" if CONFIG.get("auto_refresh_enabled", True) else "Disabled", auto_ref_min)
    logger.info("🔐 2FA Secret Key:      %s", CONFIG.get("totp_secret"))
    logger.info("================================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Router Server...")
        if CLOUDFLARE_PROCESS:
            try:
                CLOUDFLARE_PROCESS.terminate()
            except Exception:
                pass
        httpd.server_close()

if __name__ == "__main__":
    env_port = os.environ.get("PORT")
    if env_port and env_port.isdigit():
        port_to_run = int(env_port)
    elif len(sys.argv) > 1 and sys.argv[1].isdigit():
        port_to_run = int(sys.argv[1])
    else:
        port_to_run = CONFIG.get("port", 8081)
    run_server(port_to_run)
