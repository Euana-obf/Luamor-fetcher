"""
Luarmor Fetcher v3.0
Fetches public loader + shared bootstrap, peels static layers, extracts
_bsdata0 / script tokens / long-string envelopes. Does not execute Lua.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
import socket
import struct
import zlib
from typing import Any
from urllib.parse import urlparse

import requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Luarmor Fetcher v3</title>
<style>
:root{--bg:#0b0e17;--pane:#121626;--pane2:#0f1322;--fg:#e8ecf4;--muted:#8b93a7;--acc:#6c8cff;--ok:#3dd68c;--err:#ff6b7a;--border:#1e2438}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh}
main{max-width:980px;margin:0 auto;padding:28px 18px 60px}
h1{font-size:1.35rem;margin:0 0 6px;font-weight:650;letter-spacing:-.02em}
.sub{color:var(--muted);font-size:.9rem;margin-bottom:22px;line-height:1.45}
.card{background:linear-gradient(180deg,var(--pane),var(--pane2));border:1px solid var(--border);border-radius:14px;padding:18px;margin-bottom:16px;box-shadow:0 8px 24px rgba(0,0,0,.25)}
label{display:block;font-size:.78rem;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em}
input[type=text]{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--border);background:#0a0d16;color:var(--fg);font:inherit;font-size:.95rem}
input:focus{outline:none;border-color:var(--acc)}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;align-items:center}
button{border:0;border-radius:10px;padding:10px 16px;font:inherit;font-size:.9rem;font-weight:600;cursor:pointer;background:var(--acc);color:#fff}
button.secondary{background:#1c2238;color:var(--fg);border:1px solid var(--border)}
button:disabled{opacity:.5;cursor:not-allowed}
.chk{display:flex;align-items:center;gap:8px;font-size:.88rem;color:var(--muted)}
.status{margin-top:12px;font-size:.88rem;color:var(--muted)}.status.ok{color:var(--ok)}.status.err{color:var(--err)}
.meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin:14px 0}
.metric{background:#0a0d16;border:1px solid var(--border);border-radius:10px;padding:10px 12px}
.metric small{display:block;color:var(--muted);font-size:.72rem;margin-bottom:4px}.metric b{font-size:.92rem;word-break:break-all}
textarea{width:100%;min-height:220px;border-radius:10px;border:1px solid var(--border);background:#070a12;color:#c8d0e0;font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:12px;resize:vertical}
.hidden{display:none}
.tabs{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
.tab{padding:7px 12px;border-radius:8px;background:#151a2c;border:1px solid var(--border);color:var(--muted);font-size:.82rem;cursor:pointer}
.tab.on{background:#1e2a4a;color:var(--fg);border-color:#2e3f6a}
.peel{font-size:.82rem;color:var(--muted);white-space:pre-wrap;background:#070a12;border:1px solid var(--border);border-radius:10px;padding:12px;max-height:320px;overflow:auto}
.foot{margin-top:28px;color:var(--muted);font-size:.78rem;text-align:center}
</style>
</head>
<body>
<main>
<h1>Luarmor Fetcher <span style="opacity:.55">v3.0</span></h1>
<p class="sub">공개 loader URL → 서버가 실제로 돌려주는 본문 + 공유 bootstrap 정적 박리. 인증 우회·페이로드 복호화는 정적 추출 범위에서만 처리. Lua 실행 없음.</p>

<section class="card">
<label for="url">Loader URL</label>
<input id="url" type="text" placeholder="https://api.luarmor.net/files/v4/loaders/{ID}.lua" spellcheck="false"/>
<div class="row">
<label class="chk"><input id="boot" type="checkbox" checked/> bootstrap 포함</label>
<button id="fetch">Fetch</button>
<button id="clear" class="secondary">Clear</button>
</div>
<div id="status" class="status">대기 중</div>
</section>

<section id="result" class="card hidden">
<div class="tabs">
<button class="tab on" data-t="loader">Loader</button>
<button class="tab" data-t="peel">Peel</button>
<button class="tab" data-t="boot">Bootstrap</button>
</div>
<div id="meta" class="meta"></div>
<div id="pane-loader">
<textarea id="source" readonly spellcheck="false"></textarea>
<div class="row" style="margin-top:10px">
<button id="dl" class="secondary">Download loader</button>
<button id="copy" class="secondary">Copy</button>
</div>
</div>
<div id="pane-peel" class="hidden"><pre id="peel" class="peel"></pre></div>
<div id="pane-boot" class="hidden">
<textarea id="bootsrc" readonly spellcheck="false" placeholder="bootstrap preview / error"></textarea>
<div class="row" style="margin-top:10px">
<button id="dlboot" class="secondary">Download full bootstrap</button>
</div>
<pre id="bootpeel" class="peel" style="margin-top:12px"></pre>
</div>
</section>
<div class="foot">Luarmor Fetcher · Flask / Python · v3.0.0 · static peel only</div>
</main>
<script>
const $=id=>document.getElementById(id);
let last={loader:"",bootstrap:null,fullBoot:null};

function setStatus(m,k=""){$("status").textContent=m;$("status").className="status "+(k==="ok"?"ok":k==="err"?"err":"");}
function metric(l,v){const d=document.createElement("div");d.className="metric";const s=document.createElement("small"),b=document.createElement("b");s.textContent=l;b.textContent=v;d.append(s,b);return d;}

document.querySelectorAll(".tab").forEach(t=>{
 t.addEventListener("click",()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));
  t.classList.add("on");
  const k=t.dataset.t;
  $("pane-loader").classList.toggle("hidden",k!=="loader");
  $("pane-peel").classList.toggle("hidden",k!=="peel");
  $("pane-boot").classList.toggle("hidden",k!=="boot");
 });
});

$("fetch").addEventListener("click",async()=>{
 const url=$("url").value.trim();
 if(!url){setStatus("URL 필요","err");return;}
 $("fetch").disabled=true;$("result").classList.add("hidden");
 last={loader:"",bootstrap:null,fullBoot:null};
 setStatus("요청 중…");
 try{
  const r=await fetch("/api/fetch",{method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({url,include_bootstrap:$("boot").checked,full_bootstrap:false})});
  const d=await r.json();
  if(!r.ok||!d.ok)throw new Error(d.error||"fail");
  last.loader=d.loader.source;
  $("source").value=last.loader;
  $("meta").replaceChildren(
   metric("HTTP",String(d.loader.status)),
   metric("Loader",d.version.toUpperCase()),
   metric("Script ID",d.script_id||"—"),
   metric("Size",d.loader.bytes.toLocaleString()+" B"),
   metric("Lines",String(d.loader.lines)),
   metric("Type",d.loader.content_type)
  );
  $("peel").textContent=JSON.stringify(d.loader.peel,null,2);
  if(d.bootstrap){
   if(d.bootstrap.error){
    $("bootsrc").value="ERROR: "+d.bootstrap.error;
    $("bootpeel").textContent="";
   }else{
    $("bootsrc").value=d.bootstrap.source_preview||"(preview)";
    $("bootpeel").textContent=JSON.stringify(d.bootstrap.peel||{},null,2);
    last.bootstrap=d.bootstrap;
   }
  }else{
   $("bootsrc").value="(skipped)";
   $("bootpeel").textContent="";
  }
  $("result").classList.remove("hidden");
  setStatus("완료 — 정적 박리 포함","ok");
 }catch(e){setStatus(e.message,"err");}
 finally{$("fetch").disabled=false;}
});

$("dl").addEventListener("click",async()=>{
 if(!last.loader)return;
 const r=await fetch("/api/download",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({source:last.loader,filename:"luarmor_loader.lua"})});
 if(!r.ok){setStatus("download fail","err");return;}
 const b=await r.blob(),u=URL.createObjectURL(b),a=document.createElement("a");
 a.href=u;a.download="luarmor_loader.lua";a.click();URL.revokeObjectURL(u);
});

$("dlboot").addEventListener("click",async()=>{
 setStatus("bootstrap full fetch…");
 try{
  const r=await fetch("/api/bootstrap",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
  const d=await r.json();
  if(!r.ok||!d.ok)throw new Error(d.error||"fail");
  const r2=await fetch("/api/download",{method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({source:d.source,filename:"luarmor_bootstrap.lua"})});
  const b=await r2.blob(),u=URL.createObjectURL(b),a=document.createElement("a");
  a.href=u;a.download="luarmor_bootstrap.lua";a.click();URL.revokeObjectURL(u);
  setStatus("bootstrap saved","ok");
 }catch(e){setStatus(e.message,"err");}
});

$("copy").addEventListener("click",async()=>{
 try{await navigator.clipboard.writeText(last.loader);setStatus("copied","ok");}
 catch{setStatus("clipboard blocked","err");}
});
$("clear").addEventListener("click",()=>{
 $("url").value="";$("source").value="";$("bootsrc").value="";$("peel").textContent="";$("bootpeel").textContent="";
 $("meta").replaceChildren();$("result").classList.add("hidden");last={loader:"",bootstrap:null};setStatus("cleared");
});
</script>
</body>
</html>
"""
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

MAX_SOURCE_BYTES = 2_500_000
TIMEOUT = (5, 20)
ALLOWED_HOSTS = {"api.luarmor.net", "cdn.luarmor.net"}
LOADER_PATH = re.compile(
    r"/files/v[34]/(?:loaders|verified)/[A-Za-z0-9_-]+\.lua\Z", re.I
)
BOOTSTRAP_URL = "https://cdn.luarmor.net/v4_init_novendgood.lua"
VERSION = "3.0.0"

# ---------------------------------------------------------------------------
# URL validation (SSRF hard gate)
# ---------------------------------------------------------------------------


def validate_url(raw_url: str, *, allow_cdn: bool = False) -> str:
    parsed = urlparse((raw_url or "").strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("HTTPS only.")
    host = (parsed.hostname or "").lower()
    allowed = ALLOWED_HOSTS if allow_cdn else {"api.luarmor.net"}
    if host not in allowed:
        raise ValueError(f"Host not allowed: {host}")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL rejected.")
    if parsed.port not in (None, 443):
        raise ValueError("Port must be 443.")
    if parsed.query or parsed.fragment:
        raise ValueError("Query/fragment not allowed.")
    if host == "api.luarmor.net" and not LOADER_PATH.fullmatch(parsed.path or ""):
        raise ValueError(
            "Path must be /files/v3|v4/loaders|verified/{ID}.lua"
        )
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("DNS resolve failed.") from exc
    for answer in answers:
        addr = ipaddress.ip_address(answer[4][0])
        if not addr.is_global:
            raise ValueError("Non-public IP rejected.")
    return parsed.geturl()


def _http_get(url: str, *, stream: bool = True) -> requests.Response:
    return requests.get(
        url,
        headers={
            "User-Agent": "Roblox/WinInet",
            "Accept": "*/*",
        },
        timeout=TIMEOUT,
        allow_redirects=False,
        stream=stream,
    )


def _read_body(response: requests.Response) -> bytes:
    if 300 <= response.status_code < 400:
        raise ValueError("Redirect returned; not followed.")
    if response.status_code != 200:
        raise ValueError(f"HTTP {response.status_code}")
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=16_384):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_SOURCE_BYTES:
            raise ValueError("Body exceeds size limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def fetch_text(url: str) -> tuple[str, dict[str, Any]]:
    safe = validate_url(url, allow_cdn=("cdn.luarmor.net" in url))
    with _http_get(safe) as resp:
        raw = _read_body(resp)
        enc = resp.encoding or "utf-8"
        try:
            text = raw.decode(enc, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        meta = {
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", "unknown"),
            "content_length": resp.headers.get("Content-Length", str(len(raw))),
            "bytes": len(raw),
            "final_url": safe,
        }
        return text, meta


# ---------------------------------------------------------------------------
# Static peel / analysis
# ---------------------------------------------------------------------------

_BS_RE = re.compile(
    r"_bsdata0\s*=\s*\{([^}]{20,})\}",
    re.S,
)
_LONG_RE = re.compile(r"\[(=*)\[(.*?)\]\1\]", re.S)
_HEX_BLOB_RE = re.compile(r'"([0-9a-fA-F]{64,})"')
_ESC_STR_RE = re.compile(r'"((?:\\[0-9]{1,3}|\\.|[^"\\]){8,})"')
_URL_RE = re.compile(r'https?://[^\s"\'\\]+')
_SCRIPT_ID_RE = re.compile(
    r"/files/v[34]/(?:loaders|verified)/([A-Za-z0-9_-]+)\.lua", re.I
)


def _try_decode_escaped(s: str) -> bytes | None:
    """Turn Lua-style \\ddd / \\x escapes into bytes when possible."""
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt.isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - i < 4:
                    j += 1
                out.append(int(s[i + 1 : j]) & 0xFF)
                i = j
                continue
            if nxt == "x" and i + 3 < len(s):
                try:
                    out.append(int(s[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            escapes = {"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34, "'": 39}
            out.append(escapes.get(nxt, ord(nxt)))
            i += 2
            continue
        out.append(ord(s[i]) & 0xFF)
        i += 1
    return bytes(out) if out else None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    import math

    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def peel_loader(source: str) -> dict[str, Any]:
    """Static extraction from a public loader body."""
    report: dict[str, Any] = {
        "kind": "loader",
        "has_bsdata0": False,
        "bsdata0_fields": [],
        "hex_blobs": [],
        "escaped_blobs": [],
        "urls": [],
        "cache_folder_hint": None,
        "bootstrap_hint": None,
        "notes": [],
    }

    m = _BS_RE.search(source)
    if m:
        report["has_bsdata0"] = True
        body = m.group(1)
        # naive split on commas outside strings is enough for inventory
        parts = re.findall(
            r'"([^"]*)"|(\d+)|(\\?[0-9\\]+)',
            body,
        )
        fields: list[Any] = []
        for p in re.finditer(
            r'"(?:\\.|[^"\\])*"|\d+|true|false|nil', body
        ):
            tok = p.group(0)
            if tok.startswith('"'):
                fields.append({"type": "string", "len": len(tok) - 2, "preview": tok[:80]})
            else:
                fields.append({"type": "number", "value": tok})
        report["bsdata0_fields"] = fields[:40]
        report["notes"].append(f"_bsdata0 present, {len(fields)} tokens")

    for hx in _HEX_BLOB_RE.findall(source):
        report["hex_blobs"].append(
            {
                "len": len(hx),
                "sha256": hashlib.sha256(bytes.fromhex(hx)).hexdigest()
                if len(hx) % 2 == 0
                else None,
                "preview": hx[:48] + ("…" if len(hx) > 48 else ""),
            }
        )

    for esc in _ESC_STR_RE.findall(source):
        raw = _try_decode_escaped(esc)
        if raw and len(raw) >= 8:
            report["escaped_blobs"].append(
                {
                    "len": len(raw),
                    "entropy": round(_entropy(raw), 3),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "preview_hex": raw[:24].hex(),
                }
            )

    report["urls"] = list(dict.fromkeys(_URL_RE.findall(source)))[:20]

    folder = re.search(r'static_content_\d+', source)
    if folder:
        report["cache_folder_hint"] = folder.group(0)

    boot = re.search(r'cdn\.luarmor\.net/[A-Za-z0-9_./-]+\.lua', source)
    if boot:
        report["bootstrap_hint"] = "https://" + boot.group(0)

    if "Do not save this file" in source:
        report["notes"].append("standard loader banner present")
    if "loadstring" in source and "HttpGet" in source:
        report["notes"].append("bootstrap download via HttpGet+loadstring")

    return report


def peel_bootstrap(source: str) -> dict[str, Any]:
    """Static inventory of the shared v4 init bootstrap."""
    report: dict[str, Any] = {
        "kind": "bootstrap",
        "size": len(source),
        "long_strings": [],
        "urls": list(dict.fromkeys(_URL_RE.findall(source)))[:20],
        "lph_markers": source.count("LPH"),
        "sha256": hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest(),
        "notes": [],
    }

    for eq, body in _LONG_RE.findall(source):
        raw = body.encode("latin-1", errors="replace")
        entry = {
            "eq_level": len(eq),
            "char_len": len(body),
            "byte_len": len(raw),
            "entropy": round(_entropy(raw), 3),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "preview_hex": raw[:32].hex(),
        }
        # try zlib / raw inflate on leading bytes
        for name, attempt in (
            ("zlib", lambda d: zlib.decompress(d)),
            ("raw_inflate", lambda d: zlib.decompress(d, -15)),
            ("gzip", lambda d: zlib.decompress(d, 16 + zlib.MAX_WBITS)),
        ):
            try:
                out = attempt(raw[: min(len(raw), 4_000_000)])
                entry["decompress_try"] = {
                    "method": name,
                    "out_len": len(out),
                    "out_sha256": hashlib.sha256(out).hexdigest(),
                    "out_preview_hex": out[:32].hex(),
                }
                break
            except Exception:
                continue
        report["long_strings"].append(entry)

    if report["lph_markers"]:
        report["notes"].append(f"LPH marker count={report['lph_markers']}")
    if "Luarmor V4 bootstrapper" in source:
        report["notes"].append("v4 bootstrapper header present")
    if "superflow_bytecode" in source:
        report["notes"].append("superflow_bytecode table present")

    return report


def extract_script_id(url: str) -> str | None:
    m = _SCRIPT_ID_RE.search(url)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# High-level fetch pipeline
# ---------------------------------------------------------------------------


def fetch_pipeline(loader_url: str, *, include_bootstrap: bool = True) -> dict[str, Any]:
    loader_src, loader_meta = fetch_text(loader_url)
    if not loader_src.strip():
        raise ValueError("Empty loader body.")

    loader_peel = peel_loader(loader_src)
    script_id = extract_script_id(loader_url)
    version = "v4" if "/v4/" in loader_url else "v3"

    result: dict[str, Any] = {
        "ok": True,
        "version": version,
        "script_id": script_id,
        "loader": {
            "source": loader_src,
            **loader_meta,
            "lines": len(loader_src.splitlines()),
            "peel": loader_peel,
        },
        "bootstrap": None,
    }

    boot_url = loader_peel.get("bootstrap_hint") or BOOTSTRAP_URL
    if include_bootstrap and boot_url:
        try:
            boot_src, boot_meta = fetch_text(boot_url)
            result["bootstrap"] = {
                "source": boot_src,
                **boot_meta,
                "lines": len(boot_src.splitlines()),
                "peel": peel_bootstrap(boot_src),
                "url": boot_url,
            }
        except Exception as exc:
            result["bootstrap"] = {
                "error": str(exc),
                "url": boot_url,
            }

    return result


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
def index():
    return INDEX_HTML


@app.post("/api/fetch")
def api_fetch():
    payload = request.get_json(silent=True) or request.form or {}
    url = str(payload.get("url", "")).strip()
    include_boot = bool(payload.get("include_bootstrap", True))
    try:
        data = fetch_pipeline(url, include_bootstrap=include_boot)
        # keep response lean for UI: drop full bootstrap source from default
        # (still available via /api/bootstrap)
        if data.get("bootstrap") and "source" in data["bootstrap"]:
            data["bootstrap"]["source_sha256"] = hashlib.sha256(
                data["bootstrap"]["source"].encode("utf-8", errors="replace")
            ).hexdigest()
            data["bootstrap"]["source_preview"] = data["bootstrap"]["source"][:4000]
            # full source only if client asks
            if not payload.get("full_bootstrap"):
                data["bootstrap"].pop("source", None)
        return jsonify(data)
    except (ValueError, requests.RequestException) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/bootstrap")
def api_bootstrap():
    """Fetch + peel the shared bootstrap only."""
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url") or BOOTSTRAP_URL).strip()
    try:
        src, meta = fetch_text(url)
        return jsonify(
            {
                "ok": True,
                "source": src,
                **meta,
                "lines": len(src.splitlines()),
                "peel": peel_bootstrap(src),
            }
        )
    except (ValueError, requests.RequestException) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/download")
def api_download():
    payload = request.get_json(silent=True) or {}
    source = payload.get("source")
    name = str(payload.get("filename") or "luarmor_dump.lua")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]
    if not isinstance(source, str) or not source:
        return jsonify({"ok": False, "error": "No source."}), 400
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        return jsonify({"ok": False, "error": "Too large."}), 400
    return Response(
        source,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.get("/health")
def health():
    return jsonify({"ok": True, "version": VERSION})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
