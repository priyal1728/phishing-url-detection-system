import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st

DB_PATH = "phishing_history.db"

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "bank",
    "confirm", "update", "password", "reset", "invoice", "payment",
    "security", "claim", "winner", "reward", "alert", "urgent"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "tiny.cc", "buff.ly", "adf.ly", "bc.vc"
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def analyze_url(url):
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    indicators = []
    score = 0

    if parsed.scheme.lower() != "https":
        indicators.append("Missing HTTPS security layer.")
        score += 20

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname):
        indicators.append("IP address is used instead of a domain name.")
        score += 30

    if hostname in {"", "localhost"}:
        indicators.append("Hostname is missing or invalid.")
        score += 15

    if any(domain in hostname for domain in SHORTENER_DOMAINS):
        indicators.append("URL uses a shortening service.")
        score += 25

    found_keywords = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in hostname or keyword in path]
    if found_keywords:
        discovered = ", ".join(found_keywords[:4])
        indicators.append(f"Suspicious keywords detected: {discovered}.")
        score += min(30, 10 * len(found_keywords))

    if "@" in url:
        indicators.append("URL contains an '@' symbol, which may hide the real domain.")
        score += 15

    if hostname.count(".") > 3:
        indicators.append("Unusually long or nested hostname structure detected.")
        score += 10

    if "-" in hostname:
        indicators.append("Hyphenated hostname may indicate impersonation.")
        score += 10

    if len(hostname) > 25:
        indicators.append("Hostname length is unusually long for a normal domain.")
        score += 10

    if len(url) > 100:
        indicators.append("Long URL structure is suspicious for phishing attempts.")
        score += 10

    if not indicators:
        score = 5

    score = min(score, 100)

    if score >= 70:
        risk_level = "High"
    elif score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return score, risk_level, " | ".join(indicators) if indicators else "No major issues found."


def save_scan(url, score, risk_level, indicators):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scans (url, score, risk_level, indicators, scanned_at) VALUES (?, ?, ?, ?, ?)",
        (url, score, risk_level, indicators, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def get_history(limit=10):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT url, score, risk_level, indicators, scanned_at FROM scans ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return rows


def render_result(url, score, risk_level, indicators):
    st.subheader("Analysis Result")
    st.write(f"URL: {url}")
    st.write(f"Risk Score: {score}/100")

    if risk_level == "High":
        st.error(f"Risk Level: {risk_level}")
    elif risk_level == "Medium":
        st.warning(f"Risk Level: {risk_level}")
    else:
        st.success(f"Risk Level: {risk_level}")

    st.write("Detected Indicators:")
    st.write(indicators)

    st.write("Recommendations:")
    if risk_level == "High":
        st.markdown(
            "- Do not enter your password or personal details on this website.\n"
            "- Verify the sender or company before clicking the link.\n"
            "- Visit the official website directly instead of using the suspicious link.\n"
            "- Use browser security warnings and antivirus protection."
        )
    elif risk_level == "Medium":
        st.markdown(
            "- Be cautious before entering credentials.\n"
            "- Check if the domain looks legitimate.\n"
            "- Verify the site without using the provided link."
        )
    else:
        st.markdown(
            "- Keep your browser updated.\n"
            "- Avoid clicking unknown links.\n"
            "- Always check for HTTPS before entering sensitive information."
        )


def main():
    st.set_page_config(page_title="Phishing URL Detection System", layout="wide")
    st.title("Phishing URL Detection System")
    st.caption("Educational cybersecurity tool for analyzing suspicious URLs.")

    init_db()

    st.write("This tool checks common phishing indicators such as missing HTTPS, suspicious keywords, shortened URLs, and IP-based hostnames.")

    with st.form("url_form"):
        url = st.text_input("Enter a URL to analyze", "https://example.com")
        submitted = st.form_submit_button("Analyze URL")

    if submitted:
        if not url.strip():
            st.warning("Please enter a valid URL.")
        else:
            try:
                if not url.startswith(("http://", "https://")):
                    url = "https://" + url
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError("Invalid URL format.")

                score, risk_level, indicators = analyze_url(url)
                save_scan(url, score, risk_level, indicators)
                render_result(url, score, risk_level, indicators)
            except ValueError as exc:
                st.error(f"Invalid URL: {exc}")

    st.subheader("Recent Scan History")
    history = get_history(10)
    if not history:
        st.write("No previous scans available yet.")
    else:
        for each_url, score, risk_level, indicators, scanned_at in history:
            st.markdown(f"### {each_url}")
            st.write(f"Score: {score}/100 | Risk: {risk_level} | Time: {scanned_at}")
            st.write(indicators)
            st.write("---")


if __name__ == "__main__":
    main()
