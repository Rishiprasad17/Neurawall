"""
prescreen_patterns.py — Enhanced pre-screen patterns for Neurawall
Copy these patterns into core/middleware.py to replace PRESCREEN_PATTERNS
"""
import re

PRESCREEN_PATTERNS = [
    # ── Social Engineering ────────────────────────────────────────
    re.compile(r"(admin|password|credential|secret|token|api.?key)", re.I),
    re.compile(r"(export|dump|extract|download).{0,20}(data|user|customer|record)", re.I),
    re.compile(r"(show|reveal|display|give|send).{0,20}(password|credential|secret|key)", re.I),
    re.compile(r"(bypass|circumvent|override|ignore).{0,20}(security|auth|restrict|filter)", re.I),
    re.compile(r"(pretend|act as|behave as|imagine).{0,20}(no restriction|unrestrict|admin|root)", re.I),
    re.compile(r"(security audit|penetration test|pentest).{0,30}(show|access|reveal|give)", re.I),
    re.compile(r"(for testing|test purpose|debugging).{0,20}(disable|bypass|ignore|show)", re.I),
    re.compile(r"(as an admin|as administrator|with admin).{0,20}(access|permission|right)", re.I),

    # ── Data Exfiltration ─────────────────────────────────────────
    re.compile(r"(all user|all customer|all record|entire database)", re.I),
    re.compile(r"(list of|full list).{0,15}(user|customer|account|email|password)", re.I),
    re.compile(r"(send to|email to|forward to).{0,30}@", re.I),
    re.compile(r"(backup|copy|mirror).{0,20}(database|db|table|record)", re.I),

    # ── SSRF (Server-Side Request Forgery) ────────────────────────
    re.compile(r"(http|https|ftp)://(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254)", re.I),
    re.compile(r"(http|https)://10\.\d+\.\d+\.\d+", re.I),
    re.compile(r"(http|https)://192\.168\.\d+\.\d+", re.I),
    re.compile(r"(http|https)://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", re.I),
    re.compile(r"file:///", re.I),
    re.compile(r"gopher://", re.I),

    # ── Template Injection ────────────────────────────────────────
    re.compile(r"\{\{.{1,50}\}\}", re.I),         # Jinja2/Twig {{}}
    re.compile(r"\$\{.{1,50}\}", re.I),           # Java/JS ${}
    re.compile(r"#\{.{1,50}\}", re.I),            # Ruby #{}
    re.compile(r"<%=.{1,50}%>", re.I),            # ERB/JSP

    # ── XXE (XML External Entity) ─────────────────────────────────
    re.compile(r"<!ENTITY", re.I),
    re.compile(r"SYSTEM\s+['\"]file:", re.I),
    re.compile(r"<!DOCTYPE[^>]+\[", re.I),

    # ── Business Logic Attacks ────────────────────────────────────
    re.compile(r"quantity\s*=\s*-\d+", re.I),      # negative quantity
    re.compile(r"price\s*=\s*-\d+", re.I),         # negative price
    re.compile(r"amount\s*=\s*-\d+", re.I),        # negative amount
    re.compile(r"(transfer|send|pay).{0,20}(-\d+|0\.0+\s*(dollar|usd|inr|rupee))", re.I),

    # ── Indian Language Injections ────────────────────────────────
    re.compile(r"(पिछले निर्देश|सभी निर्देश).{0,20}(अनदेखा|भूल)", re.I),  # Hindi
    re.compile(r"(మునుపటి సూచనలు).{0,20}(విస్మరించు)", re.I),             # Telugu
    re.compile(r"(முந்தைய வழிமுறை).{0,20}(புறக்கணி)", re.I),              # Tamil

    # ── Unusual Patterns ─────────────────────────────────────────
    re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"),   # control characters
    re.compile(r"(.)\1{20,}"),                        # repeated chars (fuzzing)
    re.compile(r"(base64|hex|rot13|encode).{0,20}(execute|eval|run|decode)", re.I),
    re.compile(r"curl.{0,30}(evil|attack|malware|shell|payload)", re.I),
    re.compile(r"wget.{0,30}(evil|attack|malware|shell|payload)", re.I),

    # ── Account Takeover ─────────────────────────────────────────
    re.compile(r"(forgot|reset|change).{0,20}password.{0,20}(admin|root|superuser)", re.I),
    re.compile(r"(login as|sign in as|access as).{0,20}(admin|root|other user)", re.I),
    re.compile(r"(impersonate|masquerade).{0,20}(user|admin|account)", re.I),
]
