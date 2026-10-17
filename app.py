import ipaddress
import re
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

MAX_INPUT_LENGTH = 10_000
MAX_URL_LENGTH = 2_048
URL_PATTERN = re.compile(r"""(?:https?://|www\.)[^\s<>"']+""", re.I)
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
TEXT_RULES = (
    ("urgency", "Urgent or pressuring language", r"\b(urgent|act now|immediately|final notice|expires today|within \d+\s*(minutes?|hours?))\b", 18, "The message pressures you to act quickly."),
    ("credentials", "Request for credentials or security codes", r"\b(password|passcode|one[- ]time code|verification code|security code|login details|credentials|2fa code)\b", 26, "It mentions credentials or codes that should not be shared in a message."),
    ("payment", "Request involving money or payment", r"\b(gift card|wire transfer|crypto(?:currency)?|bitcoin|bank transfer|payment|pay now|send money|western union)\b", 24, "It refers to an unusual payment method or money transfer."),
    ("threat", "Threat or account-pressure language", r"\b(account (?:will be|has been) (?:closed|suspended|locked)|legal action|arrest warrant|service will be terminated)\b", 20, "It uses a threat or account consequence to prompt a response."),
    ("prize", "Unexpected prize or reward language", r"\b(you (?:have )?won|winner|claim your prize|free gift|you've been selected)\b", 12, "It advertises an unexpected prize or reward."),
)


def add_flag(flags, flag_id, label, detail, points):
    if not any(flag["id"] == flag_id for flag in flags):
        flags.append({"id": flag_id, "label": label, "detail": detail, "points": points})


def inspect_url(raw_url):
    """Inspect URL text only; never open it or make a network request."""
    candidate = raw_url.strip()
    if candidate.lower().startswith("www."):
        candidate = "https://" + candidate
    if len(candidate) > MAX_URL_LENGTH:
        raise ValueError(f"A URL must be {MAX_URL_LENGTH} characters or fewer.")
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("That URL could not be parsed. Check its format.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        raise ValueError("Enter a URL with a valid host, such as https://example.com.")

    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        ip_host = True
    except ValueError:
        ip_host = False
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("That URL has an invalid host name.") from exc
        labels = ascii_host.split(".")
        if (
            len(ascii_host) > 253
            or any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label, re.I)
                for label in labels
            )
        ):
            raise ValueError("That URL has an invalid host name.")
    flags = []
    checks = (
        (parsed.scheme.lower() == "http", "http", "Connection is not encrypted",
         "This URL uses HTTP. HTTPS does not prove a site is legitimate, but HTTP does not encrypt the connection.", 18),
        (parsed.username is not None or parsed.password is not None, "userinfo", "URL contains user information",
         "Text before the @ symbol can make a URL's apparent destination misleading.", 28),
        ("xn--" in host, "punycode", "URL contains an internationalized domain encoding",
         "Some lookalike domains use encoded characters that resemble familiar letters.", 24),
        (host in SHORTENERS, "shortener", "URL uses a link-shortening service",
         "A shortened link hides its final destination. Verify it independently before opening.", 18),
        (port is not None and port not in {80, 443}, "unusual-port", "URL uses a non-standard port",
         f"The URL specifies port {port}, which is less common for a public website.", 10),
    )
    if ip_host:
        add_flag(flags, "ip-host", "URL uses an IP address as its host",
                 "A numeric address can make a destination harder to verify.", 22)
    for condition, flag_id, label, detail, points in checks:
        if condition:
            add_flag(flags, flag_id, label, detail, points)
    if re.search(r"\b(login|verify|secure|account|password|wallet|billing|payment|update)\b",
                 parsed.path + " " + parsed.query, re.I):
        add_flag(flags, "sensitive-path", "URL path mentions an account or sensitive action",
                 "This alone does not prove fraud, but the path contains terms often used on sign-in, payment, or verification pages.", 10)
    return {"url": raw_url, "host": host, "score": min(100, sum(f["points"] for f in flags)), "flags": flags}


def extract_urls(text):
    found = []
    for match in URL_PATTERN.finditer(text):
        candidate = match.group(0).rstrip(".,!?;:)]}>'\"")
        if candidate and candidate not in found:
            found.append(candidate)
        if len(found) == 10:
            break
    return found


def risk_level(score):
    if score >= 60:
        return "high", "High risk indicators"
    if score >= 30:
        return "elevated", "Some warning signs"
    return "lower", "Fewer warning signs detected"


def make_result(score, flags, urls=None):
    urls = urls or []
    score = min(100, max(0, score))
    level, label = risk_level(score)
    if not flags:
        summary = "No common warning signs were detected. That does not guarantee the content is safe."
    elif level == "high":
        summary = "Several warning signs were detected. Avoid interacting until you verify the sender independently."
    elif level == "elevated":
        summary = "Some warning signs were detected. Verify the sender and destination before taking action."
    else:
        summary = "A few warning signs were detected. Be cautious and verify unexpected requests."
    steps = [
        "Do not reply with passwords, verification codes, or personal information.",
        "Contact the organization through a number or website you find independently.",
    ]
    if urls:
        steps.insert(0, "Avoid opening links in the message. Visit the organization's known website directly.")
    ids = {f["id"] for f in flags}
    if "payment" in ids:
        steps.append("Do not send money, gift cards, or cryptocurrency based on an unsolicited message.")
    return {
        "score": score, "level": level, "label": label, "summary": summary,
        "flags": flags, "urls": urls, "recommendations": list(dict.fromkeys(steps)),
        "method": "Rule-based checks; this is not an AI/ML model.",
    }


def analyze_message(text):
    flags = []
    for flag_id, label, pattern, points, detail in TEXT_RULES:
        if re.search(pattern, text, re.I):
            add_flag(flags, flag_id, label, detail, points)
    urls = []
    for raw in extract_urls(text):
        try:
            urls.append(inspect_url(raw))
        except ValueError:
            urls.append({"url": raw, "host": "", "score": 12, "flags": [{
                "id": "unparsed-url", "label": "Link could not be fully checked",
                "detail": "The link format could not be parsed reliably. Treat it cautiously.", "points": 12,
            }]})
    for url in urls:
        for flag in url["flags"]:
            add_flag(flags, f"{url['url']}:{flag['id']}", flag["label"], flag["detail"], flag["points"])
    # Combine text indicators with the strongest URL signal without double-counting its explanations.
    text_rule_ids = {rule[0] for rule in TEXT_RULES}
    text_score = sum(f["points"] for f in flags if f["id"] in text_rule_ids)
    score = min(100, text_score + round(max((u["score"] for u in urls), default=0) * 0.65))
    return make_result(score, flags, urls)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    if not request.is_json:
        return jsonify(error="Send a JSON request with Content-Type: application/json."), 415
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="The request body must be a JSON object."), 400
    mode, text = data.get("mode"), data.get("text")
    if mode not in {"message", "url"}:
        return jsonify(error="Choose either message or URL analysis."), 400
    if not isinstance(text, str):
        return jsonify(error="Enter text to analyze."), 400
    text = text.strip()
    if not text:
        return jsonify(error="Enter a message or URL to analyze."), 400
    if len(text) > MAX_INPUT_LENGTH:
        return jsonify(error=f"Input must be {MAX_INPUT_LENGTH} characters or fewer."), 413
    try:
        if mode == "url":
            item = inspect_url(text)
            result = make_result(item["score"], item["flags"], [item])
        else:
            result = analyze_message(text)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(result)


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="Request is too large."), 413


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
