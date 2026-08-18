import re
from urllib.parse import urlparse


# Maximum message length allowed by the detector
MAX_TEXT_LENGTH = 10000


# Suspicious words commonly found in scam/phishing messages
SUSPICIOUS_WORDS = [
    "urgent",
    "verify",
    "verification",
    "password",
    "login",
    "signin",
    "account",
    "suspended",
    "winner",
    "prize",
    "free",
    "claim",
    "otp",
    "bank",
    "payment",
    "security"
]


def analyze_text(text):

    # 1. Validate input
    if not isinstance(text, str):
        return {
            "score": 0,
            "risk": "ERROR",
            "reasons": ["Invalid input."]
        }

    text = text.strip()

    if not text:
        return {
            "score": 0,
            "risk": "ERROR",
            "reasons": ["No message was provided."]
        }

    if len(text) > MAX_TEXT_LENGTH:
        return {
            "score": 0,
            "risk": "ERROR",
            "reasons": [
                f"Message is too long. Maximum allowed length is "
                f"{MAX_TEXT_LENGTH} characters."
            ]
        }

    score = 0
    reasons = []

    text_lower = text.lower()

    # 2. Check suspicious words
    found_words = []

    for word in SUSPICIOUS_WORDS:
        if re.search(rf"\b{re.escape(word)}\b", text_lower):
            found_words.append(word)

    if found_words:
        score += min(len(found_words) * 8, 40)

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_words)
        )

    # 3. Check urgent or threatening language
    urgency_patterns = [
        r"\bact now\b",
        r"\bimmediately\b",
        r"\blast chance\b",
        r"\baccount suspended\b",
        r"\baccount will be closed\b"
    ]

    for pattern in urgency_patterns:

        if re.search(pattern, text_lower):

            score += 15

            reasons.append(
                "Urgent or threatening language detected."
            )

            break

    # 4. Find URLs in the message
    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text,
        re.IGNORECASE
    )

    for url in urls:

        url_result = analyze_url(url)

        score += url_result["score"]

        reasons.extend(url_result["reasons"])

    # 5. Check if the message asks for sensitive information
    sensitive_patterns = [
        r"send your password",
        r"share your otp",
        r"give me your otp",
        r"enter your password",
        r"confirm your bank",
        r"send your card number"
    ]

    for pattern in sensitive_patterns:

        if re.search(pattern, text_lower):

            score += 25

            reasons.append(
                "The message appears to request sensitive information."
            )

            break

    # 6. Keep score between 0 and 100
    score = min(score, 100)

    # 7. Determine risk level
    if score >= 70:
        risk = "HIGH"

    elif score >= 40:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    # 8. If nothing suspicious was found
    if not reasons:
        reasons.append(
            "No major suspicious indicators detected."
        )

    return {
        "score": score,
        "risk": risk,
        "reasons": reasons
    }


def analyze_url(url):

    score = 0
    reasons = []

    # Validate URL input
    if not isinstance(url, str) or not url.strip():
        return {
            "score": 0,
            "reasons": []
        }

    url = url.strip()

    # Add HTTP if protocol is missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname or ""

        if not hostname:
            return {
                "score": 30,
                "reasons": [
                    "The URL does not contain a valid hostname."
                ]
            }

        # 1. Check HTTPS
        if parsed.scheme == "http":

            score += 15

            reasons.append(
                "The URL does not use HTTPS."
            )

        # 2. Check if URL uses an IP address
        if re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            hostname
        ):

            score += 25

            reasons.append(
                "The URL uses an IP address instead of a normal domain."
            )

        # 3. Check very long URLs
        if len(url) > 100:

            score += 10

            reasons.append(
                "The URL is unusually long."
            )

        # 4. Check @ symbol
        if "@" in url:

            score += 20

            reasons.append(
                "The URL contains '@', which can hide the real destination."
            )

        # 5. Check number of subdomains
        parts = hostname.split(".")

        if len(parts) > 4:

            score += 10

            reasons.append(
                "The domain contains many subdomains."
            )

        # 6. Check suspicious words in the domain
        suspicious_url_words = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "password",
            "wallet",
            "claim",
            "free"
        ]

        found = []

        for word in suspicious_url_words:

            if word in hostname.lower():
                found.append(word)

        if found:

            score += min(len(found) * 8, 20)

            reasons.append(
                "Suspicious terms found in the domain: "
                + ", ".join(found)
            )

    except Exception:

        score += 30

        reasons.append(
            "The URL could not be analyzed normally."
        )

    return {
        "score": min(score, 100),
        "reasons": reasons
    }
