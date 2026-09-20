"""
ExfilWatch — sensitive data detector
Scans VISIBLE text for secrets/PII that shouldn't leave the building,
independent of the covert-channel detector in catch_engine.py.

Two detection layers, feeding the SAME evidence-fusion engine
(scoring.py) that catch_engine.py uses — one principled scoring
methodology for the whole product, not two different ad-hoc systems
that happen to both output "0-100":

1. NAMED PATTERNS — known-shaped secrets (emails, AWS keys, password
   fields, private key blocks, bearer tokens). High confidence, but
   only catches shapes we already know about. Each pattern's
   likelihood ratio is justified at its call site by how structurally
   improbable that shape is to appear by chance in ordinary text.

2. ENTROPY-BASED GENERALIZATION — flags high-entropy tokens matching
   NO named pattern: a random API key, JWT, or hex secret in a format
   we've never seen. Mirrors catch_engine.py's Cf-category
   generalization for unpublished stego schemes — here it's Shannon
   entropy catching unpublished secret formats. Weighted with a lower
   likelihood ratio than named patterns, reflecting genuinely lower
   confidence on a generalized, unverified signal.
"""

import math
import re
import scoring

# Each pattern: (label, compiled regex, likelihood_ratio, reasoning)
PATTERNS = [
    ("Email address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), 4,
     "Common and often intentionally shared (support emails, signatures) — weak signal alone."),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 500,
     "Fixed 'AKIA' prefix + 16 base32 chars — astronomically unlikely by chance."),
    ("Generic API key / secret", re.compile(r"\b(?:sk|pk|api|key|secret)[-_][A-Za-z0-9]{16,}\b", re.I), 200,
     "Vendor-style prefix + long random suffix — very unlikely to appear in ordinary prose."),
    ("Password field", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+", re.I), 300,
     "Explicit 'password=' assignment syntax — essentially only appears when a real credential is present."),
    ("Credit card number", re.compile(r"\b(?:\d[ -]*?){13,16}\b"), 250,
     "13-16 digit run that ALSO passes Luhn checksum — checksum-valid digit sequences are rare by chance."),
    ("US Social Security Number", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 180,
     "Specific NNN-NN-NNNN format, rarely produced by anything other than a real SSN."),
    ("Phone number", re.compile(r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b"), 2,
     "Common in legitimate contact info — weak signal alone, kept mainly for PII completeness."),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 1000,
     "PEM header is a near-unique, deliberately standardized marker — essentially never a false positive."),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}\b"), 150,
     "Auth-header syntax with a long random token — strong structural signal."),
]

SEVERITY_BY_LR = lambda lr: 3 if lr >= 100 else (2 if lr >= 20 else 1)

# --- Entropy-based generalized secret detection -----------------------------
CANDIDATE_TOKEN = re.compile(r"[A-Za-z0-9\-_./+=]{20,}")
ENTROPY_MIN_LEN = 20
ENTROPY_THRESHOLD = 3.6  # bits/char — random secrets sit ~4.0-4.8; English prose sits ~3.0-3.3
ENTROPY_LR = 30  # weaker than any named pattern: generalized, unverified signal by design


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _luhn_valid(digits: str) -> bool:
    d = [int(ch) for ch in digits if ch.isdigit()]
    if len(d) < 13:
        return False
    checksum = 0
    parity = len(d) % 2
    for i, digit in enumerate(d):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _mask(match_text: str) -> str:
    if len(match_text) <= 6:
        return "*" * len(match_text)
    return match_text[:3] + "*" * (len(match_text) - 6) + match_text[-3:]


def scan(text: str) -> dict:
    findings = []
    evidence = []
    matched_spans = []

    for label, pattern, lr, reasoning in PATTERNS:
        for m in pattern.finditer(text):
            if label == "Credit card number" and not _luhn_valid(m.group(0)):
                continue
            findings.append({
                "type": label,
                "match_preview": _mask(m.group(0)),
                "severity": SEVERITY_BY_LR(lr),
                "confidence": "high",
                "detection_method": "named pattern",
            })
            evidence.append((f"{label} match", lr))
            matched_spans.append((m.start(), m.end()))

    # URLs are handled by channel_engine (which DECODES them); scanning their slugs and
    # query strings for entropy just flags ordinary links. Blank them out, keeping offsets.
    scan_text = re.sub(r"https?://\S+", lambda u: " " * len(u.group(0)), text)
    entropy_hits = 0
    for m in CANDIDATE_TOKEN.finditer(scan_text):
        span = (m.start(), m.end())
        if any(span[0] < e and span[1] > s for s, e in matched_spans):
            continue
        token = m.group(0)
        if len(token) < ENTROPY_MIN_LEN or token.count("/") >= 2:  # file paths, not secrets
            continue
        entropy = _shannon_entropy(token)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append({
                "type": f"High-entropy token (unrecognized format, {entropy:.1f} bits/char)",
                "match_preview": _mask(token),
                "severity": 2,
                "confidence": "medium",
                "detection_method": "entropy generalization",
            })
            # Repeated entropy hits are correlated (same weak signal), so naive-Bayes would
            # overcount them: the first gets full weight, repeats only weak corroboration.
            evidence.append((f"high-entropy unrecognized token ({entropy:.1f} bits/char)",
                             ENTROPY_LR if entropy_hits == 0 else 3))
            entropy_hits += 1

    fusion = scoring.fuse(evidence)
    return {
        "found": len(findings) > 0,
        "count": len(findings),
        "findings": findings,
        "risk_score": fusion["risk_score"],
        "contributions": fusion["contributions"],
    }


if __name__ == "__main__":
    sample = (
        "Contact me at jane.doe@company.com or my API key is sk-abcdef1234567890xyz. "
        "My password: hunter22. Invoice number 4041234567890123 for reference. "
        "Also here's a raw token nobody named a pattern for: 8f2Kq9zR3mN7wJp1LxT6vB4c"
    )
    result = scan(sample)
    for f in result["findings"]:
        print(f)
    print("risk_score:", result["risk_score"])
