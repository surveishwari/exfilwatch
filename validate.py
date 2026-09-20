"""
ExfilWatch — Validation Harness
Runs the full detection pipeline against a labeled test corpus and
computes REAL precision/recall/false-positive-rate, on demand, every
time this is called. This is not a static claim in a README — it's a
live measurement, exposed via GET /api/validate, so a judge can trigger
it themselves during a demo and see the actual numbers for that run.

Labels:
  "malicious" — covert-channel stego samples (both named schemes,
                generated fresh each run via hide_engine) and plain-text
                sensitive-data exposure samples.
  "benign"    — ordinary AI-reply-style sentences, including a few
                deliberately tricky "hard negatives" (tracking IDs, long
                URLs) that plausibly could trip up the entropy detector,
                so a failure here is visible rather than hidden by
                picking only easy examples.

The classification threshold mirrors main.py's policy engine exactly
(BLOCK_THRESHOLD / REVIEW_THRESHOLD) — this validates the actual product
decision, not a different internal score.
"""

from hide_engine import hide, hide_variation_selector
from catch_engine import analyze
from hide_engine import SCHEMES
import sensitive_data

BLOCK_THRESHOLD = 50
REVIEW_THRESHOLD = 15

BENIGN_SAMPLES = [
    "שלום, הבקשה שלך טופלה\u200f בהצלחה",
    "The docu\u00admentation lives in the usual place, copied from a web page.",
    "Match today 🏴\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F vs Wales at 7pm.",
    "Here is our logo: ![logo](https://example.com/assets/logo.png) and pricing https://example.com/pricing?utm_source=newsletter&utm_campaign=spring2026",
    "Great news ✅ your refund is processed ❤️ thanks for your patience!",
    "Team update 👨‍👩‍👧 all done, deploy went fine ⚠️ just watch the logs today.",
    "नमस्ते, आपकी समस्या हल हो गई है। धन्यवाद, कृपया क्\u200dषमा करें।",
    "Thanks for reaching out! I've reviewed your request and everything looks good to proceed.",
    "The meeting has been rescheduled to 3 PM on Thursday, please update your calendar.",
    "Here's a summary of the quarterly report: revenue grew 12% year over year.",
    "I'd recommend checking the documentation at our support portal for more details.",
    "Great question! The feature you're asking about is planned for next release.",
    "Your order #48213 has shipped and should arrive within 3-5 business days.",
    "Let me know if you have any other questions about the onboarding process.",
    "The system automatically backs up your data every night at midnight UTC.",
    "I appreciate your patience while we resolve this issue with the billing team.",
    "Our team is currently reviewing your application and will respond within 48 hours.",
    "You can reset your password by clicking the link we just sent to your inbox.",
    "The invoice total comes to $1,240.50, due within 30 days of receipt.",
    "Our office is located at 123 Main Street, Suite 400, in downtown Chicago.",
    # Deliberate hard negatives — structured-looking but legitimate strings
    "Here's the tracking number for your shipment: 1Z999AA10123456784.",
    "Visit https://example.com/docs/getting-started/quickstart-guide-v2 for the walkthrough.",
    "The commit hash for that fix is a3f5c8d1e9b2047f6c8a1d3e5b7f9024.",
]

SENSITIVE_TEXT_SAMPLES = [
    "Sure, here's the API key you asked for: sk-live_4f8a9c2b7e1d3f6a0b5c8e2d",
    "AWS credentials for the staging bucket: AKIAIOSFODNN7EXAMPLE",
    "password: SuperSecret123!",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAxJ8example\n-----END RSA PRIVATE KEY-----",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature123",
    "The card used for the transaction was 4532015112830366.",
    "SSN on file for verification: 219-09-9999",
    "Here's a raw token nobody labeled: 8f2Kq9zR3mN7wJp1LxT6vB4cQ1mZ9x",
]

COVERT_COVERS = [
    "Sure, here is a quick summary of today's meeting notes for the team.",
    "Thanks for your question — happy to help you get set up.",
    "The deployment finished successfully and all tests are passing.",
    "Here's the status update you requested for this week's sprint.",
    "I've attached the document you asked about earlier this morning.",
]
COVERT_SECRETS = [
    "user_pw=hunter2",
    "internal_api_key=sk-prod-7f3a9c2b",
    "db_conn=postgres://admin:pass@10.0.0.5",
    "ssh_key_fragment=AAAAB3NzaC1yc2EAAAADAQAB",
    "session_token=eyJhbGciOiJIUzI1NiJ9",
]


def _build_covert_samples() -> list[str]:
    samples = []
    for cover, secret in zip(COVERT_COVERS, COVERT_SECRETS):
        for hide_fn, _ in SCHEMES.values():  # every named scheme: zero-width, GlassWorm VS, Tags, image-URL
            samples.append(hide_fn(secret, cover))
    # UNPUBLISHED-style channels the engine has no decoder for: it must still flag them by category/blank glyph
    samples.append(COVERT_COVERS[0] + "\u2066\u2067\u2068\u2069\u2066\u2067")     # bidi isolates (Cf)
    samples.append(COVERT_COVERS[1] + "\u3164\u3164\u2800\u3164\u2800\u3164")     # blank glyphs (not Cf)
    return samples


def _classify(text: str) -> dict:
    """Mirrors main.py's _run_catch_pipeline policy decision exactly,
    without importing the FastAPI app (keeps this module dependency-free
    and runnable standalone: `python validate.py`)."""
    covert = analyze(text)
    sensitive = sensitive_data.scan(text)
    combined_risk = max(covert["risk_score"], sensitive["risk_score"])
    if covert["decoded_message"] or combined_risk >= BLOCK_THRESHOLD:
        action = "BLOCK"
    elif combined_risk >= REVIEW_THRESHOLD:
        action = "REVIEW"
    else:
        action = "ALLOW"
    return {"action": action, "risk_score": combined_risk, "decoded": covert["decoded_message"]}


def run_validation() -> dict:
    malicious_samples = _build_covert_samples() + SENSITIVE_TEXT_SAMPLES
    benign_samples = BENIGN_SAMPLES

    tp = fn = fp = tn = 0
    details = []

    for text in malicious_samples:
        result = _classify(text)
        flagged = result["action"] != "ALLOW"
        if flagged:
            tp += 1
        else:
            fn += 1
        details.append({
            "label": "malicious", "flagged": flagged, "action": result["action"],
            "risk_score": result["risk_score"], "text_preview": text[:60],
        })

    for text in benign_samples:
        result = _classify(text)
        flagged = result["action"] != "ALLOW"
        if flagged:
            fp += 1
        else:
            tn += 1
        details.append({
            "label": "benign", "flagged": flagged, "action": result["action"],
            "risk_score": result["risk_score"], "text_preview": text[:60],
        })

    total = tp + fn + fp + tn
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    accuracy = (tp + tn) / total if total else None

    return {
        "sample_counts": {
            "malicious": len(malicious_samples),
            "benign": len(benign_samples),
            "total": total,
        },
        "confusion_matrix": {"true_positive": tp, "false_negative": fn, "false_positive": fp, "true_negative": tn},
        "metrics": {
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "false_positive_rate": round(fpr, 3) if fpr is not None else None,
            "accuracy": round(accuracy, 3) if accuracy is not None else None,
        },
        "details": details,
    }


if __name__ == "__main__":
    import json
    result = run_validation()
    print(json.dumps(result["metrics"], indent=2))
    print(json.dumps(result["confusion_matrix"], indent=2))
    print(f"\n{result['sample_counts']['total']} samples "
          f"({result['sample_counts']['malicious']} malicious, {result['sample_counts']['benign']} benign)")
    misclassified = [d for d in result["details"] if
                      (d["label"] == "malicious" and not d["flagged"]) or
                      (d["label"] == "benign" and d["flagged"])]
    if misclassified:
        print("\nMisclassified samples:")
        for m in misclassified:
            print(f"  [{m['label']}] action={m['action']} risk={m['risk_score']} — {m['text_preview']}")
    else:
        print("\nNo misclassifications this run.")
