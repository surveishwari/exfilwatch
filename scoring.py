"""
ExfilWatch — Evidence Fusion Scoring Engine

BEFORE this module existed, both detectors combined independent signals
by adding hand-picked point values: "+20 if zw_hits > 4", "+35 for
severity 3". That's arithmetically simple but has no principled basis —
there's no defensible answer to "why 20 and not 15?"

This replaces that with naive-Bayes log-odds fusion, the same technique
behind classical Bayesian spam filters and evidence-based intrusion
detection systems. Each detector emits independent evidence: a signal
name plus a likelihood ratio — how many times more likely that signal
is to appear under the "malicious" hypothesis than under "benign text".
Evidence combines by SUMMING LOG-ODDS (Bayes' rule under a conditional-
independence assumption) rather than summing arbitrary points. This
gives:

  1. A principled combination rule instead of arithmetic folklore.
  2. A probability-shaped score with a stated derivation (NOT empirically calibrated: the
     prior and likelihood ratios are engineering estimates, checked only by validate.py)
     someone made up.
  3. Per-signal contributions that are individually justified (see the
     LR reasoning documented at each call site) and can be measured
     against real data — see validate.py, which checks these against
     an actual labeled test corpus rather than asserting they're right.

This is standard, well-understood math (log P(H|E) ∝ log P(H) +
Σ log LR_i), not a novel ML claim — the honest framing is "principled
evidence combination", not "we trained a model".
"""

import math

PRIOR_PROBABILITY = 0.02  # base rate assumption: most AI output is not malicious


def _prob_to_log_odds(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def _log_odds_to_prob(lo: float) -> float:
    # guard against overflow on very large log-odds sums
    lo = min(max(lo, -50), 50)
    return 1 / (1 + math.exp(-lo))


def fuse(evidence: list[tuple[str, float]], prior: float = PRIOR_PROBABILITY) -> dict:
    """
    evidence: list of (signal_name, likelihood_ratio).
      LR > 1  -> signal makes the malicious hypothesis more likely
      LR == 1 -> signal is uninformative (no-op)
      LR < 1  -> signal makes malicious LESS likely (supported, unused today)

    Returns a probability-shaped score (0-1, uncalibrated), a 0-100 risk_score for
    display, and per-signal contributions so the UI can show exactly
    how much each piece of evidence moved the needle — real
    explainability, not just a final number with no derivation.
    """
    log_odds = _prob_to_log_odds(prior)
    contributions = []
    for name, lr in evidence:
        delta = math.log(max(lr, 1e-6))
        log_odds += delta
        contributions.append({
            "signal": name,
            "likelihood_ratio": round(lr, 2),
            "log_odds_delta": round(delta, 3),
        })

    probability = _log_odds_to_prob(log_odds)
    return {
        "probability": probability,
        "risk_score": round(probability * 100),
        "contributions": contributions,
    }


if __name__ == "__main__":
    # sanity check: strong single signal should dominate
    r = fuse([("AWS Access Key pattern match", 500)])
    print("Single strong signal:", r["risk_score"], "%")

    r2 = fuse([("weak signal A", 3), ("weak signal B", 2)])
    print("Two weak signals combined:", r2["risk_score"], "%")

    r3 = fuse([])
    print("No evidence (prior only):", r3["risk_score"], "%")
