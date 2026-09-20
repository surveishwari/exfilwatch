# 2-minute demo script

**0:00 — The problem (15s).** "Your AI assistant's reply can carry a secret in text that looks perfectly normal — or in an image a chat app loads automatically. Existing DLP scans visible text, so it sees nothing."

**0:15 — Attack (30s).** `/demo` → Run a live attack with the default GlassWorm scheme. Two reply boxes look identical. Click **X-ray** on the tampered one: numbered markers appear. "Same sentence, 40 invisible characters."

**0:45 — Detection (25s).** Watch the payload resolve in the red *Decoded* box. Point at the evidence waterfall: "Every point of the score is traceable to a signal. No black box."

**1:10 — Enforcement (20s).** Scroll to Mitigation: the tampered reply is BLOCKED, the underlying reply is independently re-scanned, and the clean one is served. "Not an alert — a decision."

**1:30 — Second channel (15s).** Switch scheme to *Zero-click markdown image URL* and run again. "Different attack, no invisible characters at all — the secret is in an image URL. Also decoded."

**1:45 — Trust (20s).** `/dashboard` → the audit chain shows *Chain intact*; run *Detector validation* (precision/recall live). Then click **Run self red team**: watch it attack itself with 4 real evasion attempts live — 3 caught, 1 genuine gap shown with its exact fix, not hidden. "We didn't just test it — we tried to break it, on stage, and told you what won."

Close: "One line to adopt: change your `base_url` to `/v1`."
