const API = "";
// Demo key only — a real deployment issues per-client keys via a secrets manager,
// never ships one in frontend JS.
const API_KEY = "demo-key-12345";
const AUTH_HEADERS = { "Content-Type": "application/json", "X-API-Key": API_KEY };

async function pingStatus() {
  const el = document.getElementById("status");
  if (!el) return;
  const dot = document.getElementById("statusDot");
  try {
    const r = await fetch(API + "/healthz");
    el.textContent = r.ok ? "API online" : "API error";
    if (dot) dot.className = "status-dot " + (r.ok ? "on" : "off");
  } catch (e) {
    el.textContent = "API offline";
    if (dot) dot.className = "status-dot off";
  }
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : s;
  return d.innerHTML;
}

function actionClass(action) {
  return action === "BLOCK" ? "block" : action === "REVIEW" ? "review" : "allow";
}

function meterColor(score) {
  if (score >= 50) return "var(--crit)";
  if (score >= 15) return "var(--warn)";
  return "var(--safe)";
}

async function loadStats(ids) {
  try {
    const res = await fetch(API + "/api/stats", { headers: AUTH_HEADERS });
    const stats = await res.json();
    if (ids.total) document.getElementById(ids.total).textContent = stats.total || 0;
    if (ids.blocked) document.getElementById(ids.blocked).textContent = stats.blocked || 0;
    if (ids.review) document.getElementById(ids.review).textContent = stats.review || 0;
    if (ids.allowed) document.getElementById(ids.allowed).textContent = stats.allowed || 0;
    return stats;
  } catch (e) {
    return null;
  }
}

document.addEventListener("DOMContentLoaded", pingStatus);

/* ---------------------------------------------------------------------
   Toast notifications — success / warning / error / info
--------------------------------------------------------------------- */
function _toastRoot() {
  let root = document.getElementById("toastRoot");
  if (!root) {
    root = document.createElement("div");
    root.id = "toastRoot";
    root.className = "toast-root";
    document.body.appendChild(root);
  }
  return root;
}
const _TOAST_ICON = { success: "✓", warning: "!", error: "✕", info: "i" };
function showToast(message, type = "info", timeoutMs = 4500) {
  const root = _toastRoot();
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span class="toast-icon">${_TOAST_ICON[type] || "i"}</span>
    <span class="toast-msg">${escapeHtml(message)}</span>
    <button class="toast-close" aria-label="Dismiss">×</button>`;
  el.querySelector(".toast-close").onclick = () => _dismissToast(el);
  root.appendChild(el);
  requestAnimationFrame(() => el.classList.add("in"));
  if (timeoutMs) setTimeout(() => _dismissToast(el), timeoutMs);
  return el;
}
function _dismissToast(el) {
  if (!el || !el.parentNode) return;
  el.classList.remove("in");
  el.classList.add("out");
  setTimeout(() => el.remove(), 220);
}

/* ---------------------------------------------------------------------
   Copy to clipboard — auto-attaches to every .code-block on the page
--------------------------------------------------------------------- */
async function copyToClipboard(text, btnEl) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); ta.remove();
    }
    if (btnEl) {
      const original = btnEl.textContent;
      btnEl.textContent = "Copied!";
      btnEl.classList.add("copied");
      setTimeout(() => { btnEl.textContent = original; btnEl.classList.remove("copied"); }, 1600);
    }
  } catch (e) {
    showToast("Couldn't copy to clipboard — copy manually instead.", "warning");
  }
}
function attachCopyButtons() {
  document.querySelectorAll("pre.code-block").forEach(pre => {
    if (pre.parentElement.classList.contains("code-wrap")) return; // already wired
    const wrap = document.createElement("div");
    wrap.className = "code-wrap";
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);
    const btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.type = "button";
    btn.textContent = "Copy";
    btn.onclick = () => copyToClipboard(pre.textContent, btn);
    wrap.appendChild(btn);
  });
}
document.addEventListener("DOMContentLoaded", attachCopyButtons);

/* ---------------------------------------------------------------------
   Malfunction / course-of-action card — for failures that need more
   than a toast: what broke, how bad, and what to do about it.
--------------------------------------------------------------------- */
function showMalfunction(containerId, { title, severity = "warning", whatWentWrong, recommendedAction, nextStep }) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const sevLabel = { error: "CRITICAL", warning: "WARNING", info: "INFO" }[severity] || "WARNING";
  el.innerHTML = `
    <div class="malfunction malfunction-${severity}">
      <div class="malfunction-head">
        <span class="malfunction-icon">${severity === "error" ? "✕" : severity === "warning" ? "!" : "i"}</span>
        <div class="malfunction-title">${escapeHtml(title)}</div>
        <span class="action-tag" style="background:var(--${severity === "error" ? "crit" : severity === "warning" ? "warn" : "accent"}-bg);color:var(--${severity === "error" ? "crit" : severity === "warning" ? "warn" : "accent"});">${sevLabel}</span>
      </div>
      <div class="malfunction-row"><b>What went wrong</b><span>${escapeHtml(whatWentWrong)}</span></div>
      ${recommendedAction ? `<div class="malfunction-row"><b>Recommended action</b><span>${escapeHtml(recommendedAction)}</span></div>` : ""}
      ${nextStep ? `<div class="malfunction-row"><b>Next step</b><span>${escapeHtml(nextStep)}</span></div>` : ""}
    </div>`;
  el.style.display = "block";
}
function clearMalfunction(containerId) {
  const el = document.getElementById(containerId);
  if (el) { el.style.display = "none"; el.innerHTML = ""; }
}

/* ---------------------------------------------------------------------
   Text highlighting — safe HTML-escaped keyword highlight for log search
--------------------------------------------------------------------- */
function highlightMatch(text, query) {
  const safe = escapeHtml(text == null ? "" : text);
  if (!query) return safe;
  const escQuery = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return safe.replace(new RegExp(`(${escQuery})`, "ig"), "<mark>$1</mark>");
}

/* ---------------------------------------------------------------------
   Pipeline stepper — Request -> Detection -> Evidence -> Risk -> Decision
--------------------------------------------------------------------- */
const STEP_DEFS = [
  { key: "request",  label: "Request" },
  { key: "detection", label: "Detection" },
  { key: "evidence", label: "Evidence" },
  { key: "risk",     label: "Risk" },
  { key: "decision", label: "Decision" },
  { key: "mitigation", label: "Mitigation" },
];

function renderStepper(containerId) {
  const el = document.getElementById(containerId);
  el.innerHTML = STEP_DEFS.map((s, i) => `
    <div class="step" data-step="${s.key}">
      <div class="node">${i + 1}</div>
      <div class="connector"></div>
      <div class="step-label">${s.label}</div>
    </div>`).join("");
}

/** Advance stepper up to `activeKey`, marking earlier ones done and later ones idle.
 *  finalState: null | "safe" | "flagged" — applied to the currently active node. */
function setStepper(containerId, activeKey, finalState) {
  const el = document.getElementById(containerId);
  const order = STEP_DEFS.map(s => s.key);
  const activeIdx = order.indexOf(activeKey);
  el.querySelectorAll(".step").forEach(node => {
    const idx = order.indexOf(node.dataset.step);
    node.classList.remove("active", "done", "flagged");
    if (idx < activeIdx) node.classList.add("done");
    else if (idx === activeIdx) {
      if (finalState) node.classList.add(finalState === "flagged" ? "flagged" : "done");
      else node.classList.add("active");
    }
  });
}

/* ---------------------------------------------------------------------
   Signal view — renders text with invisible/covert characters made visible
--------------------------------------------------------------------- */
const INVISIBLE_RANGES = [
  [0x200B, 0x200F], [0x202A, 0x202E], [0x2060, 0x2064],
  [0xFE00, 0xFE0F], [0xFEFF, 0xFEFF], [0x180E, 0x180E],
  [0xE0100, 0xE01EF], [0xE0000, 0xE007F], [0x00AD, 0x00AD],
  [0x115F, 0x1160], [0x2800, 0x2800], [0x3164, 0x3164], [0xFFA0, 0xFFA0],
];
function isInvisible(cp) {
  return INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

const _emojiish = (ch) => !!ch && (/[\p{So}\p{Sk}]/u.test(ch) || ch === "\uFE0E" || ch === "\uFE0F");

// Mirrors catch_engine._strip_benign: emoji selectors/ZWJ and Indic ZWJ/ZWNJ are legitimate,
// so the X-ray must not paint them as hidden payload (the backend would ALLOW them).
const _RTL = /[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFC]/;
function _isBenignInvisible(chars, i) {
  const ch = chars[i], cp = ch.codePointAt(0);
  const prev = chars[i - 1] || "", nxt = chars[i + 1] || "";
  const inv = (c) => !!c && isInvisible(c.codePointAt(0));
  if (cp >= 0xE0000 && cp <= 0xE007F) {  // tag letters inside a subdivision flag: 🏴 + tags + cancel tag
    const tl = (c) => !!c && c.codePointAt(0) >= 0xE0020 && c.codePointAt(0) <= 0xE007E;
    let k = cp === 0xE007F ? i - 1 : i; while (k > 0 && tl(chars[k])) k--;
    let e = i; while (e < chars.length && tl(chars[e])) e++;
    return chars[k] === "\u{1F3F4}" && e > k + 1 && e < chars.length && chars[e].codePointAt(0) === 0xE007F;
  }
  if (cp === 0x200E || cp === 0x200F) return !!prev && !inv(prev) && !inv(nxt) && (_RTL.test(prev) || _RTL.test(nxt));
  if (cp === 0x00AD) return !!prev && !!nxt && !inv(prev) && !inv(nxt);
  if (cp === 0xFEFF && i === 0) return true;
  if (cp === 0xFE0E || cp === 0xFE0F)
    return !!prev && !inv(prev) && !inv(nxt) && (_emojiish(prev) || "#*0123456789".includes(prev));
  if (cp === 0x200D && _emojiish(prev) && _emojiish(nxt)) return true;
  if (cp === 0x200C || cp === 0x200D)
    return !!prev && !!nxt && prev.codePointAt(0) > 0x7F && nxt.codePointAt(0) > 0x7F &&
           /[\p{L}\p{M}]/u.test(prev) && /[\p{L}\p{M}]/u.test(nxt);
  return false;
}

function renderSignalView(containerId, text) {
  const el = document.getElementById(containerId);
  const chars = Array.from(text);
  let html = "";
  let hiddenCount = 0;
  chars.forEach((ch, i) => {
    const cp = ch.codePointAt(0);
    if (isInvisible(cp) && !_isBenignInvisible(chars, i)) {
      hiddenCount++;
      html += `<span class="hidden-mark" title="U+${cp.toString(16).toUpperCase().padStart(4,'0')} — invisible character">${hiddenCount}</span>`;
    } else {
      html += `<span class="clean-text">${escapeHtml(ch)}</span>`;
    }
  });
  el.innerHTML = html || '<span class="clean-text">(empty)</span>';
  return hiddenCount;
}

/* Decode reveal: the payload resolves out of noise, left to right. Skipped under reduced-motion. */
function revealDecoded(el, prefix, text, suffix) {
  const chars = Array.from(text || "");
  if (!chars.length || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    el.textContent = prefix + chars.join("") + suffix; return;
  }
  const glyphs = "!<>-_/[]{}=+*^?#0123456789abcdef", t0 = performance.now(), total = 900;
  (function frame(now) {
    const p = Math.min(1, (now - t0) / total), done = Math.floor(p * chars.length);
    el.textContent = prefix + chars.map((c, i) =>
      i < done || c === " " ? c : glyphs[Math.floor(Math.random() * glyphs.length)]).join("") + (p === 1 ? suffix : "");
    if (p < 1) requestAnimationFrame(frame);
  })(t0);
}

/* ---------------------------------------------------------------------
   Evidence waterfall — visual log-odds contribution bars
--------------------------------------------------------------------- */
function renderWaterfall(containerId, evidence) {
  const el = document.getElementById(containerId);
  if (!evidence || !evidence.length) {
    el.innerHTML = '<div style="color:var(--text-faint);font-size:12px;">No scored signals — nothing contributed to the risk estimate.</div>';
    return;
  }
  const maxAbs = Math.max(1, ...evidence.map(e => Math.abs(e.log_odds_delta)));
  el.innerHTML = evidence.map(e => {
    const pct = Math.min(100, (Math.abs(e.log_odds_delta) / maxAbs) * 100);
    const neg = e.log_odds_delta < 0 ? "negative" : "";
    return `<div class="waterfall-row">
      <div class="waterfall-label" title="${escapeHtml(e.signal)}">${escapeHtml(e.signal)}</div>
      <div class="waterfall-track"><div class="waterfall-fill ${neg}" style="width:${pct}%"></div></div>
      <div class="waterfall-val">${e.log_odds_delta > 0 ? "+" : ""}${e.log_odds_delta} · ${e.likelihood_ratio}×</div>
    </div>`;
  }).join("");
}

/* ---------------------------------------------------------------------
   Risk gauge — semi-circle SVG gauge
--------------------------------------------------------------------- */
function renderGauge(containerId, score) {
  const el = document.getElementById(containerId);
  const W = 160, H = 90, cx = 80, cy = 80, r = 64;
  const angle = Math.PI * (1 - Math.min(100, Math.max(0, score)) / 100);
  const x = cx + r * Math.cos(angle);
  const y = cy - r * Math.sin(angle);
  const color = score >= 50 ? "#BD5138" : score >= 15 ? "#C1903D" : "#4C9A6E";
  el.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" style="width:160px;height:90px;overflow:visible;">
      <path d="M ${cx-r} ${cy} A ${r} ${r} 0 0 1 ${cx+r} ${cy}" fill="none" stroke="var(--border-strong)" stroke-width="10" stroke-linecap="round"/>
      <path d="M ${cx-r} ${cy} A ${r} ${r} 0 0 1 ${x} ${y}" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round"/>
      <circle cx="${x}" cy="${y}" r="5" fill="${color}"/>
    </svg>
    <div class="gauge-num" style="color:${color}">${score}</div>
    <div class="gauge-label">Risk score</div>`;
}

/* ---------------------------------------------------------------------
   Investigation timeline — expandable rows instead of a flat table
--------------------------------------------------------------------- */
function renderTimeline(containerId, rows) {
  const el = document.getElementById(containerId);
  if (!rows.length) {
    el.innerHTML = '<div style="color:var(--text-faint);font-size:12px;padding:10px 0;">No scans yet — run the live console to populate the trail.</div>';
    return;
  }
  el.innerHTML = `<div class="timeline">` + rows.map((r, i) => {
    const time = new Date(r.ts * 1000).toLocaleTimeString();
    const full = new Date(r.ts * 1000).toLocaleString();
    return `
    <div class="tl-item" id="tl-${i}">
      <div class="tl-dot action-${r.action}"></div>
      <div class="tl-row" onclick="document.getElementById('tl-${i}').classList.toggle('open')">
        <span class="tl-time">${time}</span>
        <span class="tl-preview">${escapeHtml(r.text_preview)}</span>
        <span class="tl-risk">${r.risk_score}</span>
        <span class="action-tag action-${r.action}">${r.action}</span>
        <span class="tl-chevron">▸</span>
      </div>
      <div class="tl-detail">
        <b>Timestamp:</b> ${full}<br>
        <b>Verdict:</b> ${escapeHtml(r.verdict)}<br>
        <b>Text length:</b> ${r.text_length} chars<br>
        <b>Client:</b> ${escapeHtml(r.client || "unauthenticated")}<br>
        ${r.decoded_message ? `<b>Decoded payload:</b> <span class="mono" style="color:var(--crit);">${escapeHtml(r.decoded_message)}</span>` : `<b>Decoded payload:</b> none`}
      </div>
    </div>`;
  }).join("") + `</div>`;
}
