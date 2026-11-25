/* =====================================================================
   Shared helpers for every page: API calls, formatting, badges, charts
   ===================================================================== */
"use strict";

const SOC = {
  colors: {
    critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", informational: "#64748b",
    accent: "#22d3ee", blue: "#3b82f6", muted: "#8392ab", grid: "rgba(148,163,184,.08)",
  },
  palette: ["#22d3ee", "#3b82f6", "#a855f7", "#f97316", "#eab308", "#22c55e", "#ef4444", "#14b8a6", "#ec4899", "#64748b"],
  severityOrder: ["critical", "high", "medium", "low", "informational"],
};

/* ---------------- API ---------------- */
function getCookie(name) {
  const m = document.cookie.match("(^|;)\\s*" + name + "\\s*=\\s*([^;]+)");
  return m ? decodeURIComponent(m.pop()) : "";
}

class ApiError extends Error {
  constructor(message, status, data) { super(message); this.status = status; this.data = data; }
}

async function api(url, { method = "GET", body = null, form = null } = {}) {
  const opts = { method, credentials: "same-origin", headers: { "Accept": "application/json" } };
  if (method !== "GET") opts.headers["X-CSRFToken"] = getCookie("csrftoken");
  if (form) opts.body = form;
  else if (body !== null) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(url, opts); }
  catch (e) { throw new ApiError("Cannot reach the web server. Is the Django container running?", 0); }
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (res.status === 401 || (res.status === 403 && data && /credentials/i.test(data.detail || ""))) {
    window.location.href = "/login/?next=" + encodeURIComponent(location.pathname);
    throw new ApiError("Session expired - please sign in again.", res.status, data);
  }
  if (!res.ok) {
    let msg = (data && (data.detail || data.error)) || `Request failed (${res.status})`;
    if (data && !data.detail && typeof data === "object") msg = Object.values(data).flat().join(" ");
    throw new ApiError(msg, res.status, data);
  }
  return data;
}

function qs(params) {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "" && v !== false) p.set(k, v); });
  return p.toString();
}

/* ---------------- formatting ---------------- */
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = {
  num(n) { return n === null || n === undefined ? "–" : Number(n).toLocaleString(); },
  dec(n, d = 2) { return n === null || n === undefined || isNaN(n) ? "–" : Number(n).toFixed(d); },
  pct(n, d = 1) { return n === null || n === undefined ? "–" : Number(n).toFixed(d) + "%"; },
  pct01(n, d = 1) { return n === null || n === undefined ? "–" : (Number(n) * 100).toFixed(d) + "%"; },
  bytes(b) {
    if (b === null || b === undefined) return "–";
    const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; b = Number(b);
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(i ? 1 : 0) + " " + u[i];
  },
  time(iso) { if (!iso) return "–"; const d = new Date(iso); return isNaN(d) ? esc(iso) : d.toLocaleTimeString([], { hour12: false }); },
  dt(iso) {
    if (!iso) return "–"; const d = new Date(iso); if (isNaN(d)) return esc(iso);
    return d.toLocaleDateString([], { year: "numeric", month: "short", day: "2-digit" }) + " " + d.toLocaleTimeString([], { hour12: false });
  },
  ago(iso) {
    if (!iso) return "–"; const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 5) return "just now"; if (s < 60) return s + "s ago"; if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago"; return Math.floor(s / 86400) + "d ago";
  },
  duration(sec) { if (sec === null || sec === undefined) return "–"; sec = Math.round(sec);
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    return (d ? d + "d " : "") + (h ? h + "h " : "") + m + "m"; },
  label(s) { return String(s ?? "").replace(/_/g, " "); },
  chartTime(iso, withDate = false) {
    const d = new Date(iso);
    return withDate ? d.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false })
                    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  },
};

/* ---------------- badges ---------------- */
const badge = {
  sev(s) { s = s || "none"; return `<span class="sev sev-${esc(s)}">${esc(s === "none" ? "none" : s)}</span>`; },
  status(s) { s = s || "new"; return `<span class="st st-${esc(s)}">${esc(fmt.label(s))}</span>`; },
  cls(c) { if (!c) return '<span class="text-muted">–</span>'; return `<span class="cls ${c === "normal" ? "cls-normal" : ""}">${esc(c)}</span>`; },
  methods(list) { return (list || []).map((m) => `<span class="method">${esc(m.replace("rule:", "rule: ").replace("ml_random_forest", "ML · RF").replace("anomaly_kmeans", "Anomaly · KMeans"))}</span>`).join(""); },
  sim(v) { return v ? ' <span class="sim-tag" title="Simulated test data">sim</span>' : ""; },
  origin(e) {
    if (e.is_simulated) return badge.sim(true);
    if (e.log_source === "unsw_nb15") return ' <span class="real-tag" title="Real flow replayed from the UNSW-NB15 dataset">real</span>';
    return "";
  },
  ip(ip) { return ip ? `<a href="#" class="ip" data-ip="${esc(ip)}">${esc(ip)}</a>` : "–"; },
  score(v, max = 3) {
    if (v === null || v === undefined) return '<span class="text-muted">–</span>';
    const w = Math.min(100, (Number(v) / max) * 100);
    return `<span class="score-bar"><span style="width:${w}%"></span></span><span class="mono">${Number(v).toFixed(2)}</span>`;
  },
  prob(v) { return v === null || v === undefined ? '<span class="text-muted">–</span>' : `<span class="mono">${(Number(v) * 100).toFixed(1)}%</span>`; },
  dot(status) { return `<span class="dot ${status === "up" ? "ok" : status === "degraded" ? "warn" : "down"}"></span>`; },
};

/* ---------------- UI helpers ---------------- */
function toast(message, type = "info", title = "") {
  const icons = { info: "bi-info-circle text-info", success: "bi-check-circle text-success", error: "bi-x-octagon text-danger",
                  warn: "bi-exclamation-triangle text-warning", alert: "bi-bell-fill text-danger" };
  const el = document.createElement("div");
  el.className = "toast align-items-center";
  el.innerHTML = `<div class="toast-body d-flex gap-2"><i class="bi ${icons[type] || icons.info} fs-5"></i>
    <div>${title ? `<div class="fw-semibold">${esc(title)}</div>` : ""}<div class="small">${message}</div></div>
    <button type="button" class="btn-close ms-auto" data-bs-dismiss="toast"></button></div>`;
  document.getElementById("toasts").appendChild(el);
  const t = new bootstrap.Toast(el, { delay: type === "error" ? 8000 : 5000 });
  el.addEventListener("hidden.bs.toast", () => el.remove());
  t.show();
}

function debounce(fn, ms = 300) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
function setHTML(sel, html) { const el = typeof sel === "string" ? $(sel) : sel; if (el) el.innerHTML = html; }
function setText(sel, text) { const el = typeof sel === "string" ? $(sel) : sel; if (el) el.textContent = text; }
function emptyRow(cols, text = "No data yet") { return `<tr><td colspan="${cols}" class="empty"><i class="bi bi-inbox fs-4 d-block mb-1"></i>${esc(text)}</td></tr>`; }
function errorRow(cols, err) { return `<tr><td colspan="${cols}" class="empty text-danger"><i class="bi bi-exclamation-octagon fs-4 d-block mb-1"></i>${esc(err.message || err)}</td></tr>`; }
const isAdmin = () => document.body.dataset.role === "admin";

function segmented(container, onChange) {
  $$("button", container).forEach((b) => b.addEventListener("click", () => {
    $$("button", container).forEach((x) => x.classList.remove("active"));
    b.classList.add("active"); onChange(b.dataset.value);
  }));
}

function pagination(container, page, size, total, onPage) {
  const pages = Math.max(1, Math.ceil(Math.min(total, 10000) / size));
  if (pages <= 1) { container.innerHTML = ""; return; }
  const items = [];
  const add = (p, label, disabled = false, active = false) =>
    items.push(`<li class="page-item ${disabled ? "disabled" : ""} ${active ? "active" : ""}"><a class="page-link" href="#" data-p="${p}">${label}</a></li>`);
  add(page - 1, "‹", page <= 1);
  const from = Math.max(1, page - 2), to = Math.min(pages, page + 2);
  if (from > 1) add(1, "1"); if (from > 2) add(page, "…", true);
  for (let p = from; p <= to; p++) add(p, p, false, p === page);
  if (to < pages - 1) add(page, "…", true); if (to < pages) add(pages, pages);
  add(page + 1, "›", page >= pages);
  container.innerHTML = `<ul class="pagination pagination-sm mb-0">${items.join("")}</ul>`;
  $$("a", container).forEach((a) => a.addEventListener("click", (e) => {
    e.preventDefault(); const p = Number(a.dataset.p); if (p >= 1 && p <= pages && p !== page) onPage(p);
  }));
}

/* ---------------- Chart.js defaults ---------------- */
/* read a colour from the current theme (see css/soc.css) */
function cssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback || "";
}

if (window.Chart) {
  Chart.defaults.color = cssVar("--chart-text", "#8797b2");
  Chart.defaults.borderColor = cssVar("--chart-grid", "rgba(148,163,184,.09)");
  Chart.defaults.font.family = "Inter, system-ui, sans-serif";
  Chart.defaults.font.size = 11;
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.boxHeight = 10;
  Chart.defaults.plugins.tooltip.backgroundColor = "#0b1626";
  Chart.defaults.plugins.tooltip.titleColor = "#ffffff";
  Chart.defaults.plugins.tooltip.bodyColor = "#e3eaf5";
  Chart.defaults.plugins.tooltip.borderColor = "#253852";
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
  Chart.defaults.maintainAspectRatio = false;
  Chart.defaults.animation.duration = 400;
}

function makeChart(canvasId, config) {
  const el = document.getElementById(canvasId);
  if (!el) return null;
  const existing = Chart.getChart(el);
  if (existing) existing.destroy();
  return new Chart(el, config);
}

function doughnut(canvasId, labels, values, colors) {
  return makeChart(canvasId, {
    type: "doughnut",
    data: { labels, datasets: [{ data: values, backgroundColor: colors || SOC.palette, borderColor: cssVar("--surface", "#0d1829"), borderWidth: 2 }] },
    options: { cutout: "62%", plugins: { legend: { position: "right" } } },
  });
}

function updateChart(chart, labels, datasets) {
  if (!chart) return;
  chart.data.labels = labels;
  datasets.forEach((d, i) => { if (chart.data.datasets[i]) chart.data.datasets[i].data = d; });
  chart.update("none");
}

/* ---------------- IP profile modal (click on any IP) ---------------- */
async function showIpProfile(ip) {
  const modal = bootstrap.Modal.getOrCreateInstance("#ipModal");
  setText("#ipModalTitle", ip);
  setHTML("#ipModalBody", '<div class="text-center p-4"><div class="spinner-border text-info"></div></div>');
  modal.show();
  try {
    const d = await api(`/api/events/by-ip/${encodeURIComponent(ip)}/`);
    const list = (arr) => arr.length ? arr.map((x) => `<div class="d-flex justify-content-between"><span class="mono">${esc(x.key)}</span><span class="text-muted">${fmt.num(x.count)}</span></div>`).join("") : '<span class="text-muted">none</span>';
    setHTML("#ipModalBody", `
      <div class="row g-3 mb-3">
        <div class="col-md-3"><div class="metric-tile"><div class="v">${fmt.num(d.total_events)}</div><div class="l">events</div></div></div>
        <div class="col-md-3"><div class="metric-tile"><div class="v">${fmt.num(d.as_source)}</div><div class="l">as source</div></div></div>
        <div class="col-md-3"><div class="metric-tile"><div class="v">${fmt.num(d.as_destination)}</div><div class="l">as destination</div></div></div>
        <div class="col-md-3"><div class="metric-tile"><div class="v">${fmt.num(d.alerts.length)}</div><div class="l">alerts</div></div></div>
      </div>
      <div class="row g-3 mb-3 small">
        <div class="col-md-3"><div class="form-label">First / last seen</div>${fmt.dt(d.first_seen)}<br>${fmt.dt(d.last_seen)}</div>
        <div class="col-md-3"><div class="form-label">Top destinations</div>${list(d.top_destinations)}</div>
        <div class="col-md-3"><div class="form-label">Top destination ports</div>${list(d.top_ports)}</div>
        <div class="col-md-3"><div class="form-label">Threat categories</div>${list(d.threat_categories)}</div>
      </div>
      <h6 class="mt-3">Alerts</h6>
      <div class="table-scroll short"><table class="table table-soc table-hover"><thead><tr><th>Severity</th><th>Category</th><th>Source</th><th>Events</th><th>Last seen</th><th>Status</th></tr></thead><tbody>
      ${d.alerts.length ? d.alerts.map((a) => `<tr class="clickable" onclick="location.href='/alerts/${esc(a._id)}/'"><td>${badge.sev(a.severity)}</td><td>${esc(fmt.label(a.threat_category))}</td><td class="mono">${esc(a.src_ip)}</td><td>${fmt.num(a.event_count)}</td><td>${fmt.dt(a.last_seen)}</td><td>${badge.status(a.status)}</td></tr>`).join("") : emptyRow(6, "No alerts for this IP")}
      </tbody></table></div>
      <h6 class="mt-3">Recent events</h6>
      <div class="table-scroll short"><table class="table table-soc"><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Type</th><th>Prediction</th><th>Severity</th></tr></thead><tbody>
      ${d.recent_events.length ? d.recent_events.map((e) => `<tr><td>${fmt.dt(e.event_time)}</td><td class="mono">${esc(e.src_ip)}:${esc(e.src_port)}</td><td class="mono">${esc(e.dst_ip)}:${esc(e.dst_port)}</td><td>${esc(e.protocol)}</td><td>${esc(e.event_type)}</td><td>${badge.cls(e.predicted_class)}</td><td>${badge.sev(e.severity)}</td></tr>`).join("") : emptyRow(7)}
      </tbody></table></div>
      <div class="mt-3"><a class="btn btn-ghost btn-sm" href="/history/?q=${encodeURIComponent(ip)}"><i class="bi bi-search me-1"></i>Search all history for this IP</a></div>`);
  } catch (e) {
    setHTML("#ipModalBody", `<div class="banner danger"><i class="bi bi-x-octagon"></i>${esc(e.message)}</div>`);
  }
}

document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-ip]");
  if (a) { e.preventDefault(); e.stopPropagation(); showIpProfile(a.dataset.ip); }
});

/* ---------------- clock ---------------- */
(function clock() {
  const el = document.getElementById("clock");
  if (!el) return;
  const tick = () => { const d = new Date(); el.textContent = d.toLocaleTimeString([], { hour12: false }) + " local · " + d.toISOString().substring(11, 19) + " UTC"; };
  tick(); setInterval(tick, 1000);
})();
