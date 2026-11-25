"use strict";
(() => {
  const MAX_ROWS = 250;
  let rows = [];          // newest first
  let paused = false;
  let buffered = [];
  const arrivals = [];    // timestamps for the rate meter

  const filters = () => ({
    q: $("#f-q").value.trim(), protocol: $("#f-protocol").value, severity: $("#f-severity").value,
    predicted_class: $("#f-class").value, threats_only: $("#f-threats").checked ? "1" : "",
  });

  function matches(e, f) {
    if (f.protocol && e.protocol !== f.protocol) return false;
    if (f.severity && (e.severity || "none") !== f.severity) return false;
    if (f.predicted_class && e.predicted_class !== f.predicted_class) return false;
    if (f.threats_only && !e.is_threat) return false;
    if (f.q) {
      const q = f.q.toLowerCase();
      const hay = [e.src_ip, e.dst_ip, e.event_type, e.predicted_class, e.threat_category, e.log_source].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function rowHtml(e, isNew) {
    const cls = [isNew ? "flash" : "", e.severity === "critical" ? "row-critical" : e.is_threat ? "row-threat" : ""].join(" ");
    return `<tr class="clickable ${cls}" data-id="${esc(e._id || e.event_id)}">
      <td class="mono">${fmt.dt(e.event_time)}</td>
      <td>${badge.ip(e.src_ip)}<span class="text-muted mono">:${esc(e.src_port)}</span></td>
      <td>${badge.ip(e.dst_ip)}<span class="text-muted mono">:${esc(e.dst_port)}</span></td>
      <td>${esc(e.protocol)}</td><td>${esc(e.event_type)}${badge.origin(e)}</td><td class="text-muted">${esc(e.log_source)}</td>
      <td>${badge.cls(e.predicted_class)} ${e.ml_probability != null ? `<span class="text-muted small">${(e.ml_probability * 100).toFixed(0)}%</span>` : ""}</td>
      <td>${badge.score(e.anomaly_score)}</td><td>${badge.sev(e.severity)}</td></tr>`;
  }

  function render(newIds = new Set()) {
    const f = filters();
    const shown = rows.filter((e) => matches(e, f));
    setHTML("#live-body", shown.length ? shown.map((e) => rowHtml(e, newIds.has(e._id))).join("")
      : emptyRow(9, rows.length ? "No events match the filters" : "Waiting for events… start ingestion on the Log Ingestion page."));
    setText("#live-count", `${shown.length} shown / ${rows.length} received`);
  }

  function add(items) {
    const now = Date.now();
    items.forEach(() => arrivals.push(now));
    if (paused) { buffered = items.concat(buffered).slice(0, MAX_ROWS); $("#btn-pause").innerHTML = `<i class="bi bi-play-fill"></i> Resume (${buffered.length})`; return; }
    const fresh = items.sort((a, b) => (b.event_time || "").localeCompare(a.event_time || ""));
    rows = fresh.concat(rows).slice(0, MAX_ROWS);
    render(new Set(fresh.map((e) => e._id)));
  }

  async function initial() {
    try {
      const d = await api("/api/events/recent/?" + qs({ size: 150 }));
      rows = d.results;
      render();
    } catch (e) { setHTML("#live-body", errorRow(9, e)); }
  }

  async function showEvent(id) {
    const modal = bootstrap.Modal.getOrCreateInstance("#eventModal");
    setHTML("#eventModalBody", '<div class="text-center p-4"><div class="spinner-border text-info"></div></div>');
    modal.show();
    try {
      const e = await api(`/api/events/${encodeURIComponent(id)}/`);
      setHTML("#eventModalBody", `
        <dl class="kv mb-3">
          <dt>Event ID</dt><dd class="mono">${esc(e.event_id)}</dd>
          <dt>Time</dt><dd>${fmt.dt(e.event_time)} <span class="text-muted">(processed ${fmt.dt(e.processed_at)})</span></dd>
          <dt>Connection</dt><dd class="mono">${esc(e.src_ip)}:${esc(e.src_port)} → ${esc(e.dst_ip)}:${esc(e.dst_port)} (${esc(e.protocol)})</dd>
          <dt>Log source</dt><dd>${esc(e.log_source)} · Kafka topic <span class="mono">${esc(e.kafka_topic)}</span></dd>
          <dt>Prediction</dt><dd>${badge.cls(e.predicted_class)} · probability ${badge.prob(e.ml_probability)} · P(attack) ${badge.prob(e.attack_probability)}</dd>
          <dt>Anomaly score</dt><dd>${badge.score(e.anomaly_score)} <span class="text-muted small">(distance ÷ threshold, not a probability)</span></dd>
          <dt>Detection</dt><dd>${badge.sev(e.severity)} ${badge.methods(e.detection_methods)}</dd>
          ${e.alert_id ? `<dt>Alert</dt><dd><a href="/alerts/${esc(e.alert_id)}/">${esc(e.alert_id)}</a></dd>` : ""}
          ${e.is_simulated ? `<dt>Simulated</dt><dd><span class="sim-tag">simulated</span> ground-truth label: <span class="mono">${esc(e.true_label)}</span></dd>` : ""}
        </dl>
        <div class="form-label">Raw document (Elasticsearch)</div><pre class="json">${esc(JSON.stringify(e, null, 2))}</pre>`);
    } catch (err) { setHTML("#eventModalBody", `<div class="banner danger">${esc(err.message)}</div>`); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    initial();
    ["#f-protocol", "#f-severity", "#f-class", "#f-threats"].forEach((s) => $(s).addEventListener("change", () => render()));
    $("#f-q").addEventListener("input", debounce(() => render(), 200));
    $("#btn-pause").addEventListener("click", () => {
      paused = !paused;
      if (!paused) { rows = buffered.concat(rows).slice(0, MAX_ROWS); buffered = []; render(); }
      $("#btn-pause").innerHTML = paused ? '<i class="bi bi-play-fill"></i> Resume' : '<i class="bi bi-pause-fill"></i> Pause';
    });
    $("#btn-clear").addEventListener("click", () => { rows = []; render(); });
    $("#live-body").addEventListener("click", (e) => {
      if (e.target.closest("[data-ip]")) return;
      const tr = e.target.closest("tr[data-id]"); if (tr) showEvent(tr.dataset.id);
    });
    Realtime.on("events", (msg) => add(msg.items));
    setInterval(() => {
      const cut = Date.now() - 15000;
      while (arrivals.length && arrivals[0] < cut) arrivals.shift();
      setText("#rate", (arrivals.length / 15).toFixed(1) + " ev/s");
    }, 1000);
  });
})();
