"use strict";
(() => {
  const ICONS = { "Kafka": "bi-collection", "Spark Streaming": "bi-lightning-charge", "Hadoop HDFS": "bi-hdd-stack",
                  "Elasticsearch": "bi-search", "MongoDB": "bi-database", "Django Backend": "bi-server", "Log Generator": "bi-broadcast" };

  const metric = (label, value) => value === undefined || value === null || value === "" ? "" :
    `<div class="metric"><span>${esc(label)}</span><span class="mono">${value}</span></div>`;

  function serviceMetrics(c) {
    const d = c.details || {};
    switch (c.name) {
      case "Kafka": return metric("Brokers", d.brokers) + metric("Ingestion rate", d.ingestion_rate_msgs_per_sec != null ? d.ingestion_rate_msgs_per_sec + " msg/s" : "measuring…") + metric("Messages produced", fmt.num(d.total_messages_produced));
      case "Spark Streaming": return metric("Application", d.application ? esc(d.application.app_name) : "UI not reachable") +
        metric("Input rate", d.input_rows_per_second != null ? fmt.dec(d.input_rows_per_second) + " rows/s" : null) +
        metric("Processing rate", d.processed_rows_per_second != null ? fmt.dec(d.processed_rows_per_second) + " rows/s" : null) +
        metric("Consumer lag", d.consumer_lag_offsets != null ? fmt.num(d.consumer_lag_offsets) + " offsets" : null) +
        metric("Duplicates removed", d.duplicates_removed != null ? fmt.num(d.duplicates_removed) : null) +
        metric("Last successful batch", d.last_successful_batch_at ? fmt.ago(d.last_successful_batch_at) : "never");
      case "Hadoop HDFS": return metric("Live DataNodes", d.live_datanodes) + metric("Used / capacity", `${fmt.bytes(d.capacity_used)} / ${fmt.bytes(d.capacity_total)}`) + metric("Files", fmt.num(d.files_total)) + metric("Version", esc(d.version || ""));
      case "Elasticsearch": return metric("Cluster", `${esc(d.cluster || "")} (${esc(d.cluster_status || "")})`) + metric("Version", esc(d.version || "")) + metric("Last indexed event", d.last_indexed_event_at ? fmt.ago(d.last_indexed_event_at) : "none yet");
      case "MongoDB": return metric("Version", esc(d.version || "")) + metric("Data size", fmt.bytes(d.database_size_bytes)) + metric("Collections", d.collections) + metric("Documents", fmt.num(d.documents));
      case "Django Backend": return metric("Django / Python", `${esc(d.django_version)} / ${esc(d.python_version)}`) + metric("Uptime", fmt.duration(d.uptime_seconds)) + metric("WebSocket clients", d.websocket_clients);
      case "Log Generator": return metric("Ingestion", d.running ? '<span class="text-success">running</span>' : "paused") + metric("Rate", d.rate != null ? d.rate + " ev/s" : null) + metric("Events sent", fmt.num(d.events_sent)) + metric("Failed", fmt.num(d.events_failed)) + metric("Last heartbeat", d.last_heartbeat_at ? fmt.ago(d.last_heartbeat_at) : null);
      default: return "";
    }
  }

  function render(h) {
    const ov = $("#overall");
    ov.className = "banner mb-3 " + (h.overall === "up" ? "ok" : h.overall === "degraded" ? "warn" : "danger");
    ov.querySelector(".dot").className = "dot " + (h.overall === "up" ? "ok" : h.overall === "degraded" ? "warn" : "down");
    ov.querySelector("span:nth-child(2)").textContent = h.overall === "up" ? "All components are operational"
      : h.overall === "degraded" ? "Some components are degraded" : "One or more components are down";
    setText("#checked", "checked " + fmt.time(h.checked_at));

    setHTML("#services", h.components.map((c) => `
      <div class="col-md-6 col-xl-3"><div class="card-soc svc-card">
        <div class="svc-name mb-1"><i class="bi ${ICONS[c.name] || "bi-gear"} text-info"></i>${esc(c.name)}<span class="ms-auto">${badge.dot(c.status)}</span></div>
        <div class="small mb-2 ${c.status === "up" ? "text-success" : c.status === "degraded" ? "text-warning" : "text-danger"}">${esc(c.status.toUpperCase())} · <span class="text-muted">${esc(c.message)}</span></div>
        ${serviceMetrics(c)}
      </div></div>`).join(""));

    const byName = Object.fromEntries(h.components.map((c) => [c.name, c.details || {}]));
    const topics = byName["Kafka"].topics || {};
    setHTML("#topics", Object.keys(topics).length ? Object.entries(topics).map(([t, v]) => `<tr><td class="mono">${esc(t)}</td>
      <td>${v.exists ? v.partitions : '<span class="text-danger">missing</span>'}</td><td>${fmt.num(v.end_offset_total)}</td><td>${fmt.num(v.messages_retained)}</td></tr>`).join("") : emptyRow(4, "Kafka not reachable"));

    const hd = byName["Hadoop HDFS"];
    if (hd.capacity_total) {
      const pct = 100 * hd.capacity_used / hd.capacity_total;
      setHTML("#hdfs-cap", `<div class="d-flex justify-content-between small mb-1"><span>DFS used ${fmt.bytes(hd.capacity_used)}</span><span class="text-muted">remaining ${fmt.bytes(hd.capacity_remaining)}</span></div>
        <div class="progress" style="height:8px"><div class="progress-bar bg-info" style="width:${Math.max(pct, 0.5)}%"></div></div>`);
    } else setHTML("#hdfs-cap", '<div class="text-muted small">HDFS not reachable</div>');
    const folders = hd.folders || {};
    setHTML("#hdfs", Object.keys(folders).length ? Object.entries(folders).map(([f, v]) => `<tr><td class="mono">${esc(f)}</td><td>${fmt.num(v.files)}</td><td>${fmt.bytes(v.bytes)}</td></tr>`).join("") : emptyRow(3));

    const idx = byName["Elasticsearch"].indices || {};
    setHTML("#indices", Object.keys(idx).length ? Object.entries(idx).sort().map(([n, v]) => `<tr><td class="mono">${esc(n)}</td>
      <td>${badge.dot(v.health === "green" ? "up" : v.health === "yellow" ? "degraded" : "down")} ${esc(v.health)}</td><td>${fmt.num(v.docs)}</td><td>${fmt.bytes(v.size_bytes)}</td></tr>`).join("") : emptyRow(4));
  }

  async function loadPipeline() {
    try {
      const d = await api("/api/system/pipeline/?size=120");
      const b = d.batches;
      makeChart("c-spark", {
        type: "bar",
        data: { labels: b.map((x) => fmt.chartTime(x.timestamp)), datasets: [
          { type: "bar", label: "Events per batch", data: b.map((x) => x.num_input_rows), backgroundColor: "rgba(34,211,238,.5)", yAxisID: "y" },
          { type: "bar", label: "Threats per batch", data: b.map((x) => x.threats_in_batch), backgroundColor: "rgba(239,68,68,.6)", yAxisID: "y" },
          { type: "line", label: "Batch duration (ms)", data: b.map((x) => x.batch_duration_ms), borderColor: "#eab308", pointRadius: 0, tension: .3, yAxisID: "y2" },
        ] },
        options: { interaction: { mode: "index", intersect: false },
          scales: { y: { beginAtZero: true }, y2: { beginAtZero: true, position: "right", grid: { drawOnChartArea: false }, title: { display: true, text: "ms" } } } },
      });
    } catch (e) { /* shown in service card */ }
  }

  async function loadAudit() {
    if (!$("#audit")) return;
    try {
      const rows = await api("/api/system/audit/?size=50");
      setHTML("#audit", rows.length ? rows.map((r) => `<tr><td class="small">${fmt.dt(r.created_at)}</td><td>${esc(r.username)}</td><td>${esc(fmt.label(r.action))}</td>
        <td class="mono small">${esc(r.target_type)} ${esc(r.target_id)}</td><td class="mono small">${esc(r.ip_address || "")}</td>
        <td class="small text-muted text-truncate" style="max-width:280px">${esc(JSON.stringify(r.details || {}))}</td></tr>`).join("") : emptyRow(6));
    } catch (e) { setHTML("#audit", errorRow(6, e)); }
  }

  async function load() {
    try { render(await api("/api/system/health/")); }
    catch (e) { setHTML("#services", `<div class="col-12"><div class="banner danger"><i class="bi bi-x-octagon"></i>${esc(e.message)}</div></div>`); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    load(); loadPipeline(); loadAudit();
    setInterval(() => { if (!document.hidden) { load(); loadPipeline(); } }, 10000);
    setInterval(() => { if (!document.hidden) loadAudit(); }, 30000);
  });
})();
