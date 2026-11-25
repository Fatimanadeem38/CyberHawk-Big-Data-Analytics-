"use strict";
(() => {
  let range = "24h";
  const CAT_COLORS = { brute_force: "#ef4444", port_scan: "#eab308", dos: "#f97316", suspicious_frequency: "#a855f7",
                       unusual_volume: "#3b82f6", abnormal_auth: "#ec4899", unknown_anomaly: "#64748b" };

  const bar = (val, max, color = "#22d3ee") =>
    `<div class="progress" style="height:6px"><div class="progress-bar" style="width:${max ? (100 * val / max) : 0}%;background:${color}"></div></div>`;

  function render(d) {
    setText("#k-events", fmt.num(d.total_events));
    setText("#k-bytes", fmt.bytes(d.total_bytes));
    setText("#k-src", fmt.num(d.unique_sources));
    setText("#k-dst", fmt.num(d.unique_destinations));
    setText("#interval", d.interval);
    const longRange = ["7d", "30d", "all"].includes(range);
    const labels = d.traffic_over_time.map((b) => fmt.chartTime(b.t, longRange || range === "24h"));

    makeChart("c-traffic", {
      type: "bar",
      data: { labels, datasets: [
        { type: "line", label: "Events", data: d.traffic_over_time.map((b) => b.events), borderColor: SOC.colors.accent, backgroundColor: "rgba(34,211,238,.1)", fill: true, tension: .3, pointRadius: 0, yAxisID: "y" },
        { type: "line", label: "Threat events", data: d.traffic_over_time.map((b) => b.threats), borderColor: SOC.colors.critical, tension: .3, pointRadius: 0, yAxisID: "y" },
        { type: "bar", label: "Traffic volume (bytes)", data: d.traffic_over_time.map((b) => b.bytes), backgroundColor: "rgba(59,130,246,.35)", yAxisID: "y2" },
      ] },
      options: { interaction: { mode: "index", intersect: false },
        plugins: { tooltip: { callbacks: { label: (c) => c.dataset.yAxisID === "y2" ? `${c.dataset.label}: ${fmt.bytes(c.raw)}` : `${c.dataset.label}: ${fmt.num(c.raw)}` } } },
        scales: { y: { beginAtZero: true, title: { display: true, text: "events" } },
                  y2: { beginAtZero: true, position: "right", grid: { drawOnChartArea: false }, ticks: { callback: (v) => fmt.bytes(v) } } } },
    });

    const t = d.suspicious_trend;
    makeChart("c-suspicious", {
      type: "bar",
      data: { labels: t.labels.map((x) => fmt.chartTime(x, longRange || range === "24h")),
              datasets: Object.entries(t.series).map(([cat, vals]) => ({ label: fmt.label(cat), data: vals, backgroundColor: CAT_COLORS[cat] || "#64748b", stack: "s" })) },
      options: { scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } },
    });

    doughnut("c-protocols", d.protocols.map((x) => x.key), d.protocols.map((x) => x.count));
    doughnut("c-sources", d.log_sources.map((x) => fmt.label(x.key)), d.log_sources.map((x) => x.count));
    doughnut("c-status", d.network_status.map((x) => x.key), d.network_status.map((x) => x.count));
    makeChart("c-ports", {
      type: "bar",
      data: { labels: d.top_ports.map((x) => String(x.key)), datasets: [{ data: d.top_ports.map((x) => x.count), backgroundColor: "rgba(34,211,238,.6)", borderRadius: 3 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true } } },
    });

    const maxS = Math.max(1, ...d.top_sources.map((x) => x.count));
    setHTML("#top-src", d.top_sources.length ? d.top_sources.map((x, i) => `<tr><td class="text-muted">${i + 1}</td><td>${badge.ip(x.key)}</td><td>${fmt.num(x.count)}</td>
      <td>${x.threats ? `<span class="text-danger fw-semibold">${fmt.num(x.threats)}</span>` : "0"}</td><td>${fmt.bytes(x.bytes)}</td><td>${bar(x.count, maxS, x.threats ? "#f97316" : "#22d3ee")}</td></tr>`).join("") : emptyRow(6));
    const maxD = Math.max(1, ...d.top_destinations.map((x) => x.count));
    setHTML("#top-dst", d.top_destinations.length ? d.top_destinations.map((x, i) => `<tr><td class="text-muted">${i + 1}</td><td>${badge.ip(x.key)}</td><td>${fmt.num(x.count)}</td><td>${fmt.bytes(x.bytes)}</td><td>${bar(x.count, maxD, "#3b82f6")}</td></tr>`).join("") : emptyRow(5));
  }

  async function load() {
    try { render(await api(`/api/analytics/overview/?range=${range}`)); }
    catch (e) { toast(esc(e.message), "error", "Analytics unavailable"); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    segmented($("#range"), (v) => { range = v; load(); });
    $("#refresh").addEventListener("click", load);
    load();
    setInterval(() => { if (!document.hidden) load(); }, 30000);
  });
})();
