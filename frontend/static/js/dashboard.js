"use strict";
(() => {
  let range = "24h";
  let charts = {};

  function initCharts() {
    charts.timeline = makeChart("c-timeline", {
      type: "line",
      data: { labels: [], datasets: [
        { label: "Events / min", data: [], borderColor: SOC.colors.accent, backgroundColor: "rgba(34,211,238,.12)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
        { label: "Threat events / min", data: [], borderColor: SOC.colors.critical, backgroundColor: "rgba(239,68,68,.12)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
      ] },
      options: { interaction: { mode: "index", intersect: false }, scales: { y: { beginAtZero: true } } },
    });
    charts.traffic = makeChart("c-traffic", {
      type: "bar",
      data: { labels: [], datasets: [{ label: "Bytes", data: [], backgroundColor: "rgba(59,130,246,.55)", borderRadius: 3 }] },
      options: { plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => fmt.bytes(c.raw) } } },
                 scales: { y: { beginAtZero: true, ticks: { callback: (v) => fmt.bytes(v) } } } },
    });
    charts.threats = doughnut("c-threats", [], []);
    charts.severity = makeChart("c-severity", {
      type: "bar",
      data: { labels: SOC.severityOrder, datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: SOC.severityOrder.map((s) => SOC.colors[s]), borderRadius: 4 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } },
    });
  }

  function render(d) {
    $("#dash-error").classList.add("d-none");
    setText("#k-total", fmt.num(d.total_events_all_time));
    setText("#k-range-events", fmt.num(d.events_in_range));
    setText("#k-threats", fmt.num(d.threat_events));
    setText("#k-threat-rate", fmt.pct(d.threat_rate));
    setText("#k-critical", fmt.num(d.critical_alerts));
    setText("#k-high", fmt.num(d.high_alerts));
    setText("#k-open", fmt.num(d.open_alerts));
    setText("#k-normal", fmt.num(d.normal_events));
    setText("#k-anomaly", fmt.pct(d.anomaly_rate, 2));
    setText("#k-anomaly-n", fmt.num(d.anomaly_events));
    setText("#k-alerts", fmt.num(d.alerts_in_range));
    setText("#k-bytes", fmt.bytes(d.traffic_bytes));

    const labels = d.timeline.map((b) => fmt.chartTime(b.t));
    updateChart(charts.timeline, labels, [d.timeline.map((b) => b.events), d.timeline.map((b) => b.threats)]);
    updateChart(charts.traffic, labels, [d.timeline.map((b) => b.bytes)]);

    const td = d.threat_distribution;
    charts.threats.data.labels = td.length ? td.map((x) => fmt.label(x.key)) : ["no threats"];
    charts.threats.data.datasets[0].data = td.length ? td.map((x) => x.count) : [1];
    charts.threats.data.datasets[0].backgroundColor = td.length ? SOC.palette : [cssVar("--line", "#1a2a42")];
    charts.threats.update("none");

    const sev = Object.fromEntries(d.severity_distribution.map((x) => [x.key, x.count]));
    updateChart(charts.severity, SOC.severityOrder, [SOC.severityOrder.map((s) => sev[s] || 0)]);

    setHTML("#recent-alerts", d.recent_alerts.length ? d.recent_alerts.map((a) => `
      <tr class="clickable ${a.severity === "critical" ? "row-critical" : ""}" onclick="location.href='/alerts/${esc(a._id)}/'">
        <td>${badge.sev(a.severity)}</td><td>${esc(fmt.label(a.threat_category))}${badge.sim(a.is_simulated)}</td>
        <td>${badge.ip(a.src_ip)}</td><td>${badge.ip(a.dst_ip)}</td><td>${fmt.num(a.event_count)}</td>
        <td>${badge.methods(a.detection_methods)}</td><td title="${esc(a.last_seen)}">${fmt.ago(a.last_seen)}</td><td>${badge.status(a.status)}</td>
      </tr>`).join("") : emptyRow(8, "No alerts yet. Start log ingestion on the Log Ingestion page."));
  }

  async function load() {
    try { render(await api(`/api/dashboard/stats/?range=${range}`)); }
    catch (e) {
      const box = $("#dash-error"); box.classList.remove("d-none"); setText($("span", box), e.message);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    segmented($("#range"), (v) => { range = v; load(); });
    load();
    // the WebSocket sends 24h stats every few seconds; for other ranges we re-query
    Realtime.on("stats", (msg) => { if (range === "24h") render(msg.data); else load(); });
  });
})();
