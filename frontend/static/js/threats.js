"use strict";
(() => {
  let page = 1;
  const SIZE = 50;

  const params = () => ({
    range: $("#f-range").value, threat_category: $("#f-category").value, severity: $("#f-severity").value,
    method: $("#f-method").value, q: $("#f-q").value.trim(), page, size: SIZE,
  });

  async function load() {
    try {
      const d = await api("/api/detections/?" + qs(params()));
      setText("#total", `${fmt.num(d.total)} detections`);
      setHTML("#body", d.results.length ? d.results.map((e) => `
        <tr class="clickable ${e.severity === "critical" ? "row-critical" : "row-threat"}" data-id="${esc(e._id)}">
          <td class="mono" title="event time ${esc(e.event_time)}">${fmt.dt(e.processed_at)}</td>
          <td>${esc(fmt.label(e.threat_category))}${badge.origin(e)}</td>
          <td>${badge.sev(e.severity)}</td><td>${badge.methods(e.detection_methods)}</td>
          <td>${badge.cls(e.predicted_class)} ${badge.prob(e.ml_probability)}</td>
          <td>${badge.score(e.anomaly_score)}</td>
          <td>${badge.ip(e.src_ip)}</td><td>${badge.ip(e.dst_ip)}<span class="text-muted mono">:${esc(e.dst_port)}</span></td>
          <td class="text-muted">${esc(e.event_type)}</td></tr>`).join("") : emptyRow(9, "No threats detected for these filters."));
      pagination($("#pager"), d.page, d.size, d.total, (p) => { page = p; load(); });
      const chips = [];
      d.facets.categories.forEach((c) => chips.push(`<span class="chip" data-cat="${esc(c.key)}">${esc(fmt.label(c.key))} <span class="n">${fmt.num(c.count)}</span></span>`));
      d.facets.methods.forEach((c) => chips.push(`<span class="chip" data-method="${esc(c.key.startsWith("rule:") ? "rule:" : c.key)}">${badge.methods([c.key])} <span class="n">${fmt.num(c.count)}</span></span>`));
      setHTML("#facets", chips.join(""));
    } catch (e) { setHTML("#body", errorRow(9, e)); }
  }

  async function showDetail(id) {
    const oc = bootstrap.Offcanvas.getOrCreateInstance("#detail");
    setHTML("#detailBody", '<div class="text-center p-4"><div class="spinner-border text-info"></div></div>');
    oc.show();
    try {
      const { detection: e, alert: a } = await api(`/api/detections/${encodeURIComponent(id)}/`);
      setHTML("#detailBody", `
        <div class="mb-3">${badge.sev(e.severity)} <span class="ms-2 fw-semibold">${esc(fmt.label(e.threat_category))}</span>${badge.origin(e)}</div>
        <dl class="kv mb-3">
          <dt>Event time</dt><dd>${fmt.dt(e.event_time)}</dd>
          <dt>Detected at</dt><dd>${fmt.dt(e.processed_at)} <span class="text-muted">(batch ${esc(e.batch_id)})</span></dd>
          <dt>Source</dt><dd>${badge.ip(e.src_ip)} <span class="mono text-muted">:${esc(e.src_port)}</span></dd>
          <dt>Destination</dt><dd>${badge.ip(e.dst_ip)} <span class="mono text-muted">:${esc(e.dst_port)}</span> ${esc(e.protocol)}</dd>
          <dt>Event</dt><dd>${esc(e.event_type)} · ${esc(e.log_source)} · status ${esc(e.network_status)}</dd>
          <dt>Detection models</dt><dd>${badge.methods(e.detection_methods)}</dd>
        </dl>
        <h6 class="text-info">Model outputs</h6>
        <dl class="kv mb-3">
          <dt>Model A (Random Forest)</dt><dd>${badge.cls(e.predicted_class)} with probability ${badge.prob(e.ml_probability)}<br><span class="text-muted small">P(any attack) = ${badge.prob(e.attack_probability)} · tree-vote share</span></dd>
          <dt>Model B (KMeans anomaly)</dt><dd>${badge.score(e.anomaly_score)} ${e.is_anomaly ? '<span class="sev sev-medium">anomalous</span>' : '<span class="text-muted small">within normal range</span>'}<br><span class="text-muted small">score = distance to nearest normal cluster ÷ 99th-percentile threshold (not a probability)</span></dd>
          <dt>Rule</dt><dd>${e.rule_category ? esc(fmt.label(e.rule_category)) : '<span class="text-muted">no rule fired</span>'}</dd>
        </dl>
        <h6 class="text-info">Behaviour of the source in its ${'10'} s window</h6>
        <dl class="kv mb-3">
          <dt>Connections</dt><dd>${fmt.num(e.win_conn_count)}</dd>
          <dt>Failed logins</dt><dd>${fmt.num(e.win_failed_logins)}</dd>
          <dt>Unique dest. ports</dt><dd>${fmt.num(e.win_unique_dst_ports)}</dd>
          <dt>Unique dest. hosts</dt><dd>${fmt.num(e.win_unique_dst_ips)}</dd>
          <dt>Unique usernames</dt><dd>${fmt.num(e.win_unique_usernames)}</dd>
          <dt>Requests</dt><dd>${fmt.num(e.win_request_sum)}</dd>
          <dt>Traffic volume</dt><dd>${fmt.bytes(e.win_traffic_volume)}</dd>
        </dl>
        ${a ? `<div class="banner info mb-3"><i class="bi bi-bell"></i><div>Part of alert <a href="/alerts/${esc(a._id)}/">${esc(a._id)}</a> · ${badge.status(a.status)} · ${fmt.num(a.event_count)} events<br><span class="small">${esc(a.description)}</span></div></div>` : ""}
        <details><summary class="small text-muted">Raw document</summary><pre class="json mt-2">${esc(JSON.stringify(e, null, 2))}</pre></details>`);
    } catch (err) { setHTML("#detailBody", `<div class="banner danger">${esc(err.message)}</div>`); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    load();
    ["#f-range", "#f-category", "#f-severity", "#f-method"].forEach((s) => $(s).addEventListener("change", () => { page = 1; load(); }));
    $("#f-q").addEventListener("input", debounce(() => { page = 1; load(); }, 400));
    $("#body").addEventListener("click", (e) => {
      if (e.target.closest("[data-ip]")) return;
      const tr = e.target.closest("tr[data-id]"); if (tr) showDetail(tr.dataset.id);
    });
    $("#facets").addEventListener("click", (e) => {
      const c = e.target.closest(".chip"); if (!c) return;
      if (c.dataset.cat) $("#f-category").value = c.dataset.cat;
      if (c.dataset.method) $("#f-method").value = c.dataset.method;
      page = 1; load();
    });
    const refresh = debounce(() => { if ($("#f-auto").checked && page === 1) load(); }, 1500);
    Realtime.on("events", (msg) => { if (msg.items.some((e) => e.is_threat)) refresh(); });
  });
})();
