"use strict";
(() => {
  let page = 1, status = "";
  const SIZE = 25;

  async function quickStatus(id, newStatus) {
    try {
      await api(`/api/alerts/${encodeURIComponent(id)}/status/`, { method: "PATCH", body: { status: newStatus } });
      toast(`Alert marked as <b>${esc(fmt.label(newStatus))}</b>`, "success");
      load();
    } catch (e) { toast(esc(e.message), "error", "Could not update alert"); }
  }

  async function load() {
    const p = { status, severity: $("#f-severity").value, threat_category: $("#f-category").value,
                q: $("#f-q").value.trim(), range: $("#f-range").value, sort: $("#f-sort").value, page, size: SIZE };
    try {
      const d = await api("/api/alerts/?" + qs(p));
      setText("#total", `${fmt.num(d.total)} alerts`);
      const counts = Object.fromEntries(d.facets.status.map((x) => [x.key, x.count]));
      if (!status) {
        $$("[data-n]").forEach((el) => { const k = el.dataset.n; el.textContent = k ? (counts[k] || 0) : d.total; });
      }
      setHTML("#body", d.results.length ? d.results.map((a) => `
        <tr class="clickable ${a.severity === "critical" ? "row-critical" : ""}" data-id="${esc(a._id)}">
          <td>${badge.sev(a.severity)}</td>
          <td><div>${esc(fmt.label(a.threat_category))}${badge.sim(a.is_simulated)}</div><div class="small text-muted text-truncate" style="max-width:260px" title="${esc(a.description)}">${esc(a.description || "")}</div></td>
          <td>${badge.ip(a.src_ip)}</td><td>${badge.ip(a.dst_ip)}</td><td>${fmt.num(a.event_count)}</td>
          <td>${badge.methods(a.detection_methods)}</td>
          <td><div class="small">${a.max_ml_probability != null ? "P " + badge.prob(a.max_ml_probability) : ""}</div><div class="small">${a.max_anomaly_score != null ? "A " + `<span class="mono">${fmt.dec(a.max_anomaly_score)}</span>` : ""}</div></td>
          <td class="small">${fmt.dt(a.first_seen)}</td><td class="small" title="${esc(a.last_seen)}">${fmt.ago(a.last_seen)}</td>
          <td>${badge.status(a.status)}</td><td class="small">${esc(a.assigned_to || "–")}</td>
          <td><div class="dropdown"><button class="btn btn-ghost btn-sm" data-bs-toggle="dropdown" data-stop><i class="bi bi-three-dots"></i></button>
            <ul class="dropdown-menu dropdown-menu-end">
              <li><a class="dropdown-item" href="/alerts/${esc(a._id)}/"><i class="bi bi-box-arrow-up-right me-2"></i>Open details</a></li>
              <li><a class="dropdown-item" href="#" data-act="investigating" data-aid="${esc(a._id)}"><i class="bi bi-search me-2"></i>Investigate</a></li>
              <li><a class="dropdown-item" href="#" data-act="resolved" data-aid="${esc(a._id)}"><i class="bi bi-check2-circle me-2"></i>Resolve</a></li>
              <li><a class="dropdown-item" href="#" data-act="false_positive" data-aid="${esc(a._id)}"><i class="bi bi-slash-circle me-2"></i>False positive</a></li>
            </ul></div></td>
        </tr>`).join("") : emptyRow(12, "No alerts match these filters."));
      pagination($("#pager"), d.page, d.size, d.total, (np) => { page = np; load(); });
    } catch (e) { setHTML("#body", errorRow(12, e)); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(location.search);
    if (params.get("q")) $("#f-q").value = params.get("q");
    load();
    $$("#status-tabs button").forEach((b) => b.addEventListener("click", () => {
      $$("#status-tabs button").forEach((x) => x.classList.remove("active")); b.classList.add("active");
      status = b.dataset.status; page = 1; load();
    }));
    ["#f-severity", "#f-category", "#f-range", "#f-sort"].forEach((s) => $(s).addEventListener("change", () => { page = 1; load(); }));
    $("#f-q").addEventListener("input", debounce(() => { page = 1; load(); }, 400));
    $("#body").addEventListener("click", (e) => {
      const act = e.target.closest("[data-act]");
      if (act) { e.preventDefault(); quickStatus(act.dataset.aid, act.dataset.act); return; }
      if (e.target.closest("[data-ip], [data-stop], .dropdown-menu")) return;
      const tr = e.target.closest("tr[data-id]"); if (tr) location.href = `/alerts/${tr.dataset.id}/`;
    });
    Realtime.on("alerts", debounce(() => { if (page === 1) load(); }, 1000));
  });
})();
