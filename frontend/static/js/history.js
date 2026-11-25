"use strict";
(() => {
  let page = 1;
  const SIZE = 50;
  const form = $("#search-form");

  function params() {
    const f = new FormData(form);
    const p = Object.fromEntries([...f.entries()].filter(([, v]) => v !== ""));
    ["date_from", "date_to"].forEach((k) => { if (p[k]) p[k] = new Date(p[k]).toISOString(); });
    const [sort, order] = $("#sort").value.split(":");
    return { ...p, sort, order };
  }

  async function search() {
    const p = params();
    $("#export").href = "/api/events/export/?" + qs(p);
    setHTML("#body", `<tr><td colspan="10" class="empty"><div class="spinner-border spinner-border-sm text-info"></div> Searching…</td></tr>`);
    try {
      const d = await api("/api/events/search/?" + qs({ ...p, page, size: SIZE }));
      setHTML("#total", `${fmt.num(d.total)} matching events · page ${d.page}`);
      setHTML("#body", d.results.length ? d.results.map((e) => `
        <tr class="${e.is_threat ? "row-threat" : ""}">
          <td class="mono small">${fmt.dt(e.event_time)}</td>
          <td>${badge.ip(e.src_ip)}<span class="text-muted mono">:${esc(e.src_port)}</span></td>
          <td>${badge.ip(e.dst_ip)}<span class="text-muted mono">:${esc(e.dst_port)}</span></td>
          <td>${esc(e.protocol)}</td><td>${esc(fmt.label(e.log_source))}</td><td>${esc(e.event_type)}${badge.origin(e)}</td>
          <td class="text-muted">${esc(e.network_status)}</td><td>${fmt.bytes(e.bytes_total)}</td>
          <td>${badge.cls(e.predicted_class)}</td><td>${badge.sev(e.severity)}</td></tr>`).join("") : emptyRow(10, "No events match your search."));
      pagination($("#pager"), d.page, d.size, d.total, (np) => { page = np; search(); });
    } catch (e) { setHTML("#body", errorRow(10, e)); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const url = new URLSearchParams(location.search);
    url.forEach((v, k) => { const el = form.elements[k]; if (el) el.value = v; });
    form.addEventListener("submit", (e) => { e.preventDefault(); page = 1; search(); });
    form.addEventListener("reset", () => setTimeout(() => { page = 1; search(); }, 0));
    $("#sort").addEventListener("change", () => { page = 1; search(); });
    search();
  });
})();
