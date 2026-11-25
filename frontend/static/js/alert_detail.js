"use strict";
(() => {
  const root = $("#alert-root");
  const id = root.dataset.alertId;
  let pendingStatus = null;

  function actions(status) {
    const b = [];
    if (status === "new") b.push(`<button class="btn btn-accent btn-sm" data-do="assign"><i class="bi bi-person-check me-1"></i>Assign to me &amp; investigate</button>`);
    if (status === "new" || status === "resolved" || status === "false_positive")
      b.push(`<button class="btn btn-ghost btn-sm" data-do="investigating"><i class="bi bi-search me-1"></i>${status === "new" ? "Investigate" : "Re-open"}</button>`);
    if (status !== "resolved") b.push(`<button class="btn btn-ghost btn-sm" data-do="resolved"><i class="bi bi-check2-circle me-1 text-success"></i>Resolve</button>`);
    if (status !== "false_positive") b.push(`<button class="btn btn-ghost btn-sm" data-do="false_positive"><i class="bi bi-slash-circle me-1"></i>Mark false positive</button>`);
    return b.join(" ");
  }

  function render(d) {
    const a = d.alert, w = d.workflow;
    root.innerHTML = `
    <div class="card-soc mb-3"><div class="card-body">
      <div class="d-flex flex-wrap gap-3 align-items-start">
        <div>
          <div class="d-flex align-items-center gap-2 mb-1">${badge.sev(a.severity)} ${badge.status(w.status)} ${a.is_simulated ? '<span class="sim-tag">simulated data</span>' : ""}</div>
          <h2 class="h4 mb-1">${esc(fmt.label(a.threat_category))} from <span class="mono">${esc(a.src_ip)}</span></h2>
          <div class="text-muted">${esc(a.description || "")}</div>
          <div class="small text-muted mt-1">Alert ID <span class="mono">${esc(a.alert_id)}</span> · assigned to <b>${esc(w.assigned_to || "nobody")}</b>${w.updated_by ? ` · last change by ${esc(w.updated_by)}` : ""}</div>
        </div>
        <div class="ms-auto d-flex flex-wrap gap-2">${actions(w.status)}</div>
      </div>
    </div></div>

    <div class="row g-3 mb-3">
      <div class="col-lg-5"><div class="card-soc h-100"><div class="card-head"><h3>Alert details</h3></div><div class="card-body">
        <dl class="kv">
          <dt>Source IP</dt><dd>${badge.ip(a.src_ip)}</dd>
          <dt>Destination(s)</dt><dd>${(a.dst_ips || [a.dst_ip]).map((ip) => badge.ip(ip)).join(", ")}</dd>
          <dt>Destination ports</dt><dd class="mono small">${esc((a.dst_ports || []).slice(0, 30).join(", ") || "–")}${(a.dst_ports || []).length >= 30 ? " …" : ""}</dd>
          <dt>Protocols</dt><dd>${esc((a.protocols || []).join(", "))}</dd>
          <dt>Events grouped</dt><dd>${fmt.num(a.event_count)}</dd>
          <dt>First seen</dt><dd>${fmt.dt(a.first_seen)}</dd>
          <dt>Last seen</dt><dd>${fmt.dt(a.last_seen)} (${fmt.ago(a.last_seen)})</dd>
          <dt>Detection method</dt><dd>${badge.methods(a.detection_methods)}</dd>
          <dt>Model probability</dt><dd>${badge.prob(a.max_ml_probability)} <span class="small text-muted">highest RF vote share for this category</span></dd>
          <dt>Anomaly score</dt><dd>${badge.score(a.max_anomaly_score)} <span class="small text-muted">not a probability</span></dd>
          <dt>Created / updated</dt><dd>${fmt.dt(a.created_at)} / ${fmt.dt(a.updated_at)}</dd>
        </dl>
      </div></div></div>

      <div class="col-lg-7"><div class="card-soc h-100"><div class="card-head"><h3><i class="bi bi-journal-text me-1"></i>Investigation notes</h3><span class="sub">${d.notes.length} note(s)</span></div>
        <div class="card-body">
          <ul class="timeline mb-3" style="max-height:260px;overflow:auto">
            ${d.notes.length ? d.notes.map((n) => `<li><div class="meta">${esc(n.author || "system")} · ${fmt.dt(n.created_at)}</div><div style="white-space:pre-wrap">${esc(n.text)}</div></li>`).join("") : '<li><div class="meta">No notes yet</div>Add what you checked, who you contacted and your conclusion.</li>'}
          </ul>
          <form id="noteForm" class="d-flex gap-2">
            <textarea class="form-control" id="noteText" rows="2" placeholder="Add an investigation note…" required></textarea>
            <button class="btn btn-accent align-self-end" type="submit"><i class="bi bi-send"></i></button>
          </form>
        </div></div></div>
    </div>

    <div class="card-soc mb-3"><div class="card-head"><h3><i class="bi bi-list-ul me-1"></i>Related events</h3><span class="sub">${fmt.num(d.related_total)} event(s) linked to this alert${d.related_total > 100 ? " · showing newest 100" : ""}</span></div>
      <div class="table-scroll short"><table class="table table-soc"><thead><tr><th>Event time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Type</th><th>Status</th><th>Failed logins</th><th>Requests</th><th>Prediction</th><th>Anomaly</th><th>Severity</th></tr></thead><tbody>
      ${d.related_events.length ? d.related_events.map((e) => `<tr><td class="mono small">${fmt.dt(e.event_time)}</td><td class="mono">${esc(e.src_ip)}:${esc(e.src_port)}</td><td class="mono">${esc(e.dst_ip)}:${esc(e.dst_port)}</td><td>${esc(e.protocol)}</td><td>${esc(e.event_type)}</td><td>${esc(e.network_status)}</td><td>${fmt.num(e.failed_logins)}</td><td>${fmt.num(e.request_count)}</td><td>${badge.cls(e.predicted_class)}</td><td>${badge.score(e.anomaly_score)}</td><td>${badge.sev(e.severity)}</td></tr>`).join("") : emptyRow(11, "Related events are still being indexed")}
      </tbody></table></div></div>

    <div class="row g-3">
      <div class="col-lg-6"><div class="card-soc h-100"><div class="card-head"><h3><i class="bi bi-clock-history me-1"></i>Workflow history (audit log)</h3></div><div class="card-body">
        <ul class="timeline">${d.history.length ? d.history.map((h) => `<li><div class="meta">${fmt.dt(h.created_at)} · ${esc(h.username)}</div>${esc(fmt.label(h.action))}${h.details && h.details.new_status ? `: ${esc(fmt.label(h.details.old_status))} → <b>${esc(fmt.label(h.details.new_status))}</b>` : ""}</li>`).join("") : '<li><div class="meta">No changes yet</div>Created automatically by the detection pipeline.</li>'}</ul>
      </div></div></div>
      <div class="col-lg-6"><div class="card-soc h-100"><div class="card-head"><h3><i class="bi bi-diagram-3 me-1"></i>Other alerts from this source</h3></div>
        <div class="table-scroll short"><table class="table table-soc table-hover"><tbody>
        ${d.other_alerts_from_source.length ? d.other_alerts_from_source.map((o) => `<tr class="clickable" onclick="location.href='/alerts/${esc(o._id)}/'"><td>${badge.sev(o.severity)}</td><td>${esc(fmt.label(o.threat_category))}</td><td>${fmt.num(o.event_count)} events</td><td>${fmt.ago(o.last_seen)}</td><td>${badge.status(o.status)}</td></tr>`).join("") : emptyRow(5, "No other alerts from this IP")}
        </tbody></table></div></div></div>
    </div>`;
  }

  async function load() {
    try { render(await api(`/api/alerts/${encodeURIComponent(id)}/`)); }
    catch (e) { root.innerHTML = `<div class="banner danger"><i class="bi bi-x-octagon"></i>${esc(e.message)}</div>`; }
  }

  async function update(body, msg) {
    try {
      await api(`/api/alerts/${encodeURIComponent(id)}/status/`, { method: "PATCH", body });
      toast(msg, "success");
      load();
    } catch (e) { toast(esc(e.message), "error", "Update failed"); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    load();
    root.addEventListener("click", (e) => {
      const b = e.target.closest("[data-do]"); if (!b) return;
      const act = b.dataset.do;
      if (act === "assign") return update({ assign_to_me: true, status: "investigating" }, "Alert assigned to you");
      if (act === "investigating") return update({ status: "investigating" }, "Alert is now being investigated");
      pendingStatus = act;
      setText("#resolveTitle", act === "resolved" ? "Resolve alert" : "Mark as false positive");
      $("#resolveText").value = "";
      bootstrap.Modal.getOrCreateInstance("#resolveModal").show();
    });
    $("#resolveConfirm").addEventListener("click", () => {
      const text = $("#resolveText").value.trim();
      bootstrap.Modal.getOrCreateInstance("#resolveModal").hide();
      update({ status: pendingStatus, note: text ? `[${fmt.label(pendingStatus)}] ${text}` : "", resolution_summary: text },
             pendingStatus === "resolved" ? "Alert resolved" : "Alert marked as false positive");
    });
    root.addEventListener("submit", async (e) => {
      if (e.target.id !== "noteForm") return;
      e.preventDefault();
      const text = $("#noteText").value.trim(); if (!text) return;
      try { await api(`/api/alerts/${encodeURIComponent(id)}/notes/`, { method: "POST", body: { text } }); toast("Note added", "success"); load(); }
      catch (err) { toast(esc(err.message), "error", "Could not add note"); }
    });
    Realtime.on("alerts", (msg) => { if (msg.items.some((a) => a._id === id)) load(); });
  });
})();
