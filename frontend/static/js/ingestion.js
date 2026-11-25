"use strict";
(() => {
  let enabled = false;
  let slidersTouched = false;

  function render(d) {
    const c = d.control, g = d.generator, hb = d.heartbeat || {};
    enabled = c.enabled;
    const btn = $("#btn-toggle");
    btn.innerHTML = enabled ? '<i class="bi bi-pause-fill"></i> Pause ingestion' : '<i class="bi bi-play-fill"></i> Start ingestion';
    btn.classList.toggle("btn-accent", !enabled);
    btn.classList.toggle("btn-ghost", enabled);
    if (!slidersTouched) {
      $("#rate").value = c.rate; setText("#rate-val", c.rate);
      $("#prob").value = Math.round(c.attack_probability * 100); setText("#prob-val", Math.round(c.attack_probability * 100) + "%");
    }
    setHTML("#gen-status", `${badge.dot(g.status)} <span class="small">${esc(g.message)}</span>`);
    setHTML("#gen-metrics", `
      <dl class="kv small mb-0">
        <dt>Switch</dt><dd>${enabled ? '<span class="text-success">ON</span>' : "OFF"} · set by ${esc(c.updated_by || "default")} ${c.updated_at ? fmt.ago(c.updated_at) : ""}</dd>
        <dt>Events delivered</dt><dd>${fmt.num(hb.events_sent)} <span class="text-muted">(failed ${fmt.num(hb.events_failed)})</span></dd>
        <dt>Queued burst events</dt><dd>${fmt.num(hb.pending_burst_events)}</dd>
        <dt>Last heartbeat</dt><dd>${hb.last_seen ? fmt.ago(hb.last_seen) : "never – is the generator container running?"}</dd>
      </dl>`);

    const topics = d.kafka_topics || {};
    const sent = hb.by_topic || {};
    setHTML("#topics", topics.error ? errorRow(5, topics.error) : Object.entries(topics).map(([t, v]) => `<tr><td class="mono">${esc(t)}</td>
      <td>${v.exists ? v.partitions : '<span class="text-danger">missing</span>'}</td><td>${fmt.num(v.end_offset_total)}</td><td>${fmt.num(v.messages_retained)}</td><td>${fmt.num(sent[t] || 0)}</td></tr>`).join(""));
    setHTML("#labels", Object.entries(hb.by_label || {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<span class="chip">${badge.cls(k)} <span class="n">${fmt.num(v)}</span></span>`).join("") || '<span class="text-muted small">nothing sent yet</span>');

    setHTML("#scen", d.recent_scenarios.length ? d.recent_scenarios.map((s) => `<tr><td>${esc(fmt.label(s.scenario))}</td><td>${esc(s.requested_by__username || "")}</td>
      <td>${fmt.ago(s.created_at)}</td><td>${s.consumed_at ? '<i class="bi bi-check2 text-success"></i> ' + fmt.ago(s.consumed_at) : '<span class="text-warning">waiting…</span>'}</td></tr>`).join("") : emptyRow(4, "No scenarios requested yet"));
    setHTML("#uploads", d.recent_uploads.length ? d.recent_uploads.map((u) => `<tr><td class="mono small">${esc(u.filename)}</td><td>${esc(u.status)}</td>
      <td>${fmt.num(u.rows_total)}</td><td>${fmt.num(u.rows_valid)}</td><td>${fmt.num(u.rows_rejected)}</td><td>${fmt.num(u.rows_published)}</td><td>${fmt.ago(u.created_at)}</td></tr>`).join("") : emptyRow(7, "No uploads yet"));
  }

  function renderDataset(ds, rp) {
    if (!ds) return;
    setHTML("#ds-files", ds.files.length ? ds.files.map((f) => `<div class="d-flex justify-content-between"><span class="mono">${esc(f.name)}</span>
      <span class="text-muted">${fmt.bytes(f.size_bytes)} · ${f.format === "full" ? "replay (has IPs)" : "training/testing"}</span></div>`).join("")
      : `<div class="banner warn small"><i class="bi bi-download"></i><div>No files yet. Download them as described in <span class="mono">documentation/real_dataset.md</span>.</div></div>`);
    if (!ds.training_files_present && ds.files.length) setHTML("#ds-files", $("#ds-files").innerHTML + '<div class="text-warning mt-1">Training needs UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv.</div>');
    const m = ds.model;
    setHTML("#ds-model", m ? `<div><i class="bi bi-check-circle text-success"></i> trained ${fmt.dt(m.trained_at)}</div>
      <div>Official test set: accuracy <b>${fmt.pct01(m.accuracy)}</b>, attack-vs-normal F1 <b>${fmt.pct01(m.binary_f1)}</b>, ROC-AUC ${fmt.pct01(m.roc_auc)}</div>
      <a href="/models/">See full evaluation →</a>`
      : `<div class="text-muted">Not trained yet. In the WSL terminal run:<br><span class="mono">python3 scripts/train_models.py --dataset unsw</span></div>`);
    const st = rp && rp.status;
    setHTML("#ds-replay-status", st ? `${badge.dot(st === "running" ? "up" : st === "failed" ? "down" : "degraded")} <span class="small">${esc(st)}</span>` : "");
    if (!st) { setHTML("#ds-progress", '<span class="text-muted">No replay yet.</span>'); return; }
    const pct = rp.rows_target ? Math.min(100, 100 * rp.rows_sent / rp.rows_target) : 0;
    setHTML("#ds-progress", `
      <div class="d-flex justify-content-between"><span>${esc(rp.file || "")} · ${esc(rp.mode)}</span><span class="mono">${fmt.num(rp.rows_sent)} / ${fmt.num(rp.rows_target)}</span></div>
      <div class="progress my-1" style="height:6px"><div class="progress-bar bg-success" style="width:${pct}%"></div></div>
      <div class="text-muted">read ${fmt.num(rp.rows_read)} rows · ${esc(rp.rate)} flows/s · last row ${fmt.num(rp.last_row)}</div>
      <div class="d-flex flex-wrap gap-1 mt-2">${Object.entries(rp.by_label || {}).sort((x, y) => y[1] - x[1]).map(([k, v]) => `<span class="chip">${badge.cls(k)} <span class="n">${fmt.num(v)}</span></span>`).join("")}</div>
      ${rp.error ? `<div class="banner danger small mt-2"><i class="bi bi-x-octagon"></i>${esc(rp.error)}</div>` : ""}`);
  }

  async function load() {
    try { const d = await api("/api/ingestion/status/"); render(d); renderDataset(d.dataset, d.replay); }
    catch (e) { setHTML("#gen-metrics", `<div class="banner danger small">${esc(e.message)}</div>`); }
  }

  async function control(body, msg) {
    try { await api("/api/ingestion/control/", { method: "POST", body }); toast(msg, "success"); slidersTouched = false; load(); }
    catch (e) { toast(esc(e.message), "error", "Could not change ingestion"); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    load();
    setInterval(() => { if (!document.hidden) load(); }, 5000);
    $("#btn-toggle").addEventListener("click", () => control({ enabled: !enabled },
      enabled ? "Ingestion paused" : "Ingestion started – events will appear within a few seconds"));
    $("#rate").addEventListener("input", (e) => { slidersTouched = true; setText("#rate-val", e.target.value); });
    $("#prob").addEventListener("input", (e) => { slidersTouched = true; setText("#prob-val", e.target.value + "%"); });
    $("#btn-save").addEventListener("click", () => control({ rate: Number($("#rate").value), attack_probability: Number($("#prob").value) / 100 }, "Rate settings applied"));
    $$("[data-scenario]").forEach((b) => b.addEventListener("click", async () => {
      b.disabled = true;
      try { const r = await api("/api/ingestion/scenario/", { method: "POST", body: { scenario: b.dataset.scenario } }); toast(esc(r.message), "success", fmt.label(r.scenario)); load(); }
      catch (e) { toast(esc(e.message), "error"); }
      setTimeout(() => { b.disabled = false; }, 3000);
    }));
    $("#ds-start-btn").addEventListener("click", async () => {
      const body = { rows: Number($("#ds-rows").value), rate: Number($("#ds-rate").value), mode: $("#ds-mode").value,
                     start_row: Number($("#ds-start").value), normal_fraction: 0.05 };
      try { const r = await api("/api/ingestion/dataset-replay/", { method: "POST", body }); toast(esc(r.message), "success", "UNSW-NB15 replay"); load(); }
      catch (e) { toast(esc(e.message), "error", "Replay not started"); }
    });
    $("#ds-stop-btn").addEventListener("click", async () => {
      try { await api("/api/ingestion/dataset-replay/", { method: "POST", body: { action: "stop" } }); toast("Stop request sent", "success"); }
      catch (e) { toast(esc(e.message), "error"); }
    });
    $("#upload-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const form = new FormData(e.target);
      if (!e.target.replay_now.checked) form.delete("replay_now");
      setHTML("#upload-result", '<div class="small"><span class="spinner-border spinner-border-sm text-info"></span> Validating and publishing…</div>');
      try {
        const r = await api("/api/ingestion/upload/", { method: "POST", form });
        const reasons = Object.entries(r.rejection_reasons || {}).map(([k, v]) => `<li>${fmt.num(v)} × ${esc(k)}</li>`).join("");
        setHTML("#upload-result", `<div class="banner ${r.rows_published ? "ok" : "warn"} small"><i class="bi bi-check2-circle"></i><div>
          <b>${esc(r.filename)}</b>: ${fmt.num(r.rows_total)} rows · ${fmt.num(r.rows_valid)} valid · ${fmt.num(r.rows_rejected)} rejected · <b>${fmt.num(r.rows_published)} published to Kafka</b>
          ${reasons ? `<ul class="mb-0 mt-1">${reasons}</ul>` : ""}</div></div>`);
        e.target.reset(); load();
      } catch (err) { setHTML("#upload-result", `<div class="banner danger small"><i class="bi bi-x-octagon"></i>${esc(err.message)}</div>`); }
    });
  });
})();
