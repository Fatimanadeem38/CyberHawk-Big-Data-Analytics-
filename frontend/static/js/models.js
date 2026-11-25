"use strict";
(() => {
  const tile = (label, v, isPct = true) =>
    `<div class="col"><div class="metric-tile"><div class="v">${v === null || v === undefined ? "–" : isPct ? fmt.pct01(v, 2) : esc(v)}</div><div class="l">${label}</div></div></div>`;

  function confusionTable(cm) {
    const labels = cm.labels, m = cm.matrix;
    const max = Math.max(1, ...m.flat());
    const cell = (v, diag) => {
      const a = v / max;
      const color = diag ? `rgba(34,197,94,${0.12 + a * 0.6})` : v ? `rgba(239,68,68,${0.12 + a * 0.6})` : "transparent";
      return `<td style="background:${color}">${fmt.num(v)}</td>`;
    };
    return `<div class="table-responsive"><table class="table table-soc cm-table mb-0">
      <thead><tr><th class="rowh">actual ↓ / predicted →</th>${labels.map((l) => `<th>${esc(fmt.label(l))}</th>`).join("")}</tr></thead>
      <tbody>${m.map((row, i) => `<tr><th class="rowh">${esc(fmt.label(labels[i]))}</th>${row.map((v, j) => cell(v, i === j)).join("")}</tr>`).join("")}</tbody></table></div>`;
  }

  function modelCard(doc) {
    const m = doc.metrics || {};
    const isClf = doc.model_type === "classification";
    const tiles = isClf
      ? [tile("Accuracy", m.accuracy), tile("Precision (weighted)", m.precision), tile("Recall (weighted)", m.recall), tile("F1-score", m.f1), tile("ROC-AUC (attack vs normal)", m.roc_auc)]
      : [tile("Accuracy", m.accuracy), tile("Precision", m.precision), tile("Recall", m.recall), tile("F1-score", m.f1), tile("ROC-AUC (score)", m.roc_auc)];
    let extra = "";
    if (isClf && m.per_class) {
      extra = `<h6 class="mt-3">Per-class results</h6><div class="table-responsive"><table class="table table-soc"><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Test events</th></tr></thead><tbody>
        ${Object.entries(m.per_class).map(([k, v]) => `<tr><td>${badge.cls(k)}</td><td>${fmt.pct01(v.precision)}</td><td>${fmt.pct01(v.recall)}</td><td>${fmt.pct01(v.f1)}</td><td>${fmt.num(v.support)}</td></tr>`).join("")}
        </tbody></table></div>`;
      const ab = m.ablation_without_ttl;
      if (ab) extra = `<div class="banner warn small mb-3"><i class="bi bi-flask"></i><div><b>Ablation: same model without the TTL features</b> (${esc(ab.removed_features.join(", "))}).
        Accuracy ${fmt.pct01(ab.accuracy)} (vs ${fmt.pct01(m.accuracy)}), attack-vs-normal F1 ${fmt.pct01(ab.binary_f1)} (vs ${fmt.pct01(m.binary && m.binary.f1)}),
        false-positive rate ${fmt.pct01(ab.false_positive_rate, 2)}. In UNSW-NB15 the attack hosts used different TTL values from the normal hosts. A big drop here
        means the full model partly learned that testbed detail, so the lower number is the safer estimate.</div></div>` + extra;
      if (m.binary) extra += `<div class="small text-muted">Attack vs normal (binary view): precision ${fmt.pct01(m.binary.precision)}, recall ${fmt.pct01(m.binary.recall)}, false-positive rate ${fmt.pct01(m.binary.false_positive_rate, 2)}.</div>`;
      const top = (doc.params && doc.params.top_features) || [];
      if (top.length) extra += `<h6 class="mt-3">Most important numeric features</h6>${top.map(([n, v]) => `<div class="d-flex align-items-center gap-2 small"><span class="mono" style="width:190px">${esc(n)}</span><div class="progress flex-grow-1" style="height:6px"><div class="progress-bar bg-info" style="width:${(v / top[0][1]) * 100}%"></div></div><span class="mono">${(v * 100).toFixed(1)}%</span></div>`).join("")}`;
    }
    if (!isClf && m.detection_rate_by_category) {
      extra = `<h6 class="mt-3">Share flagged as anomalous, per true category</h6>${Object.entries(m.detection_rate_by_category).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
        `<div class="d-flex align-items-center gap-2 small mb-1"><span style="width:170px">${badge.cls(k)}</span><div class="progress flex-grow-1" style="height:6px"><div class="progress-bar" style="width:${v * 100}%;background:${k === "normal" ? "#22c55e" : "#f97316"}"></div></div><span class="mono">${fmt.pct01(v)}</span></div>`).join("")}
        <div class="small text-muted mt-1">For "normal" this is the false-alarm rate (about 1% by design, because the threshold is the 99th percentile of normal traffic).</div>`;
    }
    const params = Object.entries(doc.params || {}).filter(([k]) => !["top_features", "class_weights"].includes(k))
      .map(([k, v]) => `<span class="method">${esc(k)}=${esc(typeof v === "number" ? +v.toFixed(4) : v)}</span>`).join(" ");
    return `<div class="card-soc mb-3">
      <div class="card-head"><h3><i class="bi ${isClf ? "bi-diagram-3" : "bi-bullseye"} text-info me-1"></i>${esc(doc.model_name)}</h3>
        ${doc.dataset === "unsw_nb15" ? '<span class="real-tag ms-1">real dataset · official UNSW-NB15 test set</span>' : '<span class="sim-tag ms-1">offline · simulated test set</span>'}<span class="ms-auto small text-muted">trained ${fmt.dt(doc.trained_at)}</span></div>
      <div class="card-body">
        <div class="small text-muted mb-2"><span class="mono">${esc(doc.algorithm)}</span> · ${fmt.num(doc.training_rows)} training / ${fmt.num(doc.test_rows)} test events</div>
        <div class="row g-2 mb-3">${tiles.join("")}</div>
        <div class="row g-3">
          <div class="col-xl-7"><h6>Confusion matrix</h6>${confusionTable(doc.confusion_matrix)}${extra}</div>
          <div class="col-xl-5"><h6>Model training information</h6>
            <div class="mb-2">${params}</div>
            ${!isClf ? `<dl class="kv small"><dt>Threshold distance</dt><dd class="mono">${fmt.dec(m.threshold_distance, 4)}</dd><dt>True / false positives</dt><dd>${fmt.num(m.tp)} / ${fmt.num(m.fp)}</dd><dt>False-positive rate</dt><dd>${fmt.pct01(m.false_positive_rate, 2)}</dd></dl>` : ""}
            <div class="small text-muted mb-2">Features used: ${(doc.feature_columns || []).map((f) => `<span class="mono">${esc(f)}</span>`).join(", ")}</div>
            <div class="banner info small"><i class="bi bi-chat-square-text"></i>${esc(doc.notes || "")}</div>
          </div>
        </div>
      </div></div>`;
  }

  async function load() {
    try {
      const d = await api("/api/models/metrics/");
      const real = d.offline.filter((x) => x.dataset === "unsw_nb15");
      const sim = d.offline.filter((x) => x.dataset !== "unsw_nb15");
      const section = (title, docs) => docs.length ? `<h3 class="h6 mt-2 mb-2">${title}</h3>` + docs.map(modelCard).join("") : "";
      setHTML("#offline", d.offline.length
        ? (real.length ? "" : `<div class="banner warn small mb-3"><i class="bi bi-database-exclamation"></i>No model trained on the real UNSW-NB15 dataset yet: see <span class="mono">documentation/real_dataset.md</span>.</div>`)
          + section('<i class="bi bi-database-check text-success me-1"></i>Real dataset: UNSW-NB15 (official train/test split)', real)
          + section('<i class="bi bi-cpu text-info me-1"></i>Simulated data (pipeline demo)', sim)
        : `<div class="banner warn"><i class="bi bi-hourglass-split"></i>No trained model metrics yet. The <span class="mono">spark-train</span> container trains the models on first start. Check it with <span class="mono">docker compose logs spark-train</span>.</div>`);
      const L = d.live;
      setHTML("#live-kpis", `
        <div class="col-6 col-xl-3"><div class="card-soc kpi accent"><div class="label">Events scored</div><div class="value">${fmt.num(L.events_scored)}</div><div class="hint">${esc(L.window)}</div></div></div>
        <div class="col-6 col-xl-3"><div class="card-soc kpi"><div class="label">Avg. Model A probability</div><div class="value">${fmt.pct01(L.avg_ml_probability)}</div><div class="hint">confidence of predicted class</div></div></div>
        <div class="col-6 col-xl-3"><div class="card-soc kpi medium"><div class="label">Anomaly rate (Model B)</div><div class="value">${fmt.pct(L.anomaly_rate, 2)}</div><div class="hint">avg. score ${fmt.dec(L.avg_anomaly_score)}</div></div></div>
        <div class="col-6 col-xl-3"><div class="card-soc kpi ok"><div class="label">Agreement with ground-truth labels</div><div class="value">${L.agreement_with_simulation_labels == null ? "–" : fmt.pct(L.agreement_with_simulation_labels)}</div>
          <div class="hint">${(L.agreement_by_source || []).map((x) => `${esc(x.source)}: ${fmt.pct(x.agreement)} of ${fmt.num(x.events)}`).join(" · ") || "no labelled events yet"}</div></div></div>`);
      doughnut("c-classes", L.class_distribution.map((x) => fmt.label(x.key)), L.class_distribution.map((x) => x.count));
      makeChart("c-methods", {
        type: "bar",
        data: { labels: L.detection_methods.map((x) => x.key.replace("ml_random_forest", "Random Forest").replace("anomaly_kmeans", "KMeans anomaly")),
                datasets: [{ data: L.detection_methods.map((x) => x.count), backgroundColor: "rgba(59,130,246,.6)", borderRadius: 3 }] },
        options: { indexAxis: "y", plugins: { legend: { display: false } } },
      });
      setHTML("#history", d.training_history.length ? d.training_history.map((h) => `<tr><td>${fmt.dt(h.trained_at)}</td><td>${esc(h.model_name)}${h.dataset === "unsw_nb15" ? ' <span class="real-tag">real</span>' : ""}</td>
        <td>${fmt.pct01(h.metrics && h.metrics.accuracy)}</td><td>${fmt.pct01(h.metrics && h.metrics.f1)}</td><td>${fmt.pct01(h.metrics && h.metrics.roc_auc)}</td><td>${h.is_current ? '<i class="bi bi-check-circle text-success"></i>' : ""}</td></tr>`).join("") : emptyRow(6));
    } catch (e) { setHTML("#offline", `<div class="banner danger"><i class="bi bi-x-octagon"></i>${esc(e.message)}</div>`); }
  }

  document.addEventListener("DOMContentLoaded", () => { load(); setInterval(() => { if (!document.hidden) load(); }, 60000); });
})();
