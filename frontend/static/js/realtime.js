/* =====================================================================
   Real-time WebSocket client  (Kafka → Spark → Elasticsearch → Django → here)
   - reconnects automatically with exponential back-off (1 s … 30 s)
   - sends a ping every 25 s to keep the connection alive
   - re-broadcasts every message as a DOM event, e.g. "rt:events", "rt:alerts", "rt:stats"
   ===================================================================== */
"use strict";

const Realtime = (() => {
  let ws = null, retry = 0, pingTimer = null, closedByUser = false;
  const statusEl = document.getElementById("rt-status");
  const handlers = {};

  function setStatus(state, text) {
    if (!statusEl) return;
    const dot = statusEl.querySelector(".dot");
    dot.className = "dot " + (state === "ok" ? "ok" : state === "warn" ? "warn" : "down");
    statusEl.querySelector(".txt").textContent = text;
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    setStatus("warn", retry ? `Reconnecting (${retry})…` : "Connecting…");
    try { ws = new WebSocket(`${proto}://${location.host}/ws/stream/`); }
    catch (e) { scheduleReconnect(); return; }

    ws.onopen = () => {
      retry = 0;
      setStatus("ok", "Live");
      clearInterval(pingTimer);
      pingTimer = setInterval(() => { if (ws.readyState === 1) ws.send(JSON.stringify({ type: "ping" })); }, 25000);
    };
    ws.onmessage = (msg) => {
      let data;
      try { data = JSON.parse(msg.data); } catch (e) { return; }
      if (data.type === "error") setStatus("warn", data.service === "elasticsearch" ? "Live · search offline" : "Live · backend error");
      if (data.type === "recovered" || data.type === "events" || data.type === "stats") setStatus("ok", "Live");
      document.dispatchEvent(new CustomEvent("rt:" + data.type, { detail: data }));
      (handlers[data.type] || []).forEach((fn) => { try { fn(data); } catch (e) { console.error(e); } });
    };
    ws.onclose = (ev) => {
      clearInterval(pingTimer);
      if (ev.code === 4403) { setStatus("down", "No permission"); return; }
      if (!closedByUser) scheduleReconnect();
    };
    ws.onerror = () => { /* onclose follows */ };
  }

  function scheduleReconnect() {
    retry += 1;
    const delay = Math.min(30000, 1000 * 2 ** Math.min(retry - 1, 5));
    setStatus("down", `Offline · retry in ${Math.round(delay / 1000)}s`);
    setTimeout(connect, delay);
  }

  window.addEventListener("beforeunload", () => { closedByUser = true; if (ws) ws.close(); });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && ws && ws.readyState === 3) { retry = 0; connect(); }
  });

  return {
    start: connect,
    on(type, fn) { (handlers[type] = handlers[type] || []).push(fn); },
  };
})();

/* ---- global: toast for new high/critical alerts + open-alert counter in the sidebar ---- */
(function globalAlerts() {
  const announced = new Set();
  Realtime.on("alerts", (msg) => {
    msg.items.forEach((a) => {
      if (announced.has(a._id)) return;
      announced.add(a._id);
      if ((a.severity === "critical" || a.severity === "high") && a.status === "new" && document.body.dataset.page !== "alert-detail") {
        toast(`${esc(fmt.label(a.threat_category))} from <span class="mono">${esc(a.src_ip)}</span> · ${fmt.num(a.event_count)} events
              <br><a href="/alerts/${esc(a._id)}/">Open alert →</a>`, "alert", `${a.severity.toUpperCase()} alert${a.is_simulated ? " (simulated)" : ""}`);
      }
    });
  });
  Realtime.on("stats", (msg) => {
    const el = document.getElementById("nav-alert-count");
    const n = msg.data.critical_alerts + msg.data.high_alerts;
    if (el) { el.textContent = n; el.classList.toggle("d-none", !n); el.title = "Open critical + high alerts"; }
  });
})();

document.addEventListener("DOMContentLoaded", () => Realtime.start());
