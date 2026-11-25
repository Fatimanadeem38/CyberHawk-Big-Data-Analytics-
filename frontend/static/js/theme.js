/* =====================================================================
   Light / dark theme switch.
   The choice is saved in localStorage ("ch-theme") and applied before
   the page paints by a small script in <head>. Charts are recoloured
   when the theme changes, without reloading the page.
   ===================================================================== */
"use strict";

function currentTheme() {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

function applyChartTheme() {
  if (!window.Chart) return;
  const text = cssVar("--chart-text"), grid = cssVar("--chart-grid"), surface = cssVar("--surface");
  Chart.defaults.color = text;
  Chart.defaults.borderColor = grid;
  SOC.colors.muted = text;
  SOC.colors.grid = grid;
  Object.values(Chart.instances || {}).forEach((chart) => {
    const o = chart.options;
    Object.values(o.scales || {}).forEach((sc) => {
      if (sc.ticks) sc.ticks.color = text;
      if (sc.grid) sc.grid.color = grid;
      if (sc.title) sc.title.color = text;
    });
    if (o.plugins && o.plugins.legend && o.plugins.legend.labels) o.plugins.legend.labels.color = text;
    if (chart.config.type === "doughnut" || chart.config.type === "pie") {
      chart.data.datasets.forEach((ds) => { ds.borderColor = surface; });
    }
    chart.update("none");
  });
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.setAttribute("data-bs-theme", theme);
  try { localStorage.setItem("ch-theme", theme); } catch (e) { /* private mode: theme just isn't remembered */ }
  applyChartTheme();
}

document.addEventListener("click", (e) => {
  if (e.target.closest("#theme-toggle")) setTheme(currentTheme() === "dark" ? "light" : "dark");
});

applyChartTheme();
