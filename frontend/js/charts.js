// charts.js - five Chart.js charts. Features: theme-aware colours, hover-dim + focused tooltip + click-to-isolate
// on the trend chart, and clickable donut / bars that filter the Incident Log.

Chart.defaults.font.family = 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
Chart.defaults.font.size = 12;

const SEVERITY_COLORS = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#22c55e" };
const ATTACK_COLORS = {
  "Brute Force": "#ef4444", "Port Scan": "#22d3ee", "SQL Injection": "#a78bfa", "Phishing": "#f59e0b",
  "Cross-Site Scripting": "#34d399", "DDoS": "#3b82f6", "Malware": "#f472b6", "Privilege Escalation": "#fb923c",
  "Suspicious Activity": "#94a3b8", "Other": "#64748b",
};
const FALLBACK_COLORS = ["#2dd4bf", "#e879f9", "#facc15", "#60a5fa", "#4ade80", "#f87171", "#818cf8", "#fb7185"];
function colorForType(label, index) { return ATTACK_COLORS[label] || FALLBACK_COLORS[index % FALLBACK_COLORS.length]; }

const EASE = "easeOutQuint"; // Chart.js easing closest to cubic-bezier(0.22, 1, 0.36, 1)
const HIT_RADIUS = 16;       // how close (px) the mouse must be to a line to "touch" it

const charts = {};           // every chart object lives here
let trendFocus = null;       // attack type currently isolated on the trend chart (null = show all)
let lastChartData = null;    // last data given to updateCharts (used to redraw after a theme change)
let trendBound = false, severityBound = false; // make sure event listeners are attached only once

// ---------------------------------------------------------------- Theme colours (read from CSS variables)
const THEME = { text: "#8a9bbd", strong: "#f1f5f9", grid: "rgba(99,140,255,.1)", surface: "#0f1a33", guide: "rgba(148,163,184,.45)", tipBg: "rgba(7,13,30,.96)", tipBorder: "rgba(96,165,250,.35)", tipText: "#c3d0ea" };

function readTheme() { // pulls the current light/dark colours from style.css
  const css = getComputedStyle(document.documentElement);
  const get = (name, fallback) => css.getPropertyValue(name).trim() || fallback;
  THEME.text = get("--chart-text", THEME.text);
  THEME.strong = get("--chart-strong", THEME.strong);
  THEME.grid = get("--chart-grid", THEME.grid);
  THEME.surface = get("--chart-surface", THEME.surface);
  THEME.guide = get("--chart-guide", THEME.guide);
  THEME.tipBg = get("--chart-tip-bg", THEME.tipBg);
  THEME.tipBorder = get("--chart-tip-border", THEME.tipBorder);
  THEME.tipText = get("--chart-tip-text", THEME.tipText);
  Chart.defaults.color = THEME.text;
  Chart.defaults.borderColor = THEME.grid;
}

function tooltipStyle() { // one tooltip look for the simple charts
  return { backgroundColor: THEME.tipBg, borderColor: THEME.tipBorder, borderWidth: 1, padding: 12, titleColor: THEME.strong, bodyColor: THEME.tipText, cornerRadius: 10, boxPadding: 4 };
}

function pointerCursor(event, elements) { // hand cursor when hovering something clickable
  if (event.native && event.native.target) event.native.target.style.cursor = elements.length ? "pointer" : "default";
}

// ---------------------------------------------------------------- Plugins
const revealPlugin = { // progressive left-to-right line drawing
  id: "revealLines",
  beforeDatasetsDraw(chart) {
    if (chart.$reveal === undefined || chart.$reveal >= 1) return;
    const a = chart.chartArea;
    chart.ctx.save(); chart.ctx.beginPath();
    chart.ctx.rect(a.left - 12, a.top - 12, (a.width + 24) * chart.$reveal, a.height + 24);
    chart.ctx.clip(); chart.$clipped = true;
  },
  afterDatasetsDraw(chart) { if (chart.$clipped) { chart.ctx.restore(); chart.$clipped = false; } },
};

const lineFocusPlugin = { // fades a line by drawing it with lower globalAlpha (no data update needed = very smooth)
  id: "lineFocus",
  beforeDatasetDraw(chart, args) {
    const alpha = chart.$alpha && chart.$alpha[args.index];
    if (alpha === undefined || alpha >= 0.999) return;
    chart.ctx.save(); chart.ctx.globalAlpha = alpha;
  },
  afterDatasetDraw(chart, args) {
    const alpha = chart.$alpha && chart.$alpha[args.index];
    if (alpha === undefined || alpha >= 0.999) return;
    chart.ctx.restore();
  },
};

const markerPlugin = { // vertical guide line + dot on the hovered point
  id: "trendMarker",
  afterDatasetsDraw(chart) {
    const m = chart.$marker;
    if (!m) return;
    const a = chart.chartArea, ctx = chart.ctx;
    ctx.save();
    ctx.strokeStyle = THEME.guide; ctx.lineWidth = 1; ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(m.x, a.top); ctx.lineTo(m.x, a.bottom); ctx.stroke();
    ctx.setLineDash([]); ctx.fillStyle = m.color; ctx.strokeStyle = THEME.surface; ctx.lineWidth = 3;
    ctx.beginPath(); ctx.arc(m.x, m.y, 6, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
    ctx.restore();
  },
};

const centerTextPlugin = { // number in the middle of the severity donut (shows the hovered slice when hovering)
  id: "centerText",
  afterDraw(chart) {
    const info = chart.$center, a = chart.chartArea;
    if (!info || !a) return;
    let value = info.value, label = info.label;
    const active = chart.getActiveElements();
    if (active.length) { value = Number(chart.data.datasets[0].data[active[0].index]).toLocaleString(); label = chart.data.labels[active[0].index]; }
    const x = (a.left + a.right) / 2, y = (a.top + a.bottom) / 2, ctx = chart.ctx;
    ctx.save(); ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillStyle = THEME.strong; ctx.font = "700 26px ui-sans-serif, system-ui, sans-serif"; ctx.fillText(value, x, y - 8);
    ctx.fillStyle = THEME.text; ctx.font = "500 12px ui-sans-serif, system-ui, sans-serif"; ctx.fillText(label, x, y + 14);
    ctx.restore();
  },
};

function playReveal(chart, duration = 1500) { // animates chart.$reveal from 0 to 1
  if (!chart.canvas.offsetWidth) { chart.$reveal = 1; return; }
  const token = (chart.$revealToken = (chart.$revealToken || 0) + 1);
  const start = performance.now();
  chart.$reveal = 0;
  function frame(now) {
    if (chart.$revealToken !== token) return;
    const p = Math.min((now - start) / duration, 1);
    chart.$reveal = 1 - Math.pow(1 - p, 4);
    chart.draw();
    if (p < 1) requestAnimationFrame(frame); else chart.$reveal = 1;
  }
  requestAnimationFrame(frame);
}

// ---------------------------------------------------------------- Chart creation
function initCharts() {
  readTheme(); // colours for the current theme

  // 1) MULTI-LINE attack trend. Chart.js events are OFF because we handle the mouse ourselves (see bindTrendInteractions)
  charts.trend = new Chart($("trendChart"), {
    type: "line",
    data: { labels: [], datasets: [] },
    plugins: [revealPlugin, lineFocusPlugin, markerPlugin],
    options: {
      responsive: true, maintainAspectRatio: false, events: [],
      animation: { duration: 1100, easing: EASE },
      layout: { padding: { top: 6, right: 8 } },
      plugins: { legend: { display: false }, tooltip: { enabled: false } }, // custom HTML legend + tooltip are used instead
      scales: {
        x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
        y: { beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
  charts.trend.$alpha = [];
  bindTrendInteractions();

  // 2) Severity DONUT (clickable)
  charts.severityDonut = new Chart($("severityDonut"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: THEME.surface, borderWidth: 3, hoverOffset: 14, hoverBorderColor: THEME.surface }] },
    plugins: [centerTextPlugin],
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "66%", layout: { padding: 14 },
      animation: { animateRotate: true, animateScale: true, duration: 1300, easing: EASE },
      onHover(event, elements) { pointerCursor(event, elements); highlightSeverityPill(elements.length ? elements[0].index : -1); },
      onClick(event, elements, chart) { if (elements.length) openIncidentsWith({ severity: chart.data.labels[elements[0].index] }); },
      plugins: { legend: { display: false }, tooltip: tooltipStyle() }, // legend is the custom pill row under the chart
    },
  });
  bindSeverityLegend();

  // 3) Top attacking IPs (click a bar = open that IP's incidents)
  charts.ips = new Chart($("ipChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Incidents", data: [], backgroundColor: "#22d3ee", hoverBackgroundColor: "#67e8f9", borderRadius: 8, maxBarThickness: 26 }] },
    options: {
      indexAxis: "y", responsive: true, maintainAspectRatio: false,
      animation: { duration: 1100, easing: EASE },
      onHover: pointerCursor,
      onClick(event, elements, chart) { if (elements.length) openIncidentsWith({ search: chart.data.labels[elements[0].index] }); },
      plugins: { legend: { display: false }, tooltip: tooltipStyle() },
      scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
    },
  });

  // 4) Attack type doughnut (Risk Analysis)
  charts.types = new Chart($("typeChart"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: THEME.surface, borderWidth: 3, hoverOffset: 12 }] },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "62%", layout: { padding: 12 },
      animation: { animateRotate: true, animateScale: true, duration: 1300, easing: EASE },
      onHover: pointerCursor,
      onClick(event, elements, chart) { if (elements.length) openIncidentsWith({ attackType: chart.data.labels[elements[0].index] }); },
      plugins: {
        tooltip: tooltipStyle(),
        legend: {
          position: "bottom", labels: { boxWidth: 10, padding: 10, usePointStyle: true },
          onClick(event, item) { openIncidentsWith({ attackType: item.text }); },
          onHover(event) { event.native.target.style.cursor = "pointer"; },
          onLeave(event) { event.native.target.style.cursor = "default"; },
        },
      },
    },
  });

  // 5) Severity bars (Risk Analysis)
  charts.severityBar = new Chart($("severityBar"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Incidents", data: [], backgroundColor: [], borderRadius: 8, maxBarThickness: 54 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 1100, easing: EASE },
      onHover: pointerCursor,
      onClick(event, elements, chart) { if (elements.length) openIncidentsWith({ severity: chart.data.labels[elements[0].index] }); },
      plugins: { legend: { display: false }, tooltip: tooltipStyle() },
      scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

function rebuildCharts() { // called after a theme switch: recreate charts with the new colours
  Object.values(charts).forEach((chart) => chart.destroy());
  Object.keys(charts).forEach((key) => delete charts[key]);
  initCharts();
  if (lastChartData) updateCharts(lastChartData);
}

// ---------------------------------------------------------------- Trend chart: hover, tooltip, isolate
function trendHit(chart, x, y) { // finds which line (and which date) the mouse is on
  const a = chart.chartArea;
  if (!a || x < a.left - 8 || x > a.right + 8 || y < a.top - 8 || y > a.bottom + 8) return null;
  let best = null;
  chart.data.datasets.forEach((ds, i) => {
    if (!chart.isDatasetVisible(i)) return;
    const pts = chart.getDatasetMeta(i).data;
    if (!pts.length) return;
    let yAt;
    if (pts.length === 1) yAt = pts[0].y;
    else { // interpolate the line's height at the mouse x
      let j = 0;
      while (j < pts.length - 2 && x > pts[j + 1].x) j++;
      const p = pts[j], q = pts[j + 1];
      const t = Math.min(1, Math.max(0, (x - p.x) / ((q.x - p.x) || 1)));
      yAt = p.y + (q.y - p.y) * t;
    }
    const d = Math.abs(y - yAt);
    if (!best || d < best.d) best = { dataset: i, d };
  });
  if (!best) return null;
  if (trendFocus === null && best.d > HIT_RADIUS) return null; // when one line is isolated, any hover inside the chart counts
  const pts = chart.getDatasetMeta(best.dataset).data;
  let index = 0, dist = Infinity;
  pts.forEach((p, k) => { const d = Math.abs(p.x - x); if (d < dist) { dist = d; index = k; } });
  return { dataset: best.dataset, index };
}

function animateAlpha(chart) { // eases every line's opacity toward its target (hovered = 1, others = 0.15)
  if (prefersReducedMotion) {
    chart.data.datasets.forEach((_, i) => { chart.$alpha[i] = (chart.$hoverIdx == null || chart.$hoverIdx === i) ? 1 : 0.15; });
    chart.draw(); return;
  }
  if (chart.$alphaRaf) return; // a loop is already running; it reads the newest targets itself
  let last = performance.now();
  const step = (now) => {
    const k = 1 - Math.exp(-(now - last) / 80); last = now; // time-based smoothing = same speed on any screen
    let moving = false;
    chart.data.datasets.forEach((_, i) => {
      const target = (chart.$hoverIdx == null || chart.$hoverIdx === i) ? 1 : 0.15;
      const current = chart.$alpha[i] === undefined ? 1 : chart.$alpha[i];
      const next = current + (target - current) * k;
      if (Math.abs(target - next) < 0.01) chart.$alpha[i] = target; else { chart.$alpha[i] = next; moving = true; }
    });
    chart.draw();
    chart.$alphaRaf = moving ? requestAnimationFrame(step) : null;
  };
  chart.$alphaRaf = requestAnimationFrame(step);
}

function setTrendHover(index) { // highlight one line (index) or restore all (null)
  const chart = charts.trend;
  if (!chart || (chart.$hoverIdx === undefined ? null : chart.$hoverIdx) === index) return;
  chart.$hoverIdx = index;
  chart.data.datasets.forEach((ds, k) => { ds.borderWidth = (index !== null && k === index) ? 3.6 : 2; }); // hovered line gets thicker
  if (performance.now() >= (chart.$busyUntil || 0)) chart.update("active"); // animates the thickness change
  animateAlpha(chart);
}

function clearTrendHover() {
  const chart = charts.trend;
  if (!chart) return;
  $("trend-tip").classList.remove("show");
  chart.$marker = null;
  setTrendHover(null);
  chart.draw();
}

function showTrendTip(chart, di, idx, x, y) { // tooltip with details for ONE attack type only
  const ds = chart.data.datasets[di], color = ds._color;
  const point = chart.getDatasetMeta(di).data[idx];
  chart.$marker = { x: point.x, y: point.y, color };
  chart.draw();

  const val = ds.data[idx];
  const dayTotal = chart.data.datasets.reduce((s, d) => s + (d.data[idx] || 0), 0);
  const share = dayTotal ? Math.round((val / dayTotal) * 100) : 0;
  const total = ds.data.reduce((a, b) => a + b, 0);
  let peak = 0; ds.data.forEach((v, k) => { if (v > ds.data[peak]) peak = k; });
  const unit = chart.$unit === "hour" ? "hour" : "day";
  let change = "<b>&mdash;</b>";
  if (idx > 0) {
    const d = val - ds.data[idx - 1];
    change = d === 0 ? "<b>no change</b>" : '<b class="' + (d > 0 ? "tip-up" : "tip-down") + '">' + (d > 0 ? "\u25B2 +" : "\u25BC ") + Math.abs(d) + "</b>";
  }

  const tip = $("trend-tip");
  tip.style.setProperty("--c", color);
  tip.innerHTML =
    '<div class="tip-head"><span class="tip-dot"></span>' + escapeHtml(ds.label) + "</div>" +
    '<div class="tip-date">' + escapeHtml(chart.data.labels[idx]) + "</div>" +
    '<div class="tip-big">' + val.toLocaleString() + "<small>incidents</small></div>" +
    '<div class="tip-rows">' +
    "<div><span>Share of the " + unit + "</span><b>" + share + "%</b></div>" +
    "<div><span>vs previous " + unit + "</span>" + change + "</div>" +
    "<div><span>Total in period</span><b>" + total.toLocaleString() + "</b></div>" +
    "<div><span>Peak</span><b>" + escapeHtml(chart.data.labels[peak]) + " (" + ds.data[peak] + ")</b></div></div>";

  const w = tip.offsetWidth, h = tip.offsetHeight, boxW = chart.canvas.clientWidth, boxH = chart.canvas.clientHeight;
  let px = x + 16; if (px + w > boxW - 4) px = x - w - 16; px = Math.max(4, px);
  let py = y - h - 14; if (py < 4) py = y + 18; py = Math.min(py, boxH - h - 4);
  if (!tip.classList.contains("show")) { // first appearance: jump to position instead of gliding from the corner
    tip.style.transition = "none"; tip.style.transform = "translate3d(" + px + "px," + py + "px,0)";
    void tip.offsetWidth; tip.style.transition = "";
  } else tip.style.transform = "translate3d(" + px + "px," + py + "px,0)";
  tip.classList.add("show");
}

function syncTrendLegend() { // keeps legend chips + subtitle + reset button in step with the chart state
  const chart = charts.trend;
  $("trend-legend").querySelectorAll(".legend-item").forEach((btn) => {
    btn.classList.toggle("active", trendFocus === btn.dataset.label);
    btn.classList.toggle("dim", trendFocus !== null && trendFocus !== btn.dataset.label);
  });
  $("trend-reset").classList.toggle("hidden", trendFocus === null);
  $("trend-subtitle").textContent = (chart && chart.$subtitle ? chart.$subtitle : "") + (trendFocus ? " \u00b7 only " + trendFocus : "");
}

function renderTrendLegend(chart) {
  $("trend-legend").innerHTML = chart.data.datasets.map((ds, i) =>
    '<button type="button" class="legend-item" data-i="' + i + '" data-label="' + escapeHtml(ds.label) + '" style="--c:' + ds._color + '" title="Click to show only ' + escapeHtml(ds.label) + '"><i></i><span>' + escapeHtml(ds.label) + "</span></button>"
  ).join("");
  syncTrendLegend();
}

function applyTrendFocus(chart) { // show only the isolated line (others fade out with Chart.js' built-in hide animation)
  chart.$busyUntil = performance.now() + 700; // pause hover updates while the transition plays
  chart.$hoverIdx = null;
  chart.data.datasets.forEach((ds) => { ds.borderWidth = 2; });
  chart.data.datasets.forEach((ds, i) => {
    const wanted = trendFocus === null || ds.label === trendFocus;
    const visible = chart.isDatasetVisible(i);
    if (wanted && !visible) chart.show(i);
    if (!wanted && visible) chart.hide(i);
  });
  chart.$marker = null; $("trend-tip").classList.remove("show");
  animateAlpha(chart);
  syncTrendLegend();
}

function toggleTrendFocus(label) { // click once = isolate, click again = restore
  if (!charts.trend) return;
  trendFocus = trendFocus === label ? null : label;
  applyTrendFocus(charts.trend);
}

function resetTrendFocus() { // used by the 'Show all lines' button and the Escape key
  if (trendFocus !== null && charts.trend) { trendFocus = null; applyTrendFocus(charts.trend); }
}

function bindTrendInteractions() { // attached ONCE (the canvas element is reused when charts are rebuilt)
  if (trendBound) return;
  trendBound = true;
  const canvas = $("trendChart");

  const locate = (e) => { const r = canvas.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; };
  const onMove = (e) => {
    const chart = charts.trend;
    if (!chart || !chart.data.datasets.length) return;
    const { x, y } = locate(e);
    const hit = trendHit(chart, x, y);
    if (!hit) { clearTrendHover(); canvas.style.cursor = "default"; return; }
    canvas.style.cursor = "pointer";
    setTrendHover(hit.dataset);
    showTrendTip(chart, hit.dataset, hit.index, x, y);
  };
  canvas.addEventListener("pointermove", onMove);
  canvas.addEventListener("pointerdown", (e) => { if (e.pointerType === "touch") onMove(e); }); // touch: tap shows details
  canvas.addEventListener("pointerleave", clearTrendHover);
  canvas.addEventListener("click", (e) => {
    const chart = charts.trend; if (!chart) return;
    const { x, y } = locate(e);
    const hit = trendHit(chart, x, y);
    if (hit) toggleTrendFocus(chart.data.datasets[hit.dataset].label);
  });

  const legend = $("trend-legend");
  legend.addEventListener("mouseover", (e) => { // hovering a legend chip highlights that line too
    const btn = e.target.closest(".legend-item"); const chart = charts.trend;
    if (!btn || !chart) return;
    const i = Number(btn.dataset.i);
    if (chart.isDatasetVisible(i)) setTrendHover(i);
  });
  legend.addEventListener("mouseleave", clearTrendHover);
  legend.addEventListener("click", (e) => { const btn = e.target.closest(".legend-item"); if (btn) toggleTrendFocus(btn.dataset.label); });
  $("trend-reset").addEventListener("click", resetTrendFocus);
}

// ---------------------------------------------------------------- Severity donut: custom clickable legend
function highlightSeverityPill(index) {
  $("severity-legend").querySelectorAll(".legend-pill").forEach((btn, k) => btn.classList.toggle("is-hot", k === index));
}

function renderSeverityLegend(severity, colors) {
  const total = severity.values.reduce((a, b) => a + b, 0);
  $("severity-legend").innerHTML = severity.labels.map((label, i) => {
    const pct = total ? ((severity.values[i] / total) * 100).toFixed(1) : "0.0";
    return '<button type="button" class="legend-pill" data-i="' + i + '" data-label="' + escapeHtml(label) + '" style="--c:' + colors[i] + '" title="Click to show ' + escapeHtml(label) + ' incidents"><i></i><span>' + escapeHtml(label) + "</span><b>" + pct + "%</b></button>";
  }).join("");
}

function bindSeverityLegend() { // attached ONCE
  if (severityBound) return;
  severityBound = true;
  const box = $("severity-legend");
  let lastIndex = -1;
  box.addEventListener("mouseover", (e) => { // hovering a pill pops the matching slice out
    const btn = e.target.closest(".legend-pill"); const chart = charts.severityDonut;
    if (!btn || !chart) return;
    const i = Number(btn.dataset.i);
    if (i === lastIndex) return;
    lastIndex = i;
    chart.setActiveElements([{ datasetIndex: 0, index: i }]);
    chart.update("active");
  });
  box.addEventListener("mouseleave", () => {
    lastIndex = -1;
    const chart = charts.severityDonut; if (!chart) return;
    chart.setActiveElements([]); chart.update("active");
  });
  box.addEventListener("click", (e) => { const btn = e.target.closest(".legend-pill"); if (btn) openIncidentsWith({ severity: btn.dataset.label }); });
}

// ---------------------------------------------------------------- Feeding data into the charts
function updateCharts({ trend, types, severity, ips }) {
  lastChartData = { trend, types, severity, ips };
  const chart = charts.trend;

  // --- multi-line trend ---
  const sameShape = chart.data.datasets.length === trend.datasets.length &&
    chart.data.datasets.every((ds, i) => ds.label === trend.datasets[i].label) &&
    JSON.stringify(chart.data.labels) === JSON.stringify(trend.labels);
  chart.$unit = trend.granularity;
  chart.$subtitle = (trend.granularity === "hour" ? "Incidents per hour" : "Incidents per day") + " by attack type";

  if (sameShape) { // same lines and dates: just morph the numbers smoothly
    chart.data.datasets.forEach((ds, i) => { ds.data = trend.datasets[i].data; });
    chart.update();
  } else { // new shape: rebuild the lines and replay the left-to-right drawing
    if (trendFocus !== null && !trend.datasets.some((d) => d.label === trendFocus)) trendFocus = null;
    chart.data.labels = trend.labels;
    chart.data.datasets = trend.datasets.map((ds, i) => {
      const color = colorForType(ds.label, i);
      return {
        label: ds.label, data: ds.data, _color: color,
        borderColor: color, backgroundColor: color + "33", borderWidth: 2, tension: 0.35, fill: false,
        pointRadius: trend.labels.length <= 16 ? 3 : 0, pointHoverRadius: 0, pointBackgroundColor: color, pointBorderWidth: 0,
        hidden: trendFocus !== null && ds.label !== trendFocus, // keep an isolated line isolated after a refresh
      };
    });
    chart.$alpha = []; chart.$hoverIdx = null; chart.$marker = null;
    chart.update();
    playReveal(chart);
    renderTrendLegend(chart);
  }
  syncTrendLegend();

  // --- severity donut + custom legend ---
  const sevColors = severity.labels.map((l) => SEVERITY_COLORS[l] || "#64748b");
  charts.severityDonut.data.labels = severity.labels;
  charts.severityDonut.data.datasets[0].data = severity.values;
  charts.severityDonut.data.datasets[0].backgroundColor = sevColors;
  charts.severityDonut.$center = { value: severity.values.reduce((a, b) => a + b, 0).toLocaleString(), label: "Total" };
  charts.severityDonut.update();
  renderSeverityLegend(severity, sevColors);

  // --- severity bars ---
  charts.severityBar.data.labels = severity.labels;
  charts.severityBar.data.datasets[0].data = severity.values;
  charts.severityBar.data.datasets[0].backgroundColor = sevColors;
  charts.severityBar.update();

  // --- top attacking IPs ---
  charts.ips.data.labels = ips.labels;
  charts.ips.data.datasets[0].data = ips.values;
  charts.ips.update();

  // --- attack type doughnut ---
  charts.types.data.labels = types.labels;
  charts.types.data.datasets[0].data = types.values;
  charts.types.data.datasets[0].backgroundColor = types.labels.map((l, i) => colorForType(l, i));
  charts.types.update();
}

const VIEW_CHARTS = { overview: ["trend", "severityDonut", "ips"], risk: ["types", "severityBar"] }; // which charts live in which tab

function replayCharts(view) { // replays chart animations whenever a tab opens
  (VIEW_CHARTS[view] || []).forEach((key) => {
    const chart = charts[key];
    if (!chart) return;
    if (key === "trend") clearTrendHover();
    chart.resize(); // charts created while hidden need a fresh size
    chart.reset();
    chart.update();
    if (key === "trend") playReveal(chart);
  });
}