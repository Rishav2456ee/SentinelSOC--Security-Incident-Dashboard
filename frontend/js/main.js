// main.js - the conductor: navigation, clickable KPI cards, theme switcher, live refresh, upload, clear, health check

const VIEWS = {
  overview: { title: "Security Overview", subtitle: "Live incident intelligence & attack trends" },
  alerts: { title: "Alerts", subtitle: "Critical and High severity incidents that need attention" },
  incidents: { title: "Incident Log", subtitle: "Search, filter and explore every parsed event" },
  risk: { title: "Risk Analysis", subtitle: "Which sources and attack types are most dangerous" },
  data: { title: "Upload & Data", subtitle: "Load logs, choose Replace or Append, manage stored data" },
};
let uploadMode = "replace";     // 'replace' or 'append'
let backendWasOnline = true;    // used to refresh the data when the backend comes back
let topAttackType = "";         // remembered so the 'Top Attack Type' card knows what to filter by

// ---------------------------------------------------------------- Theme switcher (System / Light / Dark)
const THEME_KEY = "theme";
const systemDark = window.matchMedia("(prefers-color-scheme: dark)");

function getThemePref() { // saved choice, or 'system' the first time
  try { return localStorage.getItem(THEME_KEY) || "system"; } catch (e) { return "system"; }
}

function applyTheme(pref, animate) { // sets the theme on <html>; CSS variables do the rest
  const root = document.documentElement;
  const resolved = pref === "system" ? (systemDark.matches ? "dark" : "light") : pref;
  const changed = root.dataset.theme !== resolved;
  if (animate && changed && !prefersReducedMotion) { // smooth colour cross-fade for 450 ms
    root.classList.add("theme-anim");
    clearTimeout(applyTheme._timer);
    applyTheme._timer = setTimeout(() => root.classList.remove("theme-anim"), 450);
  }
  root.dataset.theme = resolved;
  root.dataset.themePref = pref;
  const switcher = $("theme-switch");
  switcher.dataset.active = pref; // moves the sliding thumb
  switcher.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.theme === pref)));
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = resolved === "dark" ? "#0a1122" : "#eef2f9";
  if (changed && charts.trend) rebuildCharts(); // charts read their colours from CSS variables
}

// ---------------------------------------------------------------- Navigation (SPA tab switching)
function showView(name) {
  if (!VIEWS[name]) name = "overview";
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.dataset.view === name));
  document.querySelectorAll(".nav-item").forEach((a) => {
    const on = a.dataset.view === name;
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  $("page-title").textContent = VIEWS[name].title;
  $("page-subtitle").textContent = VIEWS[name].subtitle;
  document.body.classList.remove("sidebar-open");
  window.scrollTo({ top: 0 });
  requestAnimationFrame(() => replayCharts(name));
}

function navigate(name) { // changes the #hash (so Back works); if already there, just re-show
  if (location.hash !== "#" + name) location.hash = "#" + name; else showView(name);
}

function openIncidentsWith(filters) { // used by IP clicks, global search, KPI cards, donut slices, bars
  const f = filters || {};
  $("global-search").value = f.search || ""; // keep the top search box in sync
  tables.explorer.setFilters(f);
  navigate("incidents");
}

function syncAlertsSeg(severity) { // highlights the right All / Critical / High button
  $("alerts-seg").querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.sev === severity));
}

function openAlertsWith(severity) {
  tables.alerts.setFilters({ severity });
  syncAlertsSeg(severity);
  navigate("alerts");
}

function flashPanel(id) { // brief glow so the user sees where they landed
  const el = $(id);
  if (!el) return;
  el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 1600);
}

function goKpi(kind) { // what each KPI card does when clicked
  if (kind === "total") openIncidentsWith({});                                   // everything, filters reset
  else if (kind === "critical") openAlertsWith("Critical");                      // Alerts tab, Critical only
  else if (kind === "ips") { navigate("risk"); flashPanel("risk-panel"); }       // unique IPs breakdown
  else if (kind === "top") openIncidentsWith(topAttackType && topAttackType !== "N/A" ? { attackType: topAttackType } : {});
}

function toggleSidebar() {
  if (window.matchMedia("(max-width: 1023px)").matches) {
    document.body.classList.toggle("sidebar-open");
  } else {
    const collapsed = document.body.classList.toggle("sidebar-collapsed");
    try { localStorage.setItem("sidebarCollapsed", collapsed ? "1" : "0"); } catch (e) { /* storage may be blocked */ }
    setTimeout(() => window.dispatchEvent(new Event("resize")), 420); // let charts re-fit after the animation
  }
}

// ---------------------------------------------------------------- Rendering data
function updateAlertBadge(count) {
  const badge = $("alerts-badge");
  const text = count > 999 ? "999+" : String(count);
  if (badge.textContent !== text) { badge.textContent = text; badge.classList.remove("pop"); void badge.offsetWidth; badge.classList.add("pop"); }
  badge.classList.toggle("hidden", count === 0);
}

function updateKpis(k) {
  topAttackType = k.top_attack_type;
  animateNumber($("kpi-total"), k.total_incidents);
  animateNumber($("kpi-critical"), k.critical_alerts);
  animateNumber($("kpi-ips"), k.unique_attacking_ips);
  $("kpi-top").textContent = k.top_attack_type;
  $("kpi-top").title = k.top_attack_type;
  $("kpi-top-count").textContent = k.top_attack_count.toLocaleString() + (k.top_attack_count === 1 ? " occurrence" : " occurrences");
  renderSparkline($("spark-total"), k.spark.total, "#38bdf8");
  renderSparkline($("spark-critical"), k.spark.critical, "#f87171");
  renderSparkline($("spark-ips"), k.spark.ips, "#fbbf24");
  renderSparkline($("spark-top"), k.spark.top, "#c084fc");
  animateNumber($("alerts-critical"), k.critical_alerts);
  animateNumber($("alerts-high"), k.high_alerts);
  animateNumber($("alerts-total"), k.alert_count);
  updateAlertBadge(k.alert_count);
}

function renderRisk(data, uniqueCount) { // risk ranking of ALL unique attacking IPs (up to 20)
  const list = $("risk-list");
  $("risk-sub").textContent = data.items.length
    ? "Showing " + data.items.length + " of " + uniqueCount.toLocaleString() + " unique IPs \u00b7 score out of 100"
    : "Risk score out of 100";
  if (!data.items.length) { list.innerHTML = '<p class="hint">No source IPs to score yet. Upload a log file.</p>'; return; }
  list.innerHTML = data.items.map((it) => {
    const tier = it.level.toLowerCase();
    return '<div class="risk-row">' +
      '<div class="risk-head">' + ipLink(it.ip) + '<span class="risk-score txt-' + tier + '">' + it.score + " / 100 &middot; " + escapeHtml(it.level) + "</span></div>" +
      '<div class="risk-bar"><div class="risk-fill fill-' + tier + '" data-w="' + it.score + '"></div></div>' +
      '<div class="risk-meta">' + it.incidents.toLocaleString() + " incidents &middot; " + it.critical.toLocaleString() + " critical &middot; main attack: " + escapeHtml(it.top_attack) + " &middot; last seen " + escapeHtml(it.last_seen) + "</div></div>";
  }).join("");
  requestAnimationFrame(() => requestAnimationFrame(() => { // two frames later, set the width so the CSS transition animates it
    list.querySelectorAll(".risk-fill").forEach((bar) => { bar.style.width = bar.dataset.w + "%"; });
  }));
}

function renderStats(stats) {
  animateNumber($("stat-rows"), stats.total);
  animateNumber($("stat-ips"), stats.unique_ips);
  animateNumber($("stat-types"), stats.attack_types);
  $("stat-range").textContent = stats.first_event ? stats.first_event.slice(0, 10) + " \u2192 " + stats.last_event.slice(0, 10) : "\u2014";
  $("stat-size").textContent = stats.db_size_kb.toLocaleString() + " KB";
  $("files-body").innerHTML = stats.files.length
    ? stats.files.map((f) => '<tr class="incident-row"><td>' + escapeHtml(f.name) + "</td><td>" + f.row_count.toLocaleString() + "</td></tr>").join("")
    : '<tr><td colspan="2" class="empty-cell">No files loaded.</td></tr>';
}

async function refreshAll() { // re-fetches EVERYTHING and updates the page in place (no reload)
  const [kpis, trend, types, severity, ips, risk, stats] = await Promise.all([
    Api.getKpis(), Api.getTrendByType(), Api.getAttackTypes(), Api.getSeverity(), Api.getTopIps(), Api.getRisk(20), Api.getStats(),
  ]);
  updateKpis(kpis);
  updateCharts({ trend, types, severity, ips });
  renderRisk(risk, kpis.unique_attacking_ips);
  renderStats(stats);
  $("empty-banner").classList.toggle("hidden", kpis.total_incidents > 0);
  await populateFilters();
  await Promise.all([tables.recent.load(), tables.alerts.load(), tables.explorer.load()]);
  $("last-updated").textContent = " \u00b7 updated " + new Date().toLocaleTimeString();
}

// ---------------------------------------------------------------- Upload and clear
function setUploading(isBusy) {
  $("dropzone").classList.toggle("busy", isBusy);
  $("quick-upload").classList.toggle("is-loading", isBusy);
  $("quick-upload").querySelector(".btn-text").textContent = isBusy ? "Processing..." : "Upload";
}

async function handleUpload(file) {
  if (!/\.(csv|json|log|txt)$/i.test(file.name)) { showToast("Only .csv, .json, .log and .txt files are allowed.", "error"); return; }
  if (file.size > 20 * 1024 * 1024) { showToast("File too large. Maximum size is 20 MB.", "error"); return; }
  setUploading(true);
  try {
    const result = await Api.uploadFile(file, uploadMode);
    Object.values(tables).forEach((t) => { t.state.page = 1; });
    await refreshAll();
    let message = result.inserted.toLocaleString() + " incidents loaded from " + result.filename + " (" + (result.mode === "append" ? "added" : "replaced") + ").";
    if (result.skipped > 0) message += " " + result.skipped + " rows skipped (no valid timestamp).";
    showToast(message, "success");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setUploading(false);
    $("file-input").value = "";
  }
}

async function handleClear() {
  if (!confirm("Delete all stored incidents? This cannot be undone.")) return;
  try {
    await Api.clearData();
    Object.values(tables).forEach((t) => { t.state.page = 1; });
    await refreshAll();
    showToast("All incidents cleared.", "success");
  } catch (error) {
    showToast(error.message, "error");
  }
}

// ---------------------------------------------------------------- Backend health pill
async function checkHealth() {
  const pill = $("status-pill");
  try {
    await Api.health();
    pill.classList.remove("offline");
    $("status-text").textContent = "Backend Connected";
    if (!backendWasOnline) { backendWasOnline = true; refreshAll().catch(() => {}); }
  } catch (error) {
    backendWasOnline = false;
    pill.classList.add("offline");
    $("status-text").textContent = "Backend Offline";
  }
}

// ---------------------------------------------------------------- Start-up
document.addEventListener("DOMContentLoaded", () => {
  try { if (localStorage.getItem("sidebarCollapsed") === "1") document.body.classList.add("sidebar-collapsed"); } catch (e) { /* ignore */ }
  if (/Mac/i.test(navigator.platform)) $("kbd-hint").textContent = "\u2318 K";

  applyTheme(getThemePref(), false); // sync the switcher with the saved theme (before charts are created)
  $("theme-switch").addEventListener("click", (e) => {
    const button = e.target.closest("button[data-theme]");
    if (!button) return;
    try { localStorage.setItem(THEME_KEY, button.dataset.theme); } catch (err) { /* storage may be blocked */ }
    applyTheme(button.dataset.theme, true);
  });
  systemDark.addEventListener("change", () => { if (getThemePref() === "system") applyTheme("system", true); }); // follows the OS live

  initCharts();
  initTables();

  $("menu-btn").addEventListener("click", toggleSidebar);
  $("sidebar-overlay").addEventListener("click", () => document.body.classList.remove("sidebar-open"));
  window.addEventListener("hashchange", () => showView(location.hash.slice(1)));
  showView(location.hash.slice(1));

  document.querySelectorAll(".kpi[data-goto]").forEach((card) => { // clickable KPI cards (mouse + keyboard)
    card.addEventListener("click", () => goKpi(card.dataset.goto));
    card.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); goKpi(card.dataset.goto); } });
  });

  $("global-search-form").addEventListener("submit", (e) => {
    e.preventDefault();
    openIncidentsWith({ search: $("global-search").value.trim() });
    $("global-search").blur();
  });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); $("global-search").focus(); $("global-search").select(); }
    else if (e.key === "Escape") {
      document.body.classList.remove("sidebar-open");
      if (document.activeElement === $("global-search")) document.activeElement.blur();
      resetTrendFocus(); // Escape also restores all trend lines
    }
  });
  document.addEventListener("click", (e) => { // any IP button (tables or risk bars) opens its incidents
    const button = e.target.closest(".ip-link");
    if (button) openIncidentsWith({ search: button.dataset.ip });
  });

  $("file-input").addEventListener("change", (e) => { if (e.target.files[0]) handleUpload(e.target.files[0]); });
  const dropzone = $("dropzone");
  dropzone.addEventListener("click", () => $("file-input").click());
  dropzone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file-input").click(); } });
  ["dragenter", "dragover"].forEach((type) => dropzone.addEventListener(type, (e) => { e.preventDefault(); dropzone.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach((type) => dropzone.addEventListener(type, (e) => { e.preventDefault(); dropzone.classList.remove("dragover"); }));
  dropzone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 1) showToast("Only the first file was used.", "success");
    if (files[0]) handleUpload(files[0]);
  });
  ["dragover", "drop"].forEach((type) => window.addEventListener(type, (e) => e.preventDefault()));

  $("mode-seg").addEventListener("click", (e) => {
    const button = e.target.closest("button[data-mode]");
    if (!button) return;
    uploadMode = button.dataset.mode;
    $("mode-seg").querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === button));
    $("mode-hint").textContent = uploadMode === "replace"
      ? "Replace: the old incidents are deleted and only the new file is analysed."
      : "Add: the new file is combined with the incidents already stored.";
    $("quick-upload").title = "Upload a log file (mode: " + (uploadMode === "replace" ? "Replace" : "Add") + ")";
  });
  $("clear-btn").addEventListener("click", handleClear);

  refreshAll().catch(() => showToast("Cannot reach the server. Is the Flask app running?", "error"));
  checkHealth();
  setInterval(checkHealth, 8000);
});