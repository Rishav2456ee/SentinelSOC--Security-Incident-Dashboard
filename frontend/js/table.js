// table.js - one reusable table class, used for: Recent incidents, Alerts, and the Incident Log explorer

function severityBadge(severity) { // coloured severity label
  return '<span class="badge badge-' + escapeHtml(String(severity).toLowerCase()) + '">' + escapeHtml(severity) + "</span>";
}

function statusBadge(status) { // coloured status label (green = handled, amber = open, blue = being investigated)
  const s = String(status).toLowerCase();
  let css = "st-neutral";
  if (["resolved", "blocked", "mitigated", "quarantined", "isolated", "closed", "contained"].includes(s)) css = "st-good";
  else if (["open", "alerted", "new", "active"].includes(s)) css = "st-warn";
  else if (["investigating", "triaged", "in progress"].includes(s)) css = "st-info";
  return '<span class="badge ' + css + '">' + escapeHtml(status) + "</span>";
}

function ipLink(ip) { // clickable source IP: clicking it opens the Incident Log filtered by that IP
  if (!ip || ip === "Unknown") return '<span class="ip-plain">Unknown</span>';
  return '<button type="button" class="ip-link" data-ip="' + escapeHtml(ip) + '" title="Show all incidents from ' + escapeHtml(ip) + '">' + escapeHtml(ip) + "</button>";
}

class IncidentTable {
  constructor(opts) { // opts = which HTML elements to use and how this table behaves
    this.opts = opts;
    this.state = { page: 1, perPage: opts.perPage || 10, search: "", severity: "", attackType: "" }; // current filters
    this.inputs = {}; // filter controls (filled by bindControls)
    this.body = $(opts.bodyId);
    this.count = opts.countId ? $(opts.countId) : null;
    this.pageInfo = opts.pageInfoId ? $(opts.pageInfoId) : null;
    this.prev = opts.prevId ? $(opts.prevId) : null;
    this.next = opts.nextId ? $(opts.nextId) : null;
    if (this.prev) this.prev.addEventListener("click", () => { this.state.page = Math.max(1, this.state.page - 1); this.reload(); });
    if (this.next) this.next.addEventListener("click", () => { this.state.page += 1; this.reload(); }); // server clamps to last page
  }

  reload() { // load and show errors as a toast instead of crashing
    return this.load().catch((error) => showToast(error.message, "error"));
  }

  async load() { // fetch the current page from the backend and draw it
    const data = await Api.getIncidents({
      search: this.state.search,
      severity: this.state.severity,
      attack_type: this.state.attackType,
      page: this.state.page,
      per_page: this.state.perPage,
      alerts_only: this.opts.alertsOnly ? 1 : "", // the Alerts table only asks for Critical + High
    });
    this.state.page = data.page; // the server may correct an out-of-range page
    this.renderRows(data.items);
    if (this.count) this.count.textContent = data.total.toLocaleString() + (data.total === 1 ? " incident" : " incidents");
    if (this.pageInfo) this.pageInfo.textContent = "Page " + data.page + " of " + data.pages;
    if (this.prev) this.prev.disabled = data.page <= 1;
    if (this.next) this.next.disabled = data.page >= data.pages;
  }

  renderRows(items) { // builds the <tbody> HTML (every value goes through escapeHtml)
    const columns = this.opts.compact ? 6 : 7;
    if (!items.length) {
      this.body.innerHTML = '<tr><td colspan="' + columns + '" class="empty-cell">' + escapeHtml(this.opts.emptyText || "No incidents match your filters.") + "</td></tr>";
      return;
    }
    this.body.innerHTML = items.map((item, i) => this.opts.compact ? this.compactRow(item, i) : this.fullRow(item, i)).join("");
  }

  fullRow(item, i) { // 7 columns; some hide on small screens through CSS classes
    return '<tr class="incident-row" style="--i:' + i + '">' +
      '<td class="nowrap muted">' + escapeHtml(item.timestamp) + "</td>" +
      "<td>" + ipLink(item.source_ip) + "</td>" +
      '<td class="hide-md"><span class="ip-plain">' + escapeHtml(item.destination_ip) + "</span></td>" +
      '<td class="nowrap">' + escapeHtml(item.attack_type) + "</td>" +
      "<td>" + severityBadge(item.severity) + "</td>" +
      '<td class="hide-md">' + statusBadge(item.status) + "</td>" +
      '<td class="desc hide-lg" title="' + escapeHtml(item.description) + '">' + escapeHtml(item.description) + "</td></tr>";
  }

  compactRow(item, i) { // 6 columns for the 'Recent Security Incidents' panel
    return '<tr class="incident-row" style="--i:' + i + '">' +
      '<td class="nowrap muted">' + escapeHtml(item.timestamp.slice(5, 16)) + "</td>" +
      '<td class="nowrap">' + escapeHtml(item.attack_type) + "</td>" +
      "<td>" + ipLink(item.source_ip) + "</td>" +
      '<td class="hide-sm"><span class="ip-plain">' + escapeHtml(item.destination_ip) + "</span></td>" +
      "<td>" + severityBadge(item.severity) + "</td>" +
      '<td class="hide-md">' + statusBadge(item.status) + "</td></tr>";
  }

  setFilters({ search = "", severity = "", attackType = "" } = {}) { // apply filters from code (global search, IP click)
    Object.assign(this.state, { search, severity, attackType, page: 1 });
    if (this.inputs.search) this.inputs.search.value = search; // keep the visible controls in sync
    if (this.inputs.severity) this.inputs.severity.value = severity;
    if (this.inputs.type) this.inputs.type.value = attackType;
    return this.reload();
  }

  bindControls(ids) { // connects search box, dropdowns, segmented buttons and reset button
    if (ids.searchId) {
      this.inputs.search = $(ids.searchId);
      this.inputs.search.addEventListener("input", debounce((e) => { // wait 300 ms after the last keystroke
        this.state.search = e.target.value.trim(); this.state.page = 1; this.reload();
      }, 300));
    }
    if (ids.severityId) {
      this.inputs.severity = $(ids.severityId);
      this.inputs.severity.addEventListener("change", (e) => { this.state.severity = e.target.value; this.state.page = 1; this.reload(); });
    }
    if (ids.typeId) {
      this.inputs.type = $(ids.typeId);
      this.inputs.type.addEventListener("change", (e) => { this.state.attackType = e.target.value; this.state.page = 1; this.reload(); });
    }
    if (ids.perPageId) {
      $(ids.perPageId).addEventListener("change", (e) => { this.state.perPage = Number(e.target.value); this.state.page = 1; this.reload(); });
    }
    if (ids.resetId) {
      $(ids.resetId).addEventListener("click", () => { // clear every filter
        this.setFilters({});
      });
    }
    if (ids.segId) { // Critical / High / All buttons in the Alerts tab
      const seg = $(ids.segId);
      seg.addEventListener("click", (e) => {
        const button = e.target.closest("button[data-sev]");
        if (!button) return;
        seg.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === button));
        this.state.severity = button.dataset.sev; this.state.page = 1; this.reload();
      });
    }
  }
}

const tables = {}; // tables.recent, tables.alerts, tables.explorer

function initTables() { // creates the three table objects (called once at start-up)
  tables.recent = new IncidentTable({ bodyId: "recent-body", compact: true, perPage: 6, emptyText: "No incidents yet. Upload a log file to begin." });

  tables.alerts = new IncidentTable({
    bodyId: "alerts-body", countId: "alerts-count", pageInfoId: "alerts-page-info", prevId: "alerts-prev", nextId: "alerts-next",
    alertsOnly: true, perPage: 10, emptyText: "No Critical or High alerts found.",
  });
  tables.alerts.bindControls({ searchId: "alerts-search", segId: "alerts-seg" });

  tables.explorer = new IncidentTable({
    bodyId: "explorer-body", countId: "explorer-count", pageInfoId: "explorer-page-info", prevId: "explorer-prev", nextId: "explorer-next", perPage: 10,
  });
  tables.explorer.bindControls({ searchId: "search-input", severityId: "severity-filter", typeId: "type-filter", perPageId: "per-page", resetId: "reset-filters" });
}

async function populateFilters() { // fills the Incident Log dropdowns with values that really exist in the data
  const options = await Api.getFilters();
  const table = tables.explorer;
  const sev = $("severity-filter"), typ = $("type-filter");
  sev.innerHTML = '<option value="">All severities</option>' + options.severities.map((s) => '<option value="' + escapeHtml(s) + '">' + escapeHtml(s) + "</option>").join("");
  typ.innerHTML = '<option value="">All attack types</option>' + options.attack_types.map((t) => '<option value="' + escapeHtml(t) + '">' + escapeHtml(t) + "</option>").join("");
  if (!options.severities.includes(table.state.severity)) table.state.severity = ""; // reset a filter that no longer exists
  if (!options.attack_types.includes(table.state.attackType)) table.state.attackType = "";
  sev.value = table.state.severity;
  typ.value = table.state.attackType;
}