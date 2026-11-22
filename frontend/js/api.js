// api.js - the ONLY file that talks to the Flask backend (all fetch calls live here)

const API_BASE = ""; // empty because the page and the API are served from the same address

async function apiRequest(url, options = {}) { // shared helper: sends a request and returns the JSON reply
  const response = await fetch(API_BASE + url, options); // send the HTTP request (this is the AJAX call)
  let data = {}; // default empty object in case the reply has no JSON
  try { data = await response.json(); } catch (error) { data = {}; } // convert the reply text to an object
  if (!response.ok) { // 4xx and 5xx status codes
    throw new Error(data.error || "Request failed (" + response.status + ")"); // show the server's message in the UI
  }
  return data;
}

const Api = { // one object that groups all backend calls, e.g. Api.getKpis()
  health() { return apiRequest("/api/health"); }, // is the backend alive?

  uploadFile(file, mode) { // sends a log file to the backend
    const formData = new FormData(); // FormData is the standard way to send files
    formData.append("file", file); // the backend reads request.files['file']
    formData.append("mode", mode); // 'replace' or 'append'
    return apiRequest("/api/upload", { method: "POST", body: formData });
  },

  getKpis() { return apiRequest("/api/kpis"); }, // KPI numbers, alert count and sparklines
  getTrendByType() { return apiRequest("/api/charts/trend-by-type"); }, // one line per attack type
  getAttackTypes() { return apiRequest("/api/charts/attack-types"); }, // doughnut data
  getSeverity() { return apiRequest("/api/charts/severity"); }, // severity counts
  getTopIps() { return apiRequest("/api/charts/top-ips"); }, // top attackers chart
  getRisk(limit) { return apiRequest("/api/risk/ips?limit=" + (limit || 8)); }, // risk scores
  getStats() { return apiRequest("/api/stats"); }, // database statistics
  getFilters() { return apiRequest("/api/filters"); }, // dropdown options

  getIncidents(params) { // table rows with search, filters and paging
    const query = new URLSearchParams(); // builds a safe query string like ?search=ssh&page=2
    Object.entries(params).forEach(([key, value]) => {
      if (value !== "" && value !== null && value !== undefined) query.append(key, value); // skip empty values
    });
    return apiRequest("/api/incidents?" + query.toString());
  },

  clearData() { return apiRequest("/api/incidents", { method: "DELETE" }); }, // delete all incidents
};