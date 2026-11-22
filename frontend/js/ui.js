// ui.js - small reusable helpers: DOM shortcut, safe HTML, toast, animated numbers, sparklines

const $ = (id) => document.getElementById(id); // shortcut: $("kpi-total") instead of document.getElementById(...)

const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches; // user turned animations off?

function escapeHtml(value) { // makes untrusted log text safe to put inside HTML (prevents XSS)
  return String(value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function debounce(callback, delay) { // waits until the user stops typing before running the callback
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => callback(...args), delay); };
}

let toastTimer; // remembers the timer that hides the pop-up
function showToast(message, type) { // shows a temporary message (green = success, red = error)
  const toast = $("toast");
  toast.textContent = message; // textContent is safe against HTML injection
  toast.className = "toast " + (type === "error" ? "toast-error" : "toast-success");
  void toast.offsetWidth; // force a reflow so the slide-in animation replays every time
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 4500); // hide after 4.5 seconds
}

function animateNumber(element, target, duration = 900) { // counts smoothly from the OLD value to the NEW value
  if (!element) return;
  if (element._raf) cancelAnimationFrame(element._raf); // stop any animation still running on this element
  const from = element._current || 0; // the number currently shown
  const to = Number(target) || 0; // the number we want to reach
  if (prefersReducedMotion || from === to) { element._current = to; element.textContent = to.toLocaleString(); return; }
  const startTime = performance.now();
  function step(now) { // runs on every animation frame
    const progress = Math.min((now - startTime) / duration, 1); // 0 -> 1
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out: fast start, gentle finish
    element._current = Math.round(from + (to - from) * eased);
    element.textContent = element._current.toLocaleString();
    element._raf = progress < 1 ? requestAnimationFrame(step) : null;
  }
  element._raf = requestAnimationFrame(step);
}

function renderSparkline(element, values, color) { // draws a tiny SVG line graph inside a KPI card
  if (!element) return;
  let points = values && values.length ? values.slice() : [0, 0]; // no data -> flat line
  if (points.length === 1) points = [points[0], points[0]]; // a line needs at least 2 points
  const width = 100, height = 32, pad = 3; // the SVG's internal coordinate system
  const min = Math.min(...points), max = Math.max(...points);
  const coords = points.map((value, i) => [ // convert each value to an (x, y) position
    (i / (points.length - 1)) * width,
    max === min ? height / 2 : height - pad - ((value - min) / (max - min)) * (height - pad * 2),
  ]);
  const line = coords.map((c, i) => (i ? "L" : "M") + c[0].toFixed(1) + " " + c[1].toFixed(1)).join(" "); // path text
  const area = line + " L" + width + " " + height + " L0 " + height + " Z"; // closed shape for the soft fill
  element.innerHTML =
    '<svg viewBox="0 0 ' + width + " " + height + '" preserveAspectRatio="none" aria-hidden="true">' +
    '<path class="spark-area" d="' + area + '" fill="' + color + '"/>' +
    '<path class="spark-line" d="' + line + '" pathLength="1" stroke="' + color + '"/></svg>'; // CSS animates the drawing
}