"use strict";

/* ---------- tiny helpers ------------------------------------------------ */

const $ = (sel, root = document) => root.querySelector(sel);

const store = {
  get(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw == null ? fallback : JSON.parse(raw);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      /* private mode / quota - ignore */
    }
  },
};

async function api(path, options) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

/* ---------- saved device inventory ---------------------------------- */

let inventoryCache = null;

async function loadInventory(force) {
  if (force) inventoryCache = null;
  if (!inventoryCache) {
    inventoryCache = api("/api/inventory")
      .then((d) => d.devices || [])
      .catch(() => []);
  }
  return inventoryCache;
}

async function addDevicePicker(view, form) {
  const devices = await loadInventory();
  if (!devices.length) return;

  const wrap = document.createElement("div");
  wrap.className = "field field-wide device-picker";
  const label = document.createElement("label");
  label.textContent = "Saved device";
  const select = document.createElement("select");
  select.innerHTML = '<option value="">— enter manually —</option>';
  for (const dev of devices) {
    const opt = document.createElement("option");
    opt.value = dev.host;
    opt.textContent = dev.name ? `${dev.name} (${dev.host})` : dev.host;
    select.append(opt);
  }
  const communityInput = form.querySelector('[name="community"]');
  const communityRequired = communityInput ? communityInput.required : false;
  select.addEventListener("change", () => {
    const dev = devices.find((d) => d.host === select.value);
    const hostInput = form.querySelector('[name="host"], [name="range"]');
    if (dev && hostInput) hostInput.value = dev.host;
    if (communityInput) {
      if (dev && dev.has_community) {
        communityInput.value = "";
        communityInput.placeholder = "using the saved community";
        communityInput.required = false;
      } else {
        communityInput.placeholder = "read-only community";
        communityInput.required = communityRequired;
      }
    }
  });
  wrap.append(label, select);
  form.querySelector(".fields").prepend(wrap);
}

/* ---------- theme ----------------------------------------------------- */

const THEME_KEY = "netprobe:theme";

function applyTheme(mode) {
  if (mode === "light" || mode === "dark") {
    document.documentElement.setAttribute("data-theme", mode);
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

function initTheme() {
  applyTheme(store.get(THEME_KEY, null));
  $("#theme-toggle").addEventListener("click", () => {
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const current =
      document.documentElement.getAttribute("data-theme") ||
      (prefersDark ? "dark" : "light");
    const next = current === "dark" ? "light" : "dark";
    store.set(THEME_KEY, next);
    applyTheme(next);
  });
}

/* ---------- app state ------------------------------------------------- */

const listEl = $("#tool-list");
const workspaceEl = $("#workspace");
const viewTpl = $("#tool-view");

let tools = [];
let activeName = null;

const paramsKey = (name) => `netprobe:params:${name}`;
const historyKey = (name) => `netprobe:history:${name}`;
const HISTORY_LIMIT = 10;

function renderNav() {
  listEl.replaceChildren();
  let currentCategory = null;
  let groupEl = null;
  for (const tool of tools) {
    const category = tool.category || "Tools";
    if (category !== currentCategory) {
      currentCategory = category;
      const cat = document.createElement("div");
      cat.className = "nav-cat";
      const label = document.createElement("span");
      label.className = "nav-group-label";
      label.textContent = category;
      groupEl = document.createElement("div");
      groupEl.className = "nav-group";
      cat.append(label, groupEl);
      listEl.append(cat);
    }
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = tool.title;
    btn.setAttribute("aria-current", String(tool.name === activeName));
    btn.addEventListener("click", () => selectTool(tool.name));
    groupEl.append(btn);
  }
}

/* ---------- one tool view ------------------------------------------------ */

function selectTool(name) {
  const tool = tools.find((t) => t.name === name);
  if (!tool) return;
  activeName = name;
  if (location.hash !== `#${name}`) location.hash = name;
  renderNav();

  const view = viewTpl.content.firstElementChild.cloneNode(true);
  $(".tool-title", view).textContent = tool.title;
  $(".tool-desc", view).textContent = tool.description;

  const form = $(".tool-form", view);
  const fieldsEl = $(".fields", view);
  const saved = store.get(paramsKey(name), {});

  for (const field of tool.fields) {
    const wrap = document.createElement("div");
    wrap.className = "field";

    const id = `f-${name}-${field.name}`;
    const label = document.createElement("label");
    label.textContent = field.label;
    label.htmlFor = id;

    const input = document.createElement(
      field.type === "textarea" ? "textarea" : "input"
    );
    input.id = id;
    input.name = field.name;
    if (field.type === "textarea") {
      input.rows = 4;
    } else if (field.type === "password") {
      input.type = "password";
      input.autocomplete = "off";
    } else {
      input.type = field.type === "number" ? "number" : "text";
      if (field.type === "number") input.step = "any";
    }
    if (field.placeholder) input.placeholder = field.placeholder;
    if (field.required) input.required = true;
    // password fields are never persisted, so never pre-filled from storage
    const initial =
      field.type !== "password" && saved[field.name] != null && saved[field.name] !== ""
        ? saved[field.name]
        : field.default;
    if (initial != null && initial !== "") input.value = initial;
    if (field.type === "textarea") wrap.classList.add("field-wide");

    wrap.append(label, input);
    if (field.help) {
      const hint = document.createElement("span");
      hint.className = "hint";
      hint.textContent = field.help;
      wrap.append(hint);
    }
    fieldsEl.append(wrap);
  }

  if (tool.category === "Device monitoring") {
    addDevicePicker(view, form);
  }

  const runBtn = $(".run-btn", view);
  const statusEl = $(".run-status", view);
  const errEl = $(".tool-error", view);
  const resultEl = $(".tool-result", view);

  const secretNames = new Set(
    tool.fields.filter((f) => f.type === "password").map((f) => f.name)
  );
  const withoutSecrets = (obj) => {
    const copy = {};
    for (const [k, v] of Object.entries(obj)) if (!secretNames.has(k)) copy[k] = v;
    return copy;
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const params = {};
    for (const [key, value] of new FormData(form)) params[key] = value.trim();
    // never persist secrets (tokens, community strings) to localStorage
    store.set(paramsKey(name), withoutSecrets(params));

    errEl.hidden = true;
    runBtn.disabled = true;
    const started = performance.now();
    const ticker = setInterval(() => {
      statusEl.textContent = `${((performance.now() - started) / 1000).toFixed(1)}s`;
    }, 100);

    try {
      const data = await api(`/api/tools/${name}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params),
      });
      renderResult(view, data);
      if (name === "devices" || name === "snmp-discover") loadInventory(true);
      pushHistory(name, withoutSecrets(params), data);
      renderHistory(view, tool);
    } catch (err) {
      resultEl.hidden = true;
      errEl.textContent = err.message;
      errEl.hidden = false;
    } finally {
      clearInterval(ticker);
      const secs = ((performance.now() - started) / 1000).toFixed(2);
      statusEl.textContent = `done in ${secs}s`;
      runBtn.disabled = false;
    }
  });

  renderHistory(view, tool);
  workspaceEl.replaceChildren(view);
}

/* ---------- result table (sortable + filterable + export) -------------- */

function renderResult(view, data) {
  const resultEl = $(".tool-result", view);
  const summaryEl = $(".result-summary", view);
  const thead = $(".result-table thead", view);
  const tbody = $(".result-table tbody", view);
  const filterEl = $(".result-filter", view);

  summaryEl.textContent = data.summary || `${data.rows.length} row(s)`;
  summaryEl.dataset.level = data.level || "ok";

  const sortState = { col: null, dir: 1 };

  const draw = () => {
    const needle = filterEl.value.trim().toLowerCase();
    let rows = data.rows.filter((r) =>
      !needle || r.some((cell) => String(cell).toLowerCase().includes(needle))
    );
    if (sortState.col != null) {
      const i = sortState.col;
      rows = [...rows].sort((a, b) => {
        const [x, y] = [a[i], b[i]];
        const nx = Number(x);
        const ny = Number(y);
        const cmp =
          !Number.isNaN(nx) && !Number.isNaN(ny)
            ? nx - ny
            : String(x).localeCompare(String(y));
        return cmp * sortState.dir;
      });
    }

    tbody.replaceChildren();
    if (!rows.length) {
      const tr = tbody.insertRow();
      const td = tr.insertCell();
      td.colSpan = data.columns.length || 1;
      td.className = "no-rows";
      td.textContent = needle ? "no rows match the filter" : "no matches";
      return;
    }
    for (const values of rows) {
      const tr = tbody.insertRow();
      values.forEach((value, idx) => {
        const td = tr.insertCell();
        td.textContent = value;
        if (idx === values.length - 1) td.className = "value-cell";
      });
    }
  };

  thead.replaceChildren();
  const headRow = thead.insertRow();
  data.columns.forEach((col, idx) => {
    const th = document.createElement("th");
    th.textContent = col;
    th.scope = "col";
    th.addEventListener("click", () => {
      sortState.dir = sortState.col === idx ? -sortState.dir : 1;
      sortState.col = idx;
      for (const other of headRow.cells) other.removeAttribute("aria-sort");
      th.setAttribute("aria-sort", sortState.dir === 1 ? "ascending" : "descending");
      draw();
    });
    headRow.append(th);
  });

  filterEl.oninput = draw;

  for (const btn of view.querySelectorAll("[data-export]")) {
    btn.onclick = () => exportResult(btn, btn.dataset.export, data);
  }

  draw();
  resultEl.hidden = false;
}

function toCSV(data) {
  const esc = (v) => {
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [data.columns, ...data.rows].map((row) => row.map(esc).join(",")).join("\n");
}

function flashCopied(btn) {
  const original = btn.textContent;
  btn.textContent = "copied";
  btn.classList.add("copied");
  setTimeout(() => {
    btn.textContent = original;
    btn.classList.remove("copied");
  }, 1200);
}

function exportResult(btn, kind, data) {
  if (kind === "json") {
    navigator.clipboard?.writeText(JSON.stringify(data, null, 2)).then(() => flashCopied(btn));
  } else if (kind === "csv") {
    navigator.clipboard?.writeText(toCSV(data)).then(() => flashCopied(btn));
  } else if (kind === "download") {
    const blob = new Blob([toCSV(data)], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `netprobe-${activeName}-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }
}

/* ---------- per-tool run history -------------------------------------- */

function pushHistory(name, params, result) {
  const entries = store.get(historyKey(name), []);
  entries.unshift({ ts: Date.now(), params, result });
  store.set(historyKey(name), entries.slice(0, HISTORY_LIMIT));
}

function renderHistory(view, tool) {
  const section = $(".tool-history", view);
  const listNode = $(".history-list", view);
  const entries = store.get(historyKey(tool.name), []);
  listNode.replaceChildren();
  if (!entries.length) {
    section.hidden = true;
    return;
  }
  for (const entry of entries) {
    const li = document.createElement("li");
    const time = document.createElement("span");
    time.className = "history-time";
    time.textContent = new Date(entry.ts).toLocaleTimeString();
    const summary = document.createElement("span");
    summary.className = "history-summary";
    summary.textContent = entry.result.summary || "(no summary)";
    li.append(time, summary);
    li.addEventListener("click", () => {
      for (const field of tool.fields) {
        const input = $(`#f-${tool.name}-${field.name}`, view);
        if (input && entry.params[field.name] != null) {
          input.value = entry.params[field.name];
        }
      }
      renderResult(view, entry.result);
      $(".tool-error", view).hidden = true;
    });
    listNode.append(li);
  }
  section.hidden = false;
}

/* ---------- boot ------------------------------------------------------ */

initTheme();

window.addEventListener("hashchange", () => {
  const name = location.hash.slice(1);
  if (name && name !== activeName && tools.some((t) => t.name === name)) {
    selectTool(name);
  }
});

api("/api/tools")
  .then((data) => {
    tools = data.tools;
    renderNav();
    if (!tools.length) {
      workspaceEl.innerHTML = '<p class="placeholder">No tools registered.</p>';
      return;
    }
    const wanted = location.hash.slice(1);
    selectTool(tools.some((t) => t.name === wanted) ? wanted : tools[0].name);
  })
  .catch((err) => {
    workspaceEl.innerHTML = `<p class="placeholder">Could not load tools: ${err.message}</p>`;
  });
