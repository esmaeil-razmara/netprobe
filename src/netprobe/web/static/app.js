"use strict";

const listEl = document.getElementById("tool-list");
const workspaceEl = document.getElementById("workspace");
const viewTpl = document.getElementById("tool-view");

let tools = [];
let activeName = null;

async function api(path, options) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function renderNav() {
  listEl.replaceChildren();
  for (const tool of tools) {
    const btn = document.createElement("button");
    btn.textContent = tool.title;
    btn.dataset.name = tool.name;
    btn.setAttribute("aria-current", String(tool.name === activeName));
    btn.addEventListener("click", () => selectTool(tool.name));
    listEl.append(btn);
  }
}

function selectTool(name) {
  activeName = name;
  renderNav();
  const tool = tools.find((t) => t.name === name);
  if (!tool) return;

  const view = viewTpl.content.cloneNode(true);
  view.querySelector(".tool-title").textContent = tool.title;
  view.querySelector(".tool-desc").textContent = tool.description;

  const form = view.querySelector(".tool-form");
  for (const field of tool.fields) {
    const wrap = document.createElement("div");
    wrap.className = "field";

    const label = document.createElement("label");
    label.textContent = field.label;
    label.htmlFor = `f-${tool.name}-${field.name}`;

    const input = document.createElement("input");
    input.id = label.htmlFor;
    input.name = field.name;
    input.type = field.type === "number" ? "number" : "text";
    if (field.type === "number") input.step = "any";
    if (field.default !== "" && field.default !== null) input.value = field.default;
    if (field.placeholder) input.placeholder = field.placeholder;
    if (field.required) input.required = true;

    wrap.append(label, input);
    if (field.help) {
      const hint = document.createElement("span");
      hint.className = "hint";
      hint.textContent = field.help;
      wrap.append(hint);
    }
    form.append(wrap);
  }

  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Run";
  form.append(submit);

  const errEl = view.querySelector(".tool-error");
  const resultEl = view.querySelector(".tool-result");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errEl.hidden = true;
    resultEl.hidden = true;
    submit.disabled = true;
    submit.textContent = "Running…";

    const params = {};
    for (const [key, value] of new FormData(form)) params[key] = value;

    try {
      const data = await api(`/api/tools/${tool.name}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params),
      });
      renderResult(resultEl, data);
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    } finally {
      submit.disabled = false;
      submit.textContent = "Run";
    }
  });

  workspaceEl.replaceChildren(view);
}

function renderResult(container, data) {
  container.querySelector(".result-summary").textContent = data.summary || "";
  const table = container.querySelector(".result-table");
  table.replaceChildren();

  const head = table.insertRow();
  for (const col of data.columns) {
    const th = document.createElement("th");
    th.textContent = col;
    head.append(th);
  }
  if (!data.rows.length) {
    const row = table.insertRow();
    const cell = row.insertCell();
    cell.colSpan = data.columns.length || 1;
    cell.className = "no-rows";
    cell.textContent = "no matches";
  }
  for (const values of data.rows) {
    const row = table.insertRow();
    for (const value of values) row.insertCell().textContent = value;
  }
  container.hidden = false;
}

api("/api/tools")
  .then((data) => {
    tools = data.tools;
    if (!tools.length) {
      workspaceEl.innerHTML = '<p class="empty">No tools registered.</p>';
      return;
    }
    selectTool(tools[0].name);
  })
  .catch((err) => {
    workspaceEl.innerHTML = `<p class="empty">Could not load tools: ${err.message}</p>`;
  });
