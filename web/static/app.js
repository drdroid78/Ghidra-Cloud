"use strict";

const $ = (name) => document.getElementById(name);
const MIB = 1024 * 1024;
const statuses = {
  queued: "Ожидает исполнителя", requested: "Запрошено", waiting: "Ожидает исполнителя",
  pending: "Ожидает исполнителя", in_progress: "Выполняется", completed: "Завершено",
  success: "Успешно", failure: "Ошибка", cancelled: "Отменено", timed_out: "Истекло время",
  skipped: "Пропущено", neutral: "Завершено",
};
const modes = {analyze: "Ghidra", compare: "Сравнение", toolbox: "Toolbox", resume: "Продолжение Ghidra"};
const stepNames = {
  "Receive private uploads and verify SHA-256": "Проверка SHA‑256 входных файлов",
  "Install verified Ghidra": "Подготовка Ghidra",
  "Install eight analyzers": "Подготовка Toolbox",
  "Run static analysis and verification": "Статический анализ и декомпиляция Ghidra",
  "Run analysis and assertions": "Анализ Toolbox",
  "Save analysis evidence": "Сохранение отчёта",
  "Save reusable project": "Сохранение проекта Ghidra",
  "Save Ghidra projects": "Сохранение проектов Ghidra",
};

let csrf = null;
let pending = [];
let state = {uploads: [], runs: []};
let busy = false;
let polling = false;
let inspected = null;
let nextPollUntil = 0;
const selected = new Set();
const details = new Map();
const uuid = () => crypto.randomUUID().replaceAll("-", "");
const size = (bytes) => bytes < 1024 ? bytes + " Б" :
  (bytes / (bytes >= MIB ? MIB : 1024)).toLocaleString("ru-RU", {maximumFractionDigits: 2}) +
  (bytes >= MIB ? " МиБ" : " КиБ");
const time = (date) => new Date(date).toLocaleString("ru-RU");

function element(tag, content, className) {
  const node = document.createElement(tag);
  if (content) node.textContent = content;
  if (className) node.className = className;
  return node;
}

function message(content = "", error = false) {
  $("message").hidden = !content;
  $("message").textContent = content;
  $("message").classList.toggle("error", error);
}

function button(label, action, className) {
  const node = element("button", label, className);
  node.type = "button";
  node.addEventListener("click", () => Promise.resolve().then(action).catch((error) => message(error.message, true)));
  return node;
}

function link(label, url) {
  const node = element("a", label);
  node.href = url;
  return node;
}

async function api(path, method = "GET", body = null, asText = false) {
  const headers = csrf ? {"X-CSRF-Token": csrf} : {};
  if (body !== null) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {method, headers, body: body === null ? null : JSON.stringify(body)});
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || "Ошибка HTTP " + response.status);
  }
  if (method === "POST" && path.startsWith("/api/runs")) nextPollUntil = Date.now() + 45000;
  return asText ? response.text() : response.json();
}

function access(token) {
  csrf = token;
  $("workspace").hidden = !token;
  $("logout").hidden = !token;
  $("login-panel").hidden = !!token;
}

function addFiles(files) {
  if (busy) return;
  message();
  for (const file of files) {
    if (!file.size || file.size > 100 * MIB) {
      message("Недопустимый размер файла: " + file.name, true);
      continue;
    }
    if (pending.length >= 12) {
      message("За один раз можно выбрать до 12 файлов.", true);
      break;
    }
    pending.push({file, id: uuid()});
  }
  drawQueue();
}

function drawQueue() {
  $("queue").replaceChildren(...pending.map((item) => {
    const row = element("li", "", "row");
    const format = item.result?.format || item.file.name.match(/\.([^.]+)$/)?.[1] || "не определён";
    const info = element("div", item.file.name, "file");
    info.append(element("small", size(item.file.size) + " · " + format));
    item.note = element("span", item.status || "", "tag");
    item.bar = element("progress");
    item.bar.max = item.file.size;
    item.bar.hidden = true;
    item.bar.setAttribute("aria-label", "Загрузка " + item.file.name);
    row.append(info, item.note, item.bar, button("Убрать", () => {
      pending = pending.filter((candidate) => candidate !== item);
      drawQueue();
    }));
    row.lastChild.disabled = busy;
    return row;
  }));
}

function updateUpload(item, status, bytes = null) {
  item.status = status;
  item.note.textContent = status;
  item.bar.hidden = bytes === null;
  if (bytes !== null) item.bar.value = bytes;
}

function transmit(item, keep) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("file", item.file);
    form.append("id", item.id);
    form.append("keep", keep ? "1" : "0");
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/uploads");
    xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.responseType = "json";
    xhr.timeout = 300000;
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) updateUpload(item, "Загрузка", Math.min(event.loaded, item.file.size));
    };
    xhr.upload.onload = () => updateUpload(item, "Передача и проверка SHA‑256 в GitHub");
    xhr.onload = () => {
      if (xhr.status === 201) resolve(xhr.response);
      else reject(Object.assign(new Error(xhr.response?.error || "Ошибка HTTP " + xhr.status), {retry: [429, 502, 503, 504].includes(xhr.status)}));
    };
    xhr.onerror = xhr.ontimeout = () => reject(Object.assign(new Error("Связь с загрузчиком прервалась"), {retry: true}));
    xhr.send(form);
  });
}

async function uploadOne(item, keep) {
  for (let attempt = 0; attempt < 3; attempt++) {
    updateUpload(item, attempt ? "Повторная загрузка" : "Загрузка");
    try {
      item.result = await transmit(item, keep);
      updateUpload(item, "Загружен · SHA‑256 подтверждён");
      return item.result;
    } catch (error) {
      if (!error.retry || attempt === 2) {
        updateUpload(item, error.message);
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, (attempt + 1) * 1500));
    }
  }
}

function rawOptions() {
  return Object.fromEntries(["raw_language", "raw_base", "raw_entry", "raw_compiler"].map((name) => [name, $(name).value]));
}

function start(first, mode, extra = {}) {
  return api("/api/runs", "POST", {first, mode, ...rawOptions(), ...extra});
}

function automatic(file) {
  return ["elf", "pe", "macho", "hex", "srec", "esp-candidate"].includes(file.format)
    || (file.format === "raw" && $("raw_language").value.trim()) ? "analyze" : "toolbox";
}

async function submit(mode) {
  if (busy) return;
  if (mode === "compare" && (selected.size ? selected.size : pending.length) !== 2) {
    message("Для сравнения выберите ровно два файла.", true);
    return;
  }
  if (!pending.length && !(mode === "compare" && selected.size === 2)) {
    message("Выберите файлы для загрузки.", true);
    return;
  }
  busy = true;
  message();
  const form = [$("analyze"), $("upload"), $("compare"), $("picker"), $("keep")];
  form.forEach((node) => { node.disabled = true; });
  drawQueue();
  const failures = [];
  const uploaded = [];
  try {
    if (mode === "compare" && selected.size === 2) {
      const [first, second] = [...selected];
      await start(first, "compare", {second});
    } else {
      for (let offset = 0; offset < pending.length; offset += 3) {
        const results = await Promise.allSettled(pending.slice(offset, offset + 3).map(async (item) => {
          const result = item.result || await uploadOne(item, mode === "upload" || $("keep").checked);
          uploaded.push(result);
          if (mode === "analyze") await start(result.id, automatic(result));
          item.finished = true;
        }));
        failures.push(...results.filter((result) => result.status === "rejected").map((result) => result.reason.message));
      }
      if (mode === "compare" && uploaded.length === 2) {
        await start(uploaded[0].id, "compare", {second: uploaded[1].id});
      }
    }
    message(failures.length ? failures.join(" · ") : mode === "upload"
      ? "Передача завершена. SHA‑256 подтверждён для " + uploaded.length + " файлов."
      : "Задания переданы в GitHub Actions.", !!failures.length);
    pending = pending.filter((item) => !item.finished);
  } finally {
    busy = false;
    form.forEach((node) => { node.disabled = false; });
    $("picker").value = "";
    drawQueue();
    await refresh(false);
  }
}

function drawUploads() {
  const present = new Set(state.uploads.map((file) => file.id));
  for (const id of selected) if (!present.has(id)) selected.delete(id);
  $("uploads").replaceChildren(...(state.uploads.length ? state.uploads.map((file) => {
    const row = element("li", "", "row");
    const label = element("label", "", "file");
    const box = element("input");
    box.type = "checkbox";
    box.checked = selected.has(file.id);
    box.setAttribute("aria-label", "Выбрать " + file.name);
    box.onchange = () => box.checked ? selected.add(file.id) : selected.delete(file.id);
    label.append(box, " " + file.name, element("small", [size(file.size), file.format, "SHA‑256 " + file.sha256].join(" · ")));
    const actions = element("div", "", "controls");
    actions.append(button("Анализировать", async () => { await start(file.id, automatic(file)); await refresh(); }),
      button("Toolbox", async () => { await start(file.id, "toolbox"); await refresh(); }),
      button("Удалить файл", async () => {
        if (confirm("Удалить исходник «" + file.name + "» из хранилища?")) {
          await api("/api/uploads/" + file.id, "DELETE");
          await refresh();
        }
      }));
    row.append(label, actions);
    return row;
  }) : [element("li", "Загруженных файлов пока нет.", "row")]));
}

function runRow(run) {
  const item = element("li", "", "row");
  const files = run.files.map((file) => file.name || file.id).join(" ↔ ");
  const info = element("div", files, "file");
  const current = details.get(run.id);
  const running = current?.jobs.flatMap((job) => job.steps).find((step) => step.status === "in_progress");
  const failed = current?.jobs.flatMap((job) => job.steps).find((step) => step.conclusion === "failure");
  const status = running || failed;
  info.append(element("small", [modes[run.mode], "#" + run.id, time(run.run_started_at || run.created_at),
    statuses[run.conclusion || run.status] || run.status, status && (stepNames[status.name] || status.name)].filter(Boolean).join(" · ")));
  const actions = element("div", "", "controls");
  actions.append(button(run.status === "completed" ? "Результаты" : "Этапы", () => showRun(run)));
  if (run.status === "completed") {
    if (run.mode === "resume" || run.files.every((file) => state.uploads.some((upload) => upload.id === file.id))) {
      actions.append(button("Повторить", async () => { await api("/api/runs/" + run.id + "/rerun", "POST"); await refresh(); }));
    }
    if (run.conclusion === "success" && run.mode !== "toolbox") {
      actions.append(button("Продолжить", async () => {
        await start(run.files[0].id, "resume", {source: run.id});
        await refresh();
      }));
    }
  } else actions.append(button("Отменить", async () => { await api("/api/runs/" + run.id + "/cancel", "POST"); await refresh(); }));
  item.append(info, actions);
  return item;
}

function drawRuns() {
  for (const [panel, complete] of [["active", false], ["history", true]]) {
    const runs = state.runs.filter((run) => (run.status === "completed") === complete);
    $(panel).replaceChildren(...(runs.length ? runs.map(runRow) : [element("li", complete ? "История пока пуста." : "Активных заданий нет.", "row")]));
  }
}

async function refresh(reportError = true) {
  if (polling || !csrf) return;
  polling = true;
  try {
    state = await api("/api/uploads");
    drawUploads();
    drawRuns();
    const active = state.runs.filter((run) => run.status !== "completed").slice(0, 8);
    await Promise.allSettled(active.map(async (run) => details.set(run.id, await api("/api/runs/" + run.id))));
    drawRuns();
    if (inspected !== null && !$("preview").textContent) {
      const run = state.runs.find((entry) => entry.id === inspected);
      if (run && run.status !== "completed") await showRun(run, false);
    }
  } catch (error) {
    if (reportError && !busy) message(error.message, true);
  } finally {
    polling = false;
  }
}

async function preview(url) {
  $("preview").hidden = false;
  $("preview").textContent = "Загрузка…";
  try {
    $("preview").textContent = await api(url, "GET", null, true);
  } catch (error) {
    $("preview").textContent = error.message;
  }
}

async function showRun(run, open = true) {
  inspected = run.id;
  $("results-title").textContent = "Исследование #" + run.id;
  if (open) {
    $("result-body").replaceChildren(element("p", "Загрузка…"));
    $("preview").hidden = true;
    $("preview").textContent = "";
    if (!$("results").open) $("results").showModal();
  }
  const root = "/api/runs/" + run.id;
  const result = await api(root);
  if (inspected !== run.id) return;
  const nodes = [link("Открыть в GitHub Actions", run.html_url)];
  for (const job of result.jobs) {
    const list = element("ul");
    for (const step of job.steps) {
      list.append(element("li", (stepNames[step.name] || step.name) + " · " + (statuses[step.conclusion || step.status] || step.status)));
    }
    nodes.push(list);
    if (job.steps.every((step) => step.status === "completed")) {
      nodes.push(button("Журнал GitHub Actions", () => preview(root + "/jobs/" + job.id + "/log")));
    }
  }
  for (const artifact of result.artifacts) {
    const row = element("div", "", "row");
    row.append(element("strong", artifact.name + " · " + size(artifact.size_in_bytes)));
    if (artifact.expired) row.append(element("span", "Срок хранения истёк"));
    else {
      const base = root + "/artifacts/" + artifact.id;
      const controls = element("div", "", "controls");
      controls.append(link("Скачать ZIP", base + "/download"));
      if (artifact.name.includes("report")) controls.append(button("Открыть отчёты", async () => {
        const data = await api(base + "/text");
        const picker = element("select");
        picker.setAttribute("aria-label", "Файл отчёта");
        picker.append(element("option", "Выберите документ"));
        for (const file of data.files) {
          const option = element("option", file);
          option.value = file;
          picker.append(option);
        }
        picker.onchange = () => {
          if (picker.selectedIndex) void preview(base + "/text?file=" + encodeURIComponent(picker.value));
        };
        controls.append(picker);
      }));
      row.append(controls);
    }
    nodes.push(row);
  }
  $("result-body").replaceChildren(...nodes);
}

$("login").onsubmit = async (event) => {
  event.preventDefault();
  try {
    access((await api("/api/login", "POST", {password: $("password").value})).csrf);
    message();
    await refresh();
  } catch (error) { message(error.message, true); }
  finally { $("password").value = ""; }
};
$("logout").onclick = async () => {
  try {
    await api("/api/logout", "POST");
    access(null);
    pending = [];
    state = {uploads: [], runs: []};
    selected.clear();
    details.clear();
    drawQueue();
    drawUploads();
    drawRuns();
    message();
  } catch (error) { message(error.message, true); }
};
$("picker").onchange = () => addFiles($("picker").files);
$("drop").ondragover = (event) => { event.preventDefault(); $("drop").classList.add("drag"); };
$("drop").ondragleave = () => $("drop").classList.remove("drag");
$("drop").ondrop = (event) => {
  event.preventDefault();
  $("drop").classList.remove("drag");
  addFiles(event.dataTransfer.files);
};
for (const mode of ["upload", "analyze", "compare"]) {
  $(mode).onclick = () => submit(mode).catch((error) => message(error.message, true));
}
$("close-results").onclick = () => $("results").close();
$("results").onclose = () => { inspected = null; };
api("/api/session").then((data) => { access(data.csrf); return refresh(); }).catch(() => {});
setInterval(() => {
  if (!document.hidden && (busy || Date.now() < nextPollUntil || state.runs.some((run) => run.status !== "completed"))) void refresh();
}, 12000);
