"use strict";

const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];
const ACTIVE_TERMINAL_STORAGE_KEY = "openrsc.activeTerminalId";

function rememberedActiveTerminal() {
  try { return localStorage.getItem(ACTIVE_TERMINAL_STORAGE_KEY) || ""; }
  catch { return ""; }
}

function rememberActiveTerminal(terminalId) {
  try {
    if (terminalId) localStorage.setItem(ACTIVE_TERMINAL_STORAGE_KEY, terminalId);
    else localStorage.removeItem(ACTIVE_TERMINAL_STORAGE_KEY);
  } catch {  }
}

function iconElement(name, className = "ui-icon") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", className);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("viewBox", "0 0 24 24");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#icon-${name}`);
  svg.append(use);
  return svg;
}

const state = {
  csrf: "",
  session: null,
  activeView: "terminal",
  terminals: [],
  activeTerminalId: rememberedActiveTerminal(),
  terminalLimit: 8,
  terminalPoll: null,
  terminalBusy: false,
  currentPath: "",
  currentParent: null,
  roots: [],
  files: [],
  editor: null,
  aiStatus: null,
};

function syncComposerClearance() {
  const composer = $("#composerArea");
  if (!composer || composer.offsetHeight === 0) return;
  document.documentElement.style.setProperty("--composer-clearance", `${composer.offsetHeight + 18}px`);
}

function syncTerminalWelcome(outputText = "") {
  const welcome = $("#terminalWelcome");
  if (!welcome) return;
  const hasOutput = Boolean(String(outputText).trim());
  welcome.hidden = hasOutput;
  welcome.parentElement?.classList.toggle("has-output", hasOutput);
}

function syncVisualViewport() {
  const viewport = window.visualViewport;
  const height = Math.max(160, Math.round(viewport?.height || window.innerHeight));
  const offsetTop = Math.max(0, Math.round(viewport?.offsetTop || 0));
  document.documentElement.style.setProperty("--app-height", `${height}px`);
  document.documentElement.style.setProperty("--viewport-offset-top", `${offsetTop}px`);
  const layoutHeight = Math.max(window.innerHeight, document.documentElement.clientHeight);
  const keyboardOpen = matchMedia("(max-width: 820px)").matches && layoutHeight - height > 120;
  document.body.classList.toggle("keyboard-open", keyboardOpen);
  requestAnimationFrame(syncComposerClearance);
}

window.addEventListener("resize", syncVisualViewport, { passive: true });
window.addEventListener("orientationchange", syncVisualViewport, { passive: true });
window.visualViewport?.addEventListener("resize", syncVisualViewport, { passive: true });
window.visualViewport?.addEventListener("scroll", syncVisualViewport, { passive: true });
if (window.ResizeObserver) new ResizeObserver(syncComposerClearance).observe($("#composerArea"));
syncVisualViewport();

async function api(path, options = {}) {
  const method = options.method || "GET";
  const headers = new Headers(options.headers || {});
  let body = options.body;
  if (body !== undefined && options.json !== false) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(body);
  }
  if (method !== "GET" && method !== "HEAD" && path !== "/api/login") {
    headers.set("X-CSRF-Token", state.csrf);
  }
  const response = await fetch(path, { method, headers, body, credentials: "same-origin", cache: "no-store" });
  let payload = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    payload = await response.json().catch(() => null);
  }
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    const error = new Error(payload?.error || `Request failed (${response.status})`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function showLogin(message = "") {
  clearTimeout(state.terminalPoll);
  state.terminalPoll = null;
  state.session = null;
  state.csrf = "";
  state.terminals = [];
  state.activeTerminalId = "";
  $("#app").hidden = true;
  $("#loginView").hidden = false;
  $("#loginError").textContent = message;
  $("#password").value = "";
  setTimeout(() => $("#password").focus(), 50);
}

function showApp() {
  $("#loginView").hidden = true;
  $("#app").hidden = false;
  requestAnimationFrame(syncComposerClearance);
}

function toast(message, type = "success") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.textContent = message;
  $("#toasts").append(item);
  setTimeout(() => item.remove(), 4200);
}

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function fileUrl(route, path, extra = {}) {
  const query = new URLSearchParams({ path, ...extra });
  return `${route}?${query}`;
}

async function bootstrap() {
  try {
    const session = await api("/api/session");
    state.session = session;
    state.csrf = session.csrf;
    state.roots = session.roots;
    showApp();
    renderRuntime();
    renderRoots();
    renderAIRoots();
    await loadTerminals();
    startTerminalPolling(0);
  } catch {
    showLogin();
  }
}

function renderRuntime() {
  const elevated = Boolean(state.session.administrator);
  $("#adminBadge").textContent = elevated ? "Administrator" : "Standard token";
  $("#adminBadge").classList.toggle("admin", elevated);
  $("#versionLabel").textContent = `v${state.session.version}`;
  $("#securityConnection").textContent = location.protocol === "https:" ? "HTTPS secured" : "Local HTTP";
  $("#securityAdmin").textContent = elevated ? "Administrator" : "Not elevated";
  $("#securityExpiry").textContent = formatDate(state.session.expires * 1000);
  $("#securityRoots").textContent = `${state.session.roots.length} configured`;
  $("#connectionLabel").textContent = location.protocol === "https:" ? "Tunnel connected" : "Local connected";
  state.terminalLimit = Number(state.session.terminalLimit || 8);
}

$("#loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#loginButton");
  const password = $("#password").value;
  button.disabled = true;
  $("#loginError").textContent = "";
  try {
    const result = await api("/api/login", { method: "POST", body: { password } });
    state.csrf = result.csrf;
    await bootstrap();
  } catch (error) {
    const suffix = error.payload?.retryAfter ? ` Try again in ${error.payload.retryAfter}s.` : "";
    $("#loginError").textContent = `${error.message}.${suffix}`;
    $("#password").select();
  } finally {
    button.disabled = false;
  }
});

$("#togglePassword").addEventListener("click", () => {
  const input = $("#password");
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  const button = $("#togglePassword");
  button.replaceChildren(iconElement(showing ? "eye" : "eye-off"));
  button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  button.title = showing ? "Show password" : "Hide password";
  input.focus();
});

$("#logoutButton").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST", body: {} }); } catch {  }
  showLogin("Signed out.");
});

$$('.nav-item').forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));

function setSidebar(open) {
  $("#app").classList.toggle("sidebar-open", open);
  $("#sidebarBackdrop").hidden = !open;
}

$("#sidebarToggle").addEventListener("click", () => setSidebar(true));
$("#sidebarClose").addEventListener("click", () => setSidebar(false));
$("#sidebarBackdrop").addEventListener("click", () => setSidebar(false));

function switchView(name) {
  const commandInput = $("#commandInput");
  if (name !== "terminal" && document.activeElement === commandInput) commandInput.blur();
  state.activeView = name;
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `${name}View`));
  const titles = {
    terminal: [activeTerminal()?.name || "Terminal", "Persistent command workspace"],
    files: ["Files", "Browse and manage host storage"],
    ai: ["AI sessions", "Claude and Codex workspace launchers"],
    security: ["Security", "Runtime posture and session controls"],
  };
  $("#topbarViewTitle").textContent = titles[name][0];
  $("#topbarSubtitle").textContent = titles[name][1];
  $$(".terminal-action").forEach((button) => { button.hidden = name !== "terminal"; });
  if (matchMedia("(max-width: 820px)").matches) setSidebar(false);
  if (name === "files" && !state.currentPath && state.roots.length) loadFiles(state.roots[0].path);
  if (name === "ai") {
    if (!$("#aiDirectory").value && state.roots.length) $("#aiDirectory").value = state.currentPath || state.roots[0].path;
    loadAIStatus();
  }
  if (name === "terminal") {
    $("#commandInput").focus();
    startTerminalPolling(0);
  }
}

function activeTerminal() {
  return state.terminals.find((terminal) => terminal.id === state.activeTerminalId) || null;
}

function localTerminal(record, previous = null) {
  return {
    ...record,
    cursor: previous?.cursor || 0,
    output: previous?.output || "",
    commandHistory: previous?.commandHistory || [],
    historyIndex: previous?.historyIndex || 0,
  };
}

async function recoverTerminalTranscript(terminal) {
  if (!terminal) return false;
  try {
    const query = new URLSearchParams({ terminalId: terminal.id, cursor: "0" });
    const result = await api(`/api/terminal/output?${query}`);
    terminal.output = String(result.output || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    terminal.cursor = Number(result.cursor || 0);
    terminal.running = result.running;
    terminal.pid = result.pid;
    terminal.name = result.name || terminal.name;
    return true;
  } catch (error) {
    if (error.status === 401) throw error;
    return false;
  }
}

async function loadTerminals() {
  if (!state.session?.terminalEnabled) return;
  const result = await api("/api/terminals");
  const previous = new Map(state.terminals.map((terminal) => [terminal.id, terminal]));
  state.terminalLimit = Number(result.limit || state.terminalLimit || 8);
  state.terminals = result.terminals.map((record) => localTerminal(record, previous.get(record.id)));
  if (!state.terminals.some((terminal) => terminal.id === state.activeTerminalId)) {
    const remembered = rememberedActiveTerminal();
    state.activeTerminalId = state.terminals.some((terminal) => terminal.id === remembered)
      ? remembered
      : (state.terminals[0]?.id || "");
  }
  rememberActiveTerminal(state.activeTerminalId);
  renderTerminalTabs();
  renderActiveTerminal();
  const restored = activeTerminal();
  if (restored && !previous.has(restored.id)) {
    await recoverTerminalTranscript(restored);
    renderActiveTerminal();
  }
}

function renderTerminalTabs() {
  const list = $("#terminalTabs");
  list.replaceChildren();
  $("#terminalCount").textContent = `${state.terminals.length} / ${state.terminalLimit}`;
  for (const terminal of state.terminals) {
    const row = document.createElement("div");
    row.className = `terminal-tab${terminal.id === state.activeTerminalId ? " active" : ""}`;
    row.setAttribute("role", "tab");
    row.setAttribute("aria-selected", terminal.id === state.activeTerminalId ? "true" : "false");
    const select = document.createElement("button");
    select.type = "button";
    select.className = "terminal-tab-copy";
    select.title = `${terminal.name}${terminal.pid ? ` · PID ${terminal.pid}` : ""}`;
    const glyph = iconElement("terminal", "terminal-tab-glyph ui-icon");
    const name = document.createElement("span");
    name.className = "terminal-tab-name";
    name.textContent = terminal.name;
    select.append(glyph, name);
    select.addEventListener("click", () => selectTerminal(terminal.id));
    select.addEventListener("dblclick", (event) => { event.preventDefault(); renameTerminalTab(terminal); });
    const close = document.createElement("button");
    close.type = "button";
    close.className = "terminal-tab-close";
    close.setAttribute("aria-label", `Close ${terminal.name}`);
    close.title = "Close terminal";
    close.append(iconElement("x"));
    close.addEventListener("click", () => closeTerminalTab(terminal));
    row.append(select, close);
    list.append(row);
  }
}

function renderActiveTerminal() {
  const terminal = activeTerminal();
  const output = $("#terminalOutput");
  output.textContent = terminal?.output || "";
  syncTerminalWelcome(terminal?.output || "");
  $("#activeTerminalName").textContent = terminal?.name || "No terminal";
  $("#terminalState").textContent = terminal
    ? `${navigator.platform.includes("Win") ? "CMD" : "SHELL"} · ${terminal.running === false ? "stopped" : `PID ${terminal.pid || "—"}`}`
    : "Create a terminal to begin";
  $("#topbarViewTitle").textContent = state.activeView === "terminal" ? (terminal?.name || "Terminal") : $("#topbarViewTitle").textContent;
  $("#commandInput").disabled = !terminal;
  output.scrollTop = output.scrollHeight;
  renderTerminalTabs();
}

function selectTerminal(terminalId) {
  if (!state.terminals.some((terminal) => terminal.id === terminalId)) return;
  state.activeTerminalId = terminalId;
  rememberActiveTerminal(terminalId);
  switchView("terminal");
  renderActiveTerminal();
  startTerminalPolling(0);
  setTimeout(() => $("#commandInput").focus(), 0);
}

async function createTerminalTab() {
  if (state.terminals.length >= state.terminalLimit) return toast(`You can open up to ${state.terminalLimit} terminals.`, "error");
  try {
    const result = await api("/api/terminals", { method: "POST", body: {} });
    const terminal = localTerminal(result.terminal);
    state.terminals.push(terminal);
    state.activeTerminalId = terminal.id;
    rememberActiveTerminal(terminal.id);
    switchView("terminal");
    renderActiveTerminal();
    startTerminalPolling(0);
    $("#commandInput").focus();
  } catch (error) { toast(error.message, "error"); }
}

async function closeTerminalTab(terminal) {
  if (terminal.running && !confirm(`Close ${terminal.name} and stop its running shell?`)) return;
  try {
    await api("/api/terminal/close", { method: "POST", body: { terminalId: terminal.id } });
    const index = state.terminals.findIndex((item) => item.id === terminal.id);
    state.terminals = state.terminals.filter((item) => item.id !== terminal.id);
    if (state.activeTerminalId === terminal.id) {
      state.activeTerminalId = state.terminals[Math.max(0, index - 1)]?.id || state.terminals[0]?.id || "";
    }
    rememberActiveTerminal(state.activeTerminalId);
    if (!state.terminals.length) return createTerminalTab();
    renderActiveTerminal();
    startTerminalPolling(0);
  } catch (error) { toast(error.message, "error"); }
}

async function renameTerminalTab(terminal = activeTerminal()) {
  if (!terminal) return;
  const name = prompt("Terminal name:", terminal.name)?.trim();
  if (!name || name === terminal.name) return;
  try {
    const result = await api("/api/terminal/rename", { method: "POST", body: { terminalId: terminal.id, name } });
    Object.assign(terminal, result.terminal);
    renderActiveTerminal();
  } catch (error) { toast(error.message, "error"); }
}

$("#newTerminal").addEventListener("click", createTerminalTab);
$("#newTerminalTop").addEventListener("click", createTerminalTab);
$("#renameTerminal").addEventListener("click", () => renameTerminalTab());

function startTerminalPolling(delay = 250) {
  clearTimeout(state.terminalPoll);
  if (!state.session || !state.session.terminalEnabled) return;
  state.terminalPoll = setTimeout(pollTerminal, delay);
}

async function pollTerminal() {
  const requested = activeTerminal();
  if (state.terminalBusy || !state.session || !requested) return startTerminalPolling(400);
  state.terminalBusy = true;
  try {
    const query = new URLSearchParams({ terminalId: requested.id, cursor: String(requested.cursor) });
    const result = await api(`/api/terminal/output?${query}`);
    const terminal = state.terminals.find((item) => item.id === requested.id);
    if (!terminal) return;
    const output = $("#terminalOutput");
    const nearBottom = output.scrollHeight - output.scrollTop - output.clientHeight < 80;
    if (result.reset) terminal.output = "";
    if (result.output) terminal.output += result.output.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    terminal.cursor = result.cursor;
    terminal.running = result.running;
    terminal.pid = result.pid;
    terminal.name = result.name || terminal.name;
    if (state.activeTerminalId === terminal.id) {
      output.textContent = terminal.output;
      syncTerminalWelcome(terminal.output);
      $("#activeTerminalName").textContent = terminal.name;
      $("#terminalState").textContent = `${navigator.platform.includes("Win") ? "CMD" : "SHELL"} · PID ${result.pid || "—"}`;
      if (nearBottom) output.scrollTop = output.scrollHeight;
    }
    renderTerminalTabs();
  } catch (error) {
    if (error.status !== 401) $("#terminalState").textContent = "Reconnecting…";
  } finally {
    state.terminalBusy = false;
    startTerminalPolling(state.activeView === "terminal" ? 260 : 1300);
  }
}

async function sendCommand(value) {
  const terminal = activeTerminal();
  if (!terminal) return;
  const command = value.trimEnd();
  if (!command.trim()) return;
  terminal.commandHistory.push(command);
  if (terminal.commandHistory.length > 100) terminal.commandHistory.shift();
  terminal.historyIndex = terminal.commandHistory.length;
  await api("/api/terminal/input", { method: "POST", body: { terminalId: terminal.id, input: command } });
  startTerminalPolling(0);
}

$("#terminalForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = $("#commandInput");
  const value = input.value;
  if (!value.trim()) return;
  input.readOnly = true;
  form.classList.add("sending");
  form.setAttribute("aria-busy", "true");
  try {
    await sendCommand(value);
    input.value = "";
    input.style.height = "auto";
    requestAnimationFrame(syncComposerClearance);
  } catch (error) {
    toast(error.message, "error");
  } finally {
    input.readOnly = false;
    form.classList.remove("sending");
    form.removeAttribute("aria-busy");
    input.focus();
  }
});

$("#commandInput").addEventListener("keydown", (event) => {
  const input = event.currentTarget;
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    $("#terminalForm").requestSubmit();
  } else if (event.key === "ArrowUp" && !input.value.includes("\n")) {
    const terminal = activeTerminal(); if (!terminal) return;
    event.preventDefault();
    terminal.historyIndex = Math.max(0, terminal.historyIndex - 1);
    input.value = terminal.commandHistory[terminal.historyIndex] || "";
  } else if (event.key === "ArrowDown" && !input.value.includes("\n")) {
    const terminal = activeTerminal(); if (!terminal) return;
    event.preventDefault();
    terminal.historyIndex = Math.min(terminal.commandHistory.length, terminal.historyIndex + 1);
    input.value = terminal.commandHistory[terminal.historyIndex] || "";
  }
});

$("#commandInput").addEventListener("input", (event) => {
  event.currentTarget.style.height = "auto";
  event.currentTarget.style.height = `${Math.min(event.currentTarget.scrollHeight, 120)}px`;
  requestAnimationFrame(syncComposerClearance);
});

$("#clearTerminal").addEventListener("click", () => {
  const terminal = activeTerminal();
  if (terminal) terminal.output = "";
  $("#terminalOutput").textContent = "";
  syncTerminalWelcome("");
});
$("#interruptTerminal").addEventListener("click", async () => {
  const terminal = activeTerminal(); if (!terminal) return;
  try { await api("/api/terminal/interrupt", { method: "POST", body: { terminalId: terminal.id } }); startTerminalPolling(0); toast("Terminal interrupted and restarted."); }
  catch (error) { toast(error.message, "error"); }
});
$("#resetTerminal").addEventListener("click", async () => {
  const terminal = activeTerminal(); if (!terminal) return;
  if (!confirm("Reset this shell process and its environment?")) return;
  try { await api("/api/terminal/reset", { method: "POST", body: { terminalId: terminal.id } }); startTerminalPolling(0); toast("Shell reset."); }
  catch (error) { toast(error.message, "error"); }
});

document.addEventListener("keydown", (event) => {
  if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "t") {
    event.preventDefault(); createTerminalTab();
  } else if (event.ctrlKey && event.key === "Tab" && state.terminals.length > 1) {
    event.preventDefault();
    const current = state.terminals.findIndex((terminal) => terminal.id === state.activeTerminalId);
    const offset = event.shiftKey ? -1 : 1;
    selectTerminal(state.terminals[(current + offset + state.terminals.length) % state.terminals.length].id);
  } else if (event.ctrlKey && !event.shiftKey && event.key.toLowerCase() === "w" && state.activeView === "terminal") {
    event.preventDefault(); const terminal = activeTerminal(); if (terminal) closeTerminalTab(terminal);
  } else if (event.key === "Escape") setSidebar(false);
});

function renderRoots() {
  const select = $("#rootSelect");
  select.replaceChildren();
  for (const root of state.roots) {
    const option = document.createElement("option");
    option.value = root.path;
    option.textContent = root.label;
    select.append(option);
  }
}

function renderAIRoots() {
  const select = $("#aiRootSelect");
  select.replaceChildren();
  for (const root of state.roots) {
    const option = document.createElement("option"); option.value = root.path; option.textContent = root.label; select.append(option);
  }
  if (!$("#aiDirectory").value && state.roots.length) $("#aiDirectory").value = state.currentPath || state.roots[0].path;
}

function setAIStatus(provider, details) {
  const installed = Boolean(details?.installed);
  const connected = installed && Boolean(details?.authenticated);
  const text = !installed ? "Not installed" : connected ? "Connected" : "Sign-in needed";
  const ids = provider === "claude" ? ["#claudeCliStatus"] : ["#codexCliStatus", "#codexAppStatus"];
  ids.forEach((selector) => {
    const chip = $(selector); chip.textContent = text; chip.classList.toggle("ready", connected); chip.classList.toggle("missing", !installed);
    chip.title = installed ? `${details.version} · ${details.account}` : details?.version || "Not installed";
  });
  if (provider === "claude") {
    const remoteChip = $("#claudeRemoteStatus");
    remoteChip.textContent = installed ? "Ready to connect" : "Not installed";
    remoteChip.classList.toggle("ready", installed);
    remoteChip.classList.toggle("missing", !installed);
    remoteChip.title = installed
      ? `${details.version} · Remote Control verifies its account scope when it starts`
      : details?.version || "Not installed";
  }
  $$(`[data-ai-provider^="${provider}"]`).forEach((button) => { button.disabled = !installed; });
}

async function loadAIStatus(refresh = false) {
  if (state.aiStatus && !refresh) return;
  $("#refreshAI").disabled = true;
  try {
    state.aiStatus = await api(`/api/ai/status${refresh ? "?refresh=1" : ""}`);
    setAIStatus("claude", state.aiStatus.claude);
    setAIStatus("codex", state.aiStatus.codex);
  } catch (error) { toast(error.message, "error"); }
  finally { $("#refreshAI").disabled = false; }
}

function openAIForDirectory(directory) {
  $("#aiDirectory").value = directory || state.currentPath || state.roots[0]?.path || "";
  const matchingRoot = [...state.roots].sort((a, b) => b.path.length - a.path.length)
    .find((root) => $("#aiDirectory").value.toLowerCase().startsWith(root.path.toLowerCase()));
  if (matchingRoot) $("#aiRootSelect").value = matchingRoot.path;
  switchView("ai");
}

async function launchAI(provider, button) {
  const directory = $("#aiDirectory").value.trim();
  if (!directory) { $("#aiDirectory").focus(); toast("Choose a working directory.", "error"); return; }
  const original = button.innerHTML; button.disabled = true; button.classList.add("launching");
  const label = $("span", button); if (label) label.textContent = "Starting…";
  try {
    const result = await api("/api/ai/launch", { method: "POST", body: { provider, directory } });
    if (result.mode === "terminal") {
      const previous = new Map(state.terminals.map((terminal) => [terminal.id, terminal]));
      state.terminals = [...state.terminals.filter((terminal) => terminal.id !== result.terminal.id), localTerminal(result.terminal, previous.get(result.terminal.id))];
      state.activeTerminalId = result.terminal.id;
      rememberActiveTerminal(result.terminal.id);
      renderTerminalTabs(); switchView("terminal"); startTerminalPolling(0);
      toast(`${result.terminal.name} started in ${result.directory}.`);
    } else {
      toast(`Codex app opened in ${result.directory}.`);
    }
  } catch (error) { toast(error.message, "error"); }
  finally { button.innerHTML = original; button.disabled = false; button.classList.remove("launching"); }
}

async function loadFiles(path) {
  if (!path) return;
  $("#fileRows").innerHTML = '<tr><td colspan="4">Loading…</td></tr>';
  $("#emptyFiles").hidden = true;
  try {
    const result = await api(fileUrl("/api/files", path));
    state.currentPath = result.path;
    state.currentParent = result.parent;
    state.files = result.entries;
    $("#pathInput").value = result.path;
    $("#upDirectory").disabled = !result.parent;
    const matchingRoot = [...state.roots].sort((a, b) => b.path.length - a.path.length).find((root) => result.path.toLowerCase().startsWith(root.path.toLowerCase()));
    if (matchingRoot) $("#rootSelect").value = matchingRoot.path;
    renderFiles();
  } catch (error) {
    $("#fileRows").replaceChildren();
    toast(error.message, "error");
  }
}

function fileKindIcon(file) {
  if (file.kind === "directory") return { icon: "folder", className: "folder" };
  if ((file.mime || "").startsWith("image/")) return { icon: "image", className: "image" };
  if (/\.(zip|tar|gz|7z|rar)$/i.test(file.name)) return { icon: "archive", className: "archive" };
  if (/\.(js|mjs|cjs|ts|tsx|jsx|py|css|scss|html|htm|json|xml|yaml|yml|toml|ini|cfg|conf|env|properties|ps1|bat|cmd|sh|zsh|sql|md|go|rs|java|c|cc|cpp|h|hpp|cs|php|rb|vue|svelte)$/i.test(file.name)) return { icon: "file-code", className: "code" };
  return { icon: "file", className: "" };
}

function renderFiles() {
  const body = $("#fileRows");
  body.replaceChildren();
  $("#emptyFiles").hidden = state.files.length !== 0;
  $("#fileCount").textContent = `${state.files.length} item${state.files.length === 1 ? "" : "s"}`;
  for (const file of state.files) {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const wrap = document.createElement("div");
    wrap.className = "file-name";
    const kind = fileKindIcon(file);
    const icon = document.createElement("span");
    icon.className = `file-icon ${kind.className}`;
    icon.append(iconElement(kind.icon));
    const open = document.createElement("button");
    open.type = "button";
    open.textContent = file.name;
    open.title = file.path;
    open.disabled = file.kind === "unavailable" || file.outside_root;
    open.addEventListener("click", () => file.kind === "directory" ? loadFiles(file.path) : previewFile(file));
    wrap.append(icon, open);
    nameCell.append(wrap);
    const size = document.createElement("td"); size.textContent = formatBytes(file.size);
    const modified = document.createElement("td"); modified.textContent = formatDate(file.modified);
    const actions = document.createElement("td"); actions.className = "row-actions";
    if (file.kind !== "unavailable" && !file.outside_root) {
      const download = actionButton(file.kind === "directory" ? "ZIP" : "Download", () => downloadFile(file), "", "download");
      const rename = actionButton("Rename", () => renameFile(file), "", "pencil");
      const remove = actionButton("Delete", () => deleteFile(file), "danger", "trash");
      actions.append(download);
      if (file.kind === "file" && file.name.toLowerCase().endsWith(".zip")) actions.append(actionButton("Extract", () => extractFile(file), "", "archive"));
      actions.append(rename, remove);
    }
    row.append(nameCell, size, modified, actions);
    body.append(row);
  }
}

function actionButton(label, action, className = "", iconName = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.title = label;
  button.setAttribute("aria-label", label);
  if (iconName) button.append(iconElement(iconName));
  const text = document.createElement("span");
  text.className = "button-label";
  text.textContent = label;
  button.append(text);
  button.addEventListener("click", action);
  return button;
}

function downloadFile(file) {
  const route = file.kind === "directory" ? "/api/files/archive" : "/api/file/raw";
  const link = document.createElement("a");
  link.href = fileUrl(route, file.path); link.download = ""; document.body.append(link); link.click(); link.remove();
}

const LANGUAGE_LABELS = {
  plaintext: "Plain text", python: "Python", ini: "INI config", javascript: "JavaScript", typescript: "TypeScript",
  json: "JSON", html: "HTML", css: "CSS", yaml: "YAML", toml: "TOML", shell: "Shell", powershell: "PowerShell",
  batch: "Batch", markdown: "Markdown", sql: "SQL", c: "C / C++", csharp: "C#", java: "Java", go: "Go",
  rust: "Rust", php: "PHP", ruby: "Ruby", xml: "XML", csv: "CSV",
};

const LANGUAGE_KEYWORDS = {
  python: new Set("and as assert async await break class continue def del elif else except False finally for from global if import in is lambda None nonlocal not or pass raise return True try while with yield self".split(" ")),
  javascript: new Set("async await break case catch class const continue debugger default delete do else export extends false finally for from function get if import in instanceof let new null of return set static super switch this throw true try typeof undefined var void while with yield".split(" ")),
  typescript: new Set("abstract any as asserts async await boolean break case catch class const constructor continue declare default delete do else enum export extends false finally for from function get if implements import in infer instanceof interface is keyof let namespace never new null number object of private protected public readonly return set static string super switch symbol this throw true try type typeof undefined unknown var void while with yield".split(" ")),
  shell: new Set("case do done elif else esac export fi for function if in local then until while".split(" ")),
  powershell: new Set("begin break catch class continue data do dynamicparam else elseif end enum exit filter finally for foreach from function if in param process return switch throw trap try until using var while".split(" ")),
  sql: new Set("add alter and as asc begin between by case check column commit constraint create database default delete desc distinct drop else end exists foreign from full grant group having if in index inner insert into is join key left like limit not null on or order outer primary references right rollback row select set table then union unique update values view when where".split(" ")),
  c: new Set("auto bool break case catch char class const constexpr continue default delete do double else enum explicit extern false float for friend if inline int long namespace new nullptr operator private protected public register return short signed sizeof static struct switch template this throw true try typedef typename union unsigned using virtual void volatile while".split(" ")),
  csharp: new Set("abstract as async await base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern false finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new null object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void volatile while".split(" ")),
  java: new Set("abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new null package private protected public return short static strictfp super switch synchronized this throw throws transient true try void volatile while".split(" ")),
  go: new Set("break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var".split(" ")),
  rust: new Set("as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while".split(" ")),
  php: new Set("abstract and array as break callable case catch class clone const continue declare default do echo else elseif empty enddeclare endfor endforeach endif endswitch endwhile eval exit extends final finally fn for foreach function global goto if implements include include_once instanceof insteadof interface isset list match namespace new or print private protected public readonly require require_once return static switch throw trait try unset use var while xor yield".split(" ")),
  ruby: new Set("alias and begin break case class def defined do else elsif end ensure false for if in module next nil not or redo rescue retry return self super then true undef unless until when while yield".split(" ")),
};

function isTextLikeFile(file) {
  return (file.mime || "").startsWith("text/") || /(^|\.)(dockerfile|makefile)$/i.test(file.name) || /\.(txt|log|md|markdown|csv|tsv|json|jsonc|xml|yaml|yml|toml|ini|cfg|conf|env|properties|editorconfig|gitignore|gitattributes|py|pyw|js|mjs|cjs|jsx|ts|tsx|css|scss|less|html|htm|vue|svelte|ps1|psm1|bat|cmd|sh|zsh|fish|sql|go|rs|java|c|cc|cpp|h|hpp|cs|php|rb)$/i.test(file.name);
}

function languageForFile(name) {
  const lower = name.toLowerCase();
  if (/\.pyw?$/.test(lower)) return "python";
  if (/\.(ts|tsx)$/.test(lower)) return "typescript";
  if (/\.(js|mjs|cjs|jsx|vue|svelte)$/.test(lower)) return "javascript";
  if (/\.jsonc?$/.test(lower)) return "json";
  if (/\.(html?|xml)$/.test(lower)) return lower.endsWith("xml") ? "xml" : "html";
  if (/\.(css|scss|less)$/.test(lower)) return "css";
  if (/\.(ya?ml)$/.test(lower)) return "yaml";
  if (/\.toml$/.test(lower)) return "toml";
  if (/\.(ini|cfg|conf|env|properties|editorconfig)$/.test(lower)) return "ini";
  if (/\.(ps1|psm1)$/.test(lower)) return "powershell";
  if (/\.(bat|cmd)$/.test(lower)) return "batch";
  if (/\.(sh|zsh|fish)$/.test(lower)) return "shell";
  if (/\.(md|markdown)$/.test(lower)) return "markdown";
  if (/\.sql$/.test(lower)) return "sql";
  if (/\.(c|cc|cpp|h|hpp)$/.test(lower)) return "c";
  if (/\.cs$/.test(lower)) return "csharp";
  if (/\.java$/.test(lower)) return "java";
  if (/\.go$/.test(lower)) return "go";
  if (/\.rs$/.test(lower)) return "rust";
  if (/\.php$/.test(lower)) return "php";
  if (/\.rb$/.test(lower)) return "ruby";
  if (/\.csv|\.tsv$/.test(lower)) return "csv";
  if (lower === "dockerfile" || lower.endsWith(".dockerfile") || lower === "makefile") return "shell";
  return "plaintext";
}

function escapeCode(value) {
  return String(value).replace(/[&<>]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[character]);
}

function token(value, className) { return `<span class="tok-${className}">${escapeCode(value)}</span>`; }

function commentPosition(line, language) {
  const prefixes = ["python", "yaml", "toml", "shell", "powershell", "ruby"].includes(language) ? ["#"]
    : language === "ini" ? [";", "#"]
      : ["javascript", "typescript", "c", "csharp", "java", "go", "rust", "php"].includes(language) ? ["//"] : [];
  let quote = ""; let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) { escaped = false; continue; }
    if (quote && character === "\\") { escaped = true; continue; }
    if (quote) { if (character === quote) quote = ""; continue; }
    if (character === "\"" || character === "'" || character === "`") { quote = character; continue; }
    if (prefixes.some((prefix) => line.startsWith(prefix, index))) return index;
  }
  return -1;
}

function highlightInline(source, language) {
  const keywords = LANGUAGE_KEYWORDS[language] || new Set();
  const pattern = /(\$\{[^}\n]+\}|\$[A-Za-z_][\w]*|--?[A-Za-z][\w-]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\b(?:0x[\da-f]+|\d+(?:\.\d+)?)\b|[A-Za-z_$][\w$-]*)/gi;
  let result = ""; let cursor = 0;
  for (const match of source.matchAll(pattern)) {
    result += escapeCode(source.slice(cursor, match.index));
    const value = match[0]; const lower = value.toLowerCase();
    if (/^\$/.test(value)) result += token(value, "variable");
    else if (/^--?/.test(value)) result += token(value, "option");
    else if (/^["'`]/.test(value)) result += token(value, "string");
    else if (/^(?:0x[\da-f]+|\d)/i.test(value)) result += token(value, "number");
    else if (keywords.has(value) || keywords.has(lower)) result += token(value, "keyword");
    else if (["true", "false", "null", "none", "undefined", "yes", "no", "on", "off"].includes(lower)) result += token(value, "constant");
    else if (/^(print|len|str|int|dict|list|set|tuple|open|range|console|document|window|fetch|path|self|echo|printf|read|cd|pwd|source|test|command|env|sudo|bash|sh|systemctl|service|sleep|grep|sed|awk|find|cat|chmod|chown)$/i.test(value)) result += token(value, "builtin");
    else result += escapeCode(value);
    cursor = (match.index || 0) + value.length;
  }
  return result + escapeCode(source.slice(cursor));
}

function highlightLine(line, language) {
  if (language === "markdown") {
    const heading = line.match(/^(\s*)(#{1,6})(\s+)(.*)$/);
    if (heading) return `${escapeCode(heading[1])}${token(heading[2], "keyword")}${escapeCode(heading[3])}${token(heading[4], "heading")}`;
    if (/^\s*>/.test(line)) return token(line, "comment");
  }
  if ((language === "html" || language === "xml") && /^\s*<!--/.test(line)) return token(line, "comment");
  if ((language === "html" || language === "xml") && /<[^>]+>/.test(line)) {
    let cursor = 0; let output = "";
    for (const match of line.matchAll(/<\/?[A-Za-z][^>]*>/g)) {
      output += escapeCode(line.slice(cursor, match.index));
      output += token(match[0], "tag");
      cursor = (match.index || 0) + match[0].length;
    }
    return output + escapeCode(line.slice(cursor));
  }
  if (["ini", "toml"].includes(language) && /^\s*\[[^\]]+\]\s*$/.test(line)) return token(line, "section");
  const commentAt = commentPosition(line, language);
  const code = commentAt >= 0 ? line.slice(0, commentAt) : line;
  const comment = commentAt >= 0 ? line.slice(commentAt) : "";
  let output = "";
  const shellAssignment = language === "shell" ? code.match(/^(\s*)([A-Za-z_][\w]*)(\s*=\s*)(.*)$/) : null;
  const property = ["ini", "toml", "yaml", "css"].includes(language) ? code.match(/^(\s*)([^:=]+?)(\s*[:=]\s*)(.*)$/) : null;
  if (shellAssignment) output = `${escapeCode(shellAssignment[1])}${token(shellAssignment[2], "variable")}${token(shellAssignment[3], "operator")}${highlightInline(shellAssignment[4], language)}`;
  else if (property) output = `${escapeCode(property[1])}${token(property[2], "property")}${token(property[3], "operator")}${highlightInline(property[4], language)}`;
  else output = highlightInline(code, language);
  return output + (comment ? token(comment, "comment") : "");
}

function highlightedCode(text, language) {
  return String(text).replace(/\r\n?/g, "\n").split("\n").map((line, index) =>
    `<span class="code-line"><span class="code-line-number">${index + 1}</span><span class="code-line-text">${highlightLine(line, language) || " "}</span></span>`
  ).join("");
}

function modalButton(label, iconName, action, className = "code-tool") {
  const button = document.createElement("button");
  button.type = "button"; button.className = className; button.title = label;
  button.append(iconElement(iconName));
  const text = document.createElement("span"); text.textContent = label; button.append(text);
  button.addEventListener("click", action);
  return button;
}

function prepareModal(title, modifier = "") {
  $("#modalTitle").textContent = title;
  $(".modal-card").className = `modal-card ${modifier}`.trim();
  $("#modal").classList.toggle("modal--chooser", modifier.includes("modal-card--chooser"));
  $("#modal").classList.toggle("modal--code", modifier.includes("modal-card--code"));
  $(".editor-confirm")?.remove();
  $("#modalBody").replaceChildren();
  $("#modal").hidden = false;
}

function showTextOpenDialog(file, result) {
  const language = languageForFile(file.name);
  const normalizedText = String(result.text).replace(/\r\n?/g, "\n");
  state.editor = {
    file, text: normalizedText, originalText: normalizedText, sha256: result.sha256, language, mode: "choose", dirty: false,
    eol: String(result.text).includes("\r\n") ? "\r\n" : "\n",
    history: [{ value: normalizedText, start: 0, end: 0 }], historyIndex: 0, historyTimer: null, input: null,
  };
  prepareModal(`Open ${file.name}`, "modal-card--chooser");
  const body = $("#modalBody");
  const chooser = document.createElement("div"); chooser.className = "open-file-chooser";
  const intro = document.createElement("div"); intro.className = "open-file-intro";
  const badge = document.createElement("span"); badge.className = "open-file-icon"; badge.append(iconElement("file-code"));
  const details = document.createElement("div");
  const name = document.createElement("strong"); name.textContent = file.name;
  const meta = document.createElement("span"); meta.textContent = `${LANGUAGE_LABELS[language]} · ${formatBytes(result.size)} · ${String(result.text).split(/\r\n?|\n/).length} lines`;
  details.append(name, meta); intro.append(badge, details);
  const copy = document.createElement("p"); copy.className = "open-file-prompt"; copy.textContent = "Choose how you want to open this file.";
  const choices = document.createElement("div"); choices.className = "open-mode-grid";
  const read = document.createElement("button"); read.type = "button"; read.className = "open-mode-card";
  const readIcon = document.createElement("span"); readIcon.append(iconElement("book-open"));
  const readText = document.createElement("span"); readText.innerHTML = "<strong>Read</strong><small>Colored source · locked</small>";
  read.append(readIcon, readText, iconElement("chevron-right")); read.addEventListener("click", showCodeReader);
  const edit = document.createElement("button"); edit.type = "button"; edit.className = "open-mode-card recommended";
  const editIcon = document.createElement("span"); editIcon.append(iconElement("pencil"));
  const editText = document.createElement("span"); editText.innerHTML = "<strong>Edit</strong><small>Undo, redo, and save</small>";
  edit.append(editIcon, editText, iconElement("chevron-right")); edit.addEventListener("click", showCodeEditor);
  choices.append(read, edit);
  chooser.append(intro, copy, choices); body.append(chooser);
}

function codeMeta(editor) {
  const meta = document.createElement("div"); meta.className = "code-meta";
  const badge = document.createElement("span"); badge.className = `mode-badge ${editor.mode}`; badge.textContent = editor.mode === "edit" ? "Editing" : "Read only";
  const language = document.createElement("span"); language.textContent = LANGUAGE_LABELS[editor.language];
  meta.append(badge, language); return meta;
}

function codeStatus(editor) {
  const footer = document.createElement("footer"); footer.className = "code-statusbar";
  const left = document.createElement("span"); left.textContent = `${String(editor.text).replace(/\r\n?/g, "\n").split("\n").length} lines`;
  const right = document.createElement("span"); right.textContent = `${LANGUAGE_LABELS[editor.language]} · UTF-8`;
  footer.append(left, right); return footer;
}

function showCodeReader() {
  const editor = state.editor; if (!editor) return;
  editor.mode = "read"; editor.input = null;
  prepareModal(editor.file.name, "modal-card--code");
  const workbench = document.createElement("div"); workbench.className = "code-workbench";
  const toolbar = document.createElement("div"); toolbar.className = "code-toolbar"; toolbar.append(codeMeta(editor));
  const actions = document.createElement("div"); actions.className = "code-toolbar-actions";
  const copy = modalButton("Copy", "copy", async () => { await navigator.clipboard.writeText(editor.text); toast("File contents copied."); });
  const edit = modalButton("Edit file", "pencil", showCodeEditor, "code-tool code-tool--accent");
  actions.append(copy, edit); toolbar.append(actions);
  const scroller = document.createElement("div"); scroller.className = "code-reader-scroller"; scroller.tabIndex = 0;
  const pre = document.createElement("pre"); pre.className = "code-layer code-reader"; pre.setAttribute("aria-label", `${editor.file.name} read-only source`); pre.innerHTML = highlightedCode(editor.text, editor.language);
  scroller.append(pre); workbench.append(toolbar, scroller, codeStatus(editor)); $("#modalBody").append(workbench);
}

function updateEditorChrome() {
  const editor = state.editor; if (!editor || editor.mode !== "edit") return;
  editor.text = editor.input.value;
  editor.dirty = editor.text !== editor.originalText;
  const lines = editor.text.replace(/\r\n?/g, "\n").split("\n");
  editor.highlight.innerHTML = highlightedCode(editor.text, editor.language);
  const longest = Math.max(1, ...lines.map((line) => line.length));
  const mobile = matchMedia("(max-width: 620px)").matches;
  const width = Math.max(mobile ? 620 : 780, Math.min(16000, longest * (mobile ? 9.7 : 8.1) + 100));
  const height = Math.max(editor.scroller.clientHeight, lines.length * (mobile ? 24 : 22) + 32);
  for (const element of [editor.highlight, editor.input, editor.spacer]) {
    element.style.width = `${width}px`; element.style.height = `${height}px`;
  }
  editor.dirtyLabel.textContent = editor.dirty ? "Unsaved changes" : "All changes saved";
  editor.dirtyLabel.classList.toggle("dirty", editor.dirty);
  editor.saveButton.disabled = !editor.dirty || editor.saving;
  editor.undoButton.disabled = editor.historyIndex <= 0;
  editor.redoButton.disabled = editor.historyIndex >= editor.history.length - 1;
  editor.lineStatus.textContent = `${lines.length} lines`;
}

function recordEditorHistory(immediate = false) {
  const editor = state.editor; if (!editor?.input) return;
  const commit = () => {
    const snapshot = { value: editor.input.value, start: editor.input.selectionStart, end: editor.input.selectionEnd };
    if (editor.history[editor.historyIndex]?.value === snapshot.value) return;
    editor.history.splice(editor.historyIndex + 1);
    editor.history.push(snapshot);
    if (editor.history.length > 120) editor.history.shift();
    editor.historyIndex = editor.history.length - 1; updateEditorChrome();
  };
  clearTimeout(editor.historyTimer);
  if (immediate) commit(); else editor.historyTimer = setTimeout(commit, 260);
}

function applyEditorHistory(offset) {
  const editor = state.editor; if (!editor?.input) return;
  recordEditorHistory(true);
  const next = Math.max(0, Math.min(editor.history.length - 1, editor.historyIndex + offset));
  if (next === editor.historyIndex) return;
  editor.historyIndex = next;
  const snapshot = editor.history[next]; editor.input.value = snapshot.value;
  editor.input.setSelectionRange(snapshot.start, snapshot.end); updateEditorChrome(); editor.input.focus();
}

async function saveEditor() {
  const editor = state.editor; if (!editor?.input || editor.saving) return false;
  recordEditorHistory(true); updateEditorChrome();
  if (!editor.dirty) return true;
  editor.saving = true; editor.input.readOnly = true; editor.saveButton.disabled = true; editor.saveButton.classList.add("saving");
  try {
    const persistedText = editor.eol === "\r\n" ? editor.text.replace(/\n/g, "\r\n") : editor.text;
    const result = await api("/api/file/text", { method: "POST", body: { path: editor.file.path, text: persistedText, expectedSha256: editor.sha256 } });
    editor.sha256 = result.sha256; editor.originalText = editor.text; editor.dirty = false; editor.file.size = result.size; editor.file.modified = result.modified;
    toast("File saved."); updateEditorChrome(); loadFiles(state.currentPath); return true;
  } catch (error) { toast(error.message, "error"); return false; }
  finally { editor.saving = false; editor.input.readOnly = false; editor.saveButton.classList.remove("saving"); updateEditorChrome(); editor.input.focus(); }
}

function insertEditorText(value) {
  const editor = state.editor; const input = editor?.input; if (!input) return;
  const start = input.selectionStart; const end = input.selectionEnd;
  input.setRangeText(value, start, end, "end"); input.dispatchEvent(new Event("input", { bubbles: true }));
}

function showCodeEditor() {
  const editor = state.editor; if (!editor) return;
  editor.mode = "edit"; clearTimeout(editor.historyTimer);
  editor.history = [{ value: editor.text, start: 0, end: 0 }]; editor.historyIndex = 0;
  prepareModal(editor.file.name, "modal-card--code");
  const workbench = document.createElement("div"); workbench.className = "code-workbench";
  const toolbar = document.createElement("div"); toolbar.className = "code-toolbar"; toolbar.append(codeMeta(editor));
  const actions = document.createElement("div"); actions.className = "code-toolbar-actions";
  editor.undoButton = modalButton("Undo", "undo", () => applyEditorHistory(-1));
  editor.redoButton = modalButton("Redo", "redo", () => applyEditorHistory(1));
  const discard = modalButton("Don't save", "x", () => closeModal());
  editor.saveButton = modalButton("Save", "save", saveEditor, "code-tool code-save");
  actions.append(editor.undoButton, editor.redoButton, discard, editor.saveButton); toolbar.append(actions);
  const scroller = document.createElement("div"); scroller.className = "code-editor-scroller";
  const spacer = document.createElement("div"); spacer.className = "code-editor-spacer";
  const highlight = document.createElement("pre"); highlight.className = "code-layer code-highlight"; highlight.setAttribute("aria-hidden", "true");
  const input = document.createElement("textarea"); input.className = "code-editor-input"; input.value = editor.text;
  input.setAttribute("aria-label", `Edit ${editor.file.name}`); input.setAttribute("wrap", "off"); input.spellcheck = false;
  input.autocomplete = "off"; input.autocapitalize = "none"; input.setAttribute("autocorrect", "off");
  scroller.append(spacer, highlight, input);
  const status = codeStatus(editor); editor.lineStatus = status.firstElementChild;
  const dirty = document.createElement("span"); dirty.className = "editor-dirty-state"; status.insertBefore(dirty, status.lastElementChild);
  editor.input = input; editor.highlight = highlight; editor.spacer = spacer; editor.scroller = scroller; editor.dirtyLabel = dirty; editor.saving = false;
  input.addEventListener("input", () => { updateEditorChrome(); recordEditorHistory(); });
  input.addEventListener("keydown", (event) => {
    const command = event.ctrlKey || event.metaKey; const key = event.key.toLowerCase();
    if (command && key === "s") { event.preventDefault(); saveEditor(); }
    else if (command && key === "z") { event.preventDefault(); applyEditorHistory(event.shiftKey ? 1 : -1); }
    else if (command && key === "y") { event.preventDefault(); applyEditorHistory(1); }
    else if (event.key === "Tab") { event.preventDefault(); insertEditorText("  "); }
  });
  workbench.append(toolbar, scroller, status); $("#modalBody").append(workbench);
  requestAnimationFrame(() => { updateEditorChrome(); input.focus(); });
}

function showUnsavedDialog() {
  if ($(".editor-confirm")) return;
  const editor = state.editor; if (!editor) return;
  const confirm = document.createElement("div"); confirm.className = "editor-confirm";
  const panel = document.createElement("div"); panel.className = "editor-confirm-card";
  const icon = document.createElement("span"); icon.className = "confirm-icon"; icon.append(iconElement("alert"));
  const title = document.createElement("strong"); title.textContent = "Save your changes?";
  const text = document.createElement("p"); text.textContent = `Your edits to ${editor.file.name} have not been saved.`;
  const actions = document.createElement("div"); actions.className = "editor-confirm-actions";
  const keep = document.createElement("button"); keep.type = "button"; keep.className = "button subtle"; keep.textContent = "Keep editing"; keep.addEventListener("click", () => confirm.remove());
  const discard = document.createElement("button"); discard.type = "button"; discard.className = "button subtle danger-text"; discard.textContent = "Don't save"; discard.addEventListener("click", () => closeModal(true));
  const save = document.createElement("button"); save.type = "button"; save.className = "button primary"; save.textContent = "Save changes";
  save.addEventListener("click", async () => { if (await saveEditor()) closeModal(true); });
  actions.append(keep, discard, save); panel.append(icon, title, text, actions); confirm.append(panel); $(".modal-card").append(confirm); keep.focus();
}

async function previewFile(file) {
  prepareModal(file.name);
  if ((file.mime || "").startsWith("image/")) {
    state.editor = null;
    const image = document.createElement("img");
    image.alt = file.name; image.src = fileUrl("/api/file/raw", file.path, { inline: "1" }); $("#modalBody").append(image); return;
  }
  if (isTextLikeFile(file)) {
    const loading = document.createElement("div"); loading.className = "modal-message"; loading.textContent = "Loading file…"; $("#modalBody").append(loading);
    try { const result = await api(fileUrl("/api/file/text", file.path)); showTextOpenDialog(file, result); }
    catch (error) { state.editor = null; loading.textContent = error.message; }
  } else {
    state.editor = null;
    const message = document.createElement("div"); message.className = "modal-message";
    const text = document.createElement("span"); text.textContent = `${file.mime || "Binary file"} · ${formatBytes(file.size)}`;
    const button = document.createElement("button"); button.className = "button primary"; button.textContent = "Download file"; button.addEventListener("click", () => downloadFile(file));
    message.append(text, button); $("#modalBody").append(message);
  }
}

function closeModal(force = false) {
  if (!force && state.editor?.mode === "edit" && state.editor.dirty) { showUnsavedDialog(); return; }
  if (state.editor) clearTimeout(state.editor.historyTimer);
  state.editor = null; $("#modal").hidden = true; $("#modal").className = "modal"; $("#modalBody").replaceChildren(); $(".modal-card").className = "modal-card"; $(".editor-confirm")?.remove();
}
$$('[data-close-modal]').forEach((item) => item.addEventListener("click", () => closeModal()));
document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !$("#modal").hidden) closeModal(); });

async function createFolder() {
  const name = prompt("Folder name:");
  if (!name) return;
  try { await api("/api/files/mkdir", { method: "POST", body: { directory: state.currentPath, name } }); await loadFiles(state.currentPath); toast("Folder created."); }
  catch (error) { toast(error.message, "error"); }
}

async function renameFile(file) {
  const name = prompt("New name:", file.name);
  if (!name || name === file.name) return;
  try { await api("/api/files/rename", { method: "POST", body: { path: file.path, name } }); await loadFiles(state.currentPath); toast("Item renamed."); }
  catch (error) { toast(error.message, "error"); }
}

async function deleteFile(file) {
  if (!confirm(`Permanently delete ${file.name}${file.kind === "directory" ? " and everything inside it" : ""}?`)) return;
  try { await api("/api/files/delete", { method: "POST", body: { path: file.path, recursive: file.kind === "directory" } }); await loadFiles(state.currentPath); toast("Item deleted."); }
  catch (error) { toast(error.message, "error"); }
}

async function extractFile(file) {
  if (!confirm(`Extract ${file.name} into the current folder?`)) return;
  try { const result = await api("/api/files/extract", { method: "POST", body: { archive: file.path, target: state.currentPath } }); await loadFiles(state.currentPath); toast(`Extracted ${result.files} files (${formatBytes(result.bytes)}).`); }
  catch (error) { toast(error.message, "error"); }
}

function uploadChunk(uploadId, offset, chunk, file, completedBefore) {
  return new Promise((resolve, reject) => {
    const query = new URLSearchParams({ uploadId, offset: String(offset) });
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/uploads/chunk?${query}`);
    xhr.responseType = "json";
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-CSRF-Token", state.csrf);
    xhr.upload.addEventListener("progress", (event) => {
      const loaded = completedBefore + (event.lengthComputable ? event.loaded : 0);
      const percent = file.size ? Math.round(loaded / file.size * 100) : 100;
      $("#uploadProgress").textContent = `Uploading ${file.name} · ${percent}%`;
    });
    xhr.addEventListener("load", () => xhr.status >= 200 && xhr.status < 300 ? resolve(xhr.response) : reject(Object.assign(new Error(xhr.response?.error || `Upload failed (${xhr.status})`), { status: xhr.status })));
    xhr.addEventListener("error", () => reject(new Error("Upload connection failed")));
    xhr.send(chunk);
  });
}

async function uploadOne(file, overwrite = false) {
  const started = await api("/api/uploads/start", {
    method: "POST",
    body: { directory: state.currentPath, name: file.name, size: file.size, overwrite },
  });
  let offset = started.received;
  try {
    while (offset < file.size) {
      const chunk = file.slice(offset, Math.min(file.size, offset + started.chunkBytes));
      const result = await uploadChunk(started.uploadId, offset, chunk, file, offset);
      offset = result.received;
    }
    if (file.size === 0) $("#uploadProgress").textContent = `Uploading ${file.name} · 100%`;
    return await api("/api/uploads/finish", { method: "POST", body: { uploadId: started.uploadId } });
  } catch (error) {
    try { await api("/api/uploads/cancel", { method: "POST", body: { uploadId: started.uploadId } }); } catch {  }
    throw error;
  }
}

async function uploadFiles(files) {
  if (!state.currentPath || !files.length) return;
  for (const file of files) {
    try { await uploadOne(file); }
    catch (error) {
      if (error.status === 400 && /already exists/i.test(error.message) && confirm(`${file.name} already exists. Overwrite it?`)) {
        try { await uploadOne(file, true); } catch (retryError) { toast(`${file.name}: ${retryError.message}`, "error"); }
      } else toast(`${file.name}: ${error.message}`, "error");
    }
  }
  $("#uploadProgress").textContent = "";
  await loadFiles(state.currentPath);
  toast("Upload queue complete.");
}

$("#rootSelect").addEventListener("change", (event) => loadFiles(event.target.value));
$("#upDirectory").addEventListener("click", () => state.currentParent && loadFiles(state.currentParent));
$("#goPath").addEventListener("click", () => loadFiles($("#pathInput").value));
$("#pathInput").addEventListener("keydown", (event) => { if (event.key === "Enter") loadFiles(event.currentTarget.value); });
$("#refreshFiles").addEventListener("click", () => loadFiles(state.currentPath));
$("#aiFromFiles").addEventListener("click", () => openAIForDirectory(state.currentPath));
$("#newFolder").addEventListener("click", createFolder);
$("#uploadButton").addEventListener("click", () => $("#uploadInput").click());
$("#uploadInput").addEventListener("change", (event) => { uploadFiles([...event.target.files]); event.target.value = ""; });
$("#aiRootSelect").addEventListener("change", (event) => { $("#aiDirectory").value = event.target.value; });
$("#aiUseFiles").addEventListener("click", () => { $("#aiDirectory").value = state.currentPath || state.roots[0]?.path || ""; });
$("#refreshAI").addEventListener("click", () => { state.aiStatus = null; loadAIStatus(true); });
$$('[data-ai-provider]').forEach((button) => button.addEventListener("click", () => launchAI(button.dataset.aiProvider, button)));

let dragDepth = 0;
const dropZone = $("#dropZone");
dropZone.addEventListener("dragenter", (event) => { event.preventDefault(); dragDepth += 1; dropZone.classList.add("dragging"); });
dropZone.addEventListener("dragover", (event) => event.preventDefault());
dropZone.addEventListener("dragleave", () => { dragDepth -= 1; if (dragDepth <= 0) { dragDepth = 0; dropZone.classList.remove("dragging"); } });
dropZone.addEventListener("drop", (event) => { event.preventDefault(); dragDepth = 0; dropZone.classList.remove("dragging"); uploadFiles([...event.dataTransfer.files]); });

window.addEventListener("pageshow", (event) => {
  if (!event.persisted || !state.session) return;
  loadTerminals().then(() => startTerminalPolling(0)).catch((error) => {
    if (error.status !== 401) $("#terminalState").textContent = "Reconnecting…";
  });
});

bootstrap();
