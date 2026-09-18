const $ = (id) => document.getElementById(id);

const url = $("url");
const repo = $("repo");
const mode = $("mode");
const withBrowser = $("with-browser");
const authUser = $("auth-user");
const authPassword = $("auth-password");
const form = $("scan-form");
const submit = $("submit");
const formError = $("form-error");
const statusEl = $("status");
const summaryEl = $("summary");
const briefEl = $("brief");
const reportEl = $("report");
const healthEl = $("health");
const historyEl = $("history");
const clockEl = $("clock");
const docMeta = $("doc-meta");
const btnExportMd = $("btn-export-md");
const btnExportHtml = $("btn-export-html");
const btnPrint = $("btn-print");
const btnOpenHtml = $("btn-open-html");

const btnEditDoc = $("btn-edit-doc");
const editModal = $("edit-modal");
const editForm = $("edit-form");
const editId = $("edit-id");
const editLabel = $("edit-label");
const editNotes = $("edit-notes");
const editBrief = $("edit-brief");
const editReport = $("edit-report");
const editError = $("edit-error");
const editClose = $("edit-close");
const editCancel = $("edit-cancel");

const modelSelect = $("model-select");
const agentMode = $("agent-mode");
const runtimeSelect = $("runtime-select");
const cloudRepo = $("cloud-repo");
const cloudRepoList = $("cloud-repo-list");
const cliCloudRow = $("cli-cloud-row");
const cliMeta = $("cli-meta");
const cliLog = $("cli-log");
const cliForm = $("cli-form");
const cliInput = $("cli-input");
const cliSend = $("cli-send");
const cliClear = $("cli-clear");
const cliError = $("cli-error");

const agentFab = $("agent-fab");
const agentCanvas = $("agent-canvas");
const agentFabPulse = $("agent-fab-pulse");
const agentModal = $("agent-modal");
const agentClose = $("agent-close");
const agentPaneDialog = $("agent-pane-dialog");
const agentPaneHistory = $("agent-pane-history");
const chatHistoryEl = $("chat-history");
const chatHistRefresh = $("chat-hist-refresh");
const chatHistError = $("chat-hist-error");
const chatEditModal = $("chat-edit-modal");
const chatEditForm = $("chat-edit-form");
const chatEditId = $("chat-edit-id");
const chatEditLabel = $("chat-edit-label");
const chatEditNotes = $("chat-edit-notes");
const chatEditClose = $("chat-edit-close");
const chatEditCancel = $("chat-edit-cancel");
const chatEditError = $("chat-edit-error");

let agent3d = null;

const state = {
  scanId: null,
  activeTab: "brief",
  briefMd: "",
  reportMd: "",
  label: "",
  notes: "",
  chatSessionId: localStorage.getItem("hackteus_cli_session") || null,
  model: localStorage.getItem("hackteus_model") || "default",
  agentMode: localStorage.getItem("hackteus_agent_mode") || "agent",
  runtime: localStorage.getItem("hackteus_runtime") || "local",
};

function statusText(msg) {
  let text = statusEl.querySelector(".status-text");
  if (!text) {
    statusEl.textContent = "";
    statusEl.insertAdjacentHTML(
      "afterbegin",
      '<span class="status-cursor">▌</span><span class="status-text"></span>'
    );
    text = statusEl.querySelector(".status-text");
  }
  text.textContent = msg;
}

function setScanVisual(on) {
  document.body.classList.toggle("scanning", on);
  if (window.HackteusMatrix) {
    window.HackteusMatrix.setBoost(on ? 2.1 : 1);
  }
}

function decorateSeverities(root) {
  const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walk.nextNode()) nodes.push(walk.currentNode);
  const re = /\b(Critical|High|Medium|Low|Info)\b/g;
  for (const node of nodes) {
    const text = node.nodeValue;
    if (!re.test(text)) continue;
    re.lastIndex = 0;
    const span = document.createElement("span");
    span.innerHTML = text.replace(re, (m) => {
      const cls = m.toLowerCase();
      return `<span class="sev sev-${cls}">${m}</span>`;
    });
    node.parentNode.replaceChild(span, node);
  }
}

function renderMarkdown(el, md, placeholder) {
  const raw = (md || "").trim();
  if (!raw) {
    el.innerHTML = `<p class="doc-placeholder">${placeholder}</p>`;
    return;
  }
  let html;
  if (window.marked && typeof window.marked.parse === "function") {
    html = window.marked.parse(raw, { breaks: true });
  } else {
    html = `<pre>${escapeHtml(raw)}</pre>`;
  }
  el.innerHTML = html;
  decorateSeverities(el);
}

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function updateDocMeta() {
  if (!state.scanId) {
    docMeta.textContent = "nenhum documento carregado";
    btnOpenHtml.hidden = true;
    return;
  }
  const tab = state.activeTab;
  docMeta.textContent = `scan ${state.scanId} · documento ${tab.toUpperCase()}`;
  btnOpenHtml.hidden = false;
  btnOpenHtml.href = `/api/scans/${state.scanId}/docs/${tab}.html`;
}

function showDocs(data) {
  state.scanId = data.scan_id || null;
  state.briefMd = data.brief_md || "";
  state.reportMd = data.report_md || "";
  state.label = data.label || "";
  state.notes = data.notes || "";
  renderMarkdown(briefEl, state.briefMd, "_ sem brief");
  renderMarkdown(reportEl, state.reportMd, "_ sem relatório ainda");
  updateDocMeta();
  if (typeof updateCliMetaLine === "function") updateCliMetaLine();
}

function closeEditModal() {
  editModal.hidden = true;
  editError.hidden = true;
}

async function openEditModal(scanId) {
  editError.hidden = true;
  const res = await fetch(`/api/scans/${scanId}`);
  if (!res.ok) {
    alert("scan não encontrado");
    return;
  }
  const data = await res.json();
  editId.value = data.scan_id;
  editLabel.value = data.label || "";
  editNotes.value = data.notes || "";
  editBrief.value = data.brief_md || "";
  editReport.value = data.report_md || "";
  editModal.hidden = false;
}

async function deleteScan(scanId) {
  const ok = confirm(`Excluir scan ${scanId}? Esta ação remove evidências e relatórios.`);
  if (!ok) return;
  const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(data.detail || "falha ao excluir");
    return;
  }
  if (state.scanId === scanId) {
    state.scanId = null;
    state.briefMd = "";
    state.reportMd = "";
    showDocs({ scan_id: null, brief_md: "", report_md: "" });
    statusText("scan removido");
  }
  await refreshHistory();
}

editClose?.addEventListener("click", closeEditModal);
editCancel?.addEventListener("click", closeEditModal);
editModal?.addEventListener("click", (e) => {
  if (e.target === editModal) closeEditModal();
});

btnEditDoc?.addEventListener("click", () => {
  if (!state.scanId) {
    alert("Abra um scan do histórico antes de editar.");
    return;
  }
  openEditModal(state.scanId);
});

editForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  editError.hidden = true;
  const id = editId.value;
  const payload = {
    label: editLabel.value.trim(),
    notes: editNotes.value,
    brief_md: editBrief.value,
    report_md: editReport.value,
  };
  try {
    const res = await fetch(`/api/scans/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.detail || res.statusText);
    }
    closeEditModal();
    renderResult({
      scan_id: data.scan_id,
      label: data.label,
      notes: data.notes,
      brief_md: data.brief_md,
      report_md: data.report_md,
      summary: {},
    });
    await refreshHistory();
    statusText(`scan ${id} · saved`);
  } catch (err) {
    editError.hidden = false;
    editError.textContent = err.message || String(err);
  }
});

async function refreshHistory() {
  const res = await fetch("/api/scans");
  const data = await res.json();
  historyEl.innerHTML = "";
  if (!data.scans?.length) {
    historyEl.innerHTML = "<li><span>no ops logged</span></li>";
    return;
  }
  for (const s of data.scans) {
    const li = document.createElement("li");
    const label = s.label || s.scan_id;
    li.innerHTML = `
      <div class="hist-main">
        <div class="hist-label">${escapeHtml(label)}</div>
        <div class="hist-sub">${escapeHtml(s.scan_id)} · ${escapeHtml(s.mode || "?")} · ${escapeHtml(s.url || "")}</div>
      </div>
      <div class="hist-actions">
        <button type="button" data-act="open">OPEN</button>
        <button type="button" data-act="edit">EDIT</button>
        <button type="button" data-act="del" class="danger">DEL</button>
      </div>
    `;
    li.querySelector('[data-act="open"]').addEventListener("click", () => openScan(s.scan_id));
    li.querySelector('[data-act="edit"]').addEventListener("click", () => openEditModal(s.scan_id));
    li.querySelector('[data-act="del"]').addEventListener("click", () => deleteScan(s.scan_id));
    historyEl.appendChild(li);
  }
}

function renderResult(data) {
  setScanVisual(false);
  statusEl.className = "status done";
  statusText(`scan ${data.scan_id} · complete`);
  const s = data.summary || {};
  if (s && Object.keys(s).length) {
    summaryEl.hidden = false;
    summaryEl.innerHTML = [
      `secrets≈${s.secret_hits ?? "?"}`,
      `scripts=${s.scripts ?? "?"}`,
      `apis=${s.api_endpoints ?? "?"}`,
      `auth=${s.browser_authenticated ?? "—"}`,
      `findings=${s.browser_findings ?? "?"}`,
      `hdr_miss=${(s.missing_security_headers || []).length}`,
      s.browser_error ? `browser_err` : null,
    ]
      .filter(Boolean)
      .map((t) => `<span class="chip">${t}</span>`)
      .join("");
  }

  showDocs(data);
  if (data.report_md) {
    document.querySelector('.tab[data-tab="report"]')?.click();
  }
}

async function openScan(id) {
  statusEl.className = "status running";
  statusText(`loading ${id}…`);
  const res = await fetch(`/api/scans/${id}`);
  if (!res.ok) {
    statusEl.className = "status fail";
    statusText("not found");
    return;
  }
  const data = await res.json();
  renderResult({
    scan_id: data.scan_id,
    label: data.label,
    notes: data.notes,
    summary: {},
    brief_md: data.brief_md,
    report_md: data.report_md,
  });
}

function currentMarkdown() {
  return state.activeTab === "report" ? state.reportMd : state.briefMd;
}

function downloadBlob(filename, content, type) {
  const blob = new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

btnExportMd?.addEventListener("click", () => {
  const md = currentMarkdown();
  if (!md) return;
  downloadBlob(
    `${state.scanId || "hackteus"}-${state.activeTab}.md`,
    md,
    "text/markdown;charset=utf-8"
  );
});

btnExportHtml?.addEventListener("click", () => {
  if (state.scanId) {
    window.open(`/api/scans/${state.scanId}/docs/${state.activeTab}.html`, "_blank");
    return;
  }
  const md = currentMarkdown();
  if (!md) return;
  const body =
    window.marked?.parse?.(md, { breaks: true }) || `<pre>${escapeHtml(md)}</pre>`;
  downloadBlob(
    `${state.activeTab}.html`,
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${state.activeTab}</title></head><body>${body}</body></html>`,
    "text/html;charset=utf-8"
  );
});

btnPrint?.addEventListener("click", () => window.print());

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.activeTab = btn.dataset.tab;
    briefEl.hidden = state.activeTab !== "brief";
    reportEl.hidden = state.activeTab !== "report";
    updateDocMeta();
  });
});

function tickClock() {
  if (!clockEl) return;
  clockEl.textContent = new Date().toTimeString().slice(0, 8);
}
tickClock();
setInterval(tickClock, 1000);

async function refreshHealth() {
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    if (data.ok) {
      healthEl.textContent = data.cursor_api_key_configured
        ? `teste de api · ok · db ${data.db?.scans ?? "?"} scans`
        : "teste de api · ok (sem chave)";
      healthEl.className = "pill ok";
    } else {
      healthEl.textContent = "teste de api · falhou";
      healthEl.className = "pill bad";
    }
  } catch {
    healthEl.textContent = "teste de api · offline";
    healthEl.className = "pill bad";
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  formError.hidden = true;

  const targetUrl = url.value.trim();
  if (!targetUrl) {
    formError.hidden = false;
    formError.textContent = "Informe a URL do alvo.";
    return;
  }

  submit.disabled = true;
  setScanVisual(true);
  statusEl.className = "status running";
  statusText("coletando evidências…");
  briefEl.innerHTML = `<p class="doc-placeholder">_ gerando brief…</p>`;
  reportEl.innerHTML = `<p class="doc-placeholder">_ gerando relatório…</p>`;

  const payload = {
    url: targetUrl,
    repo: repo.value.trim() || null,
    mode: mode.value,
    consent: "accepted",
    with_agent: true,
    with_browser: withBrowser.checked,
    auth_user: authUser.value.trim() || null,
    auth_password: authPassword.value || null,
    model: selectedModel(),
  };

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail || res.statusText;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    renderResult(data);
    await refreshHistory();
  } catch (err) {
    setScanVisual(false);
    statusEl.className = "status fail";
    statusText("scan failed");
    formError.hidden = false;
    formError.textContent = err.message || String(err);
  } finally {
    submit.disabled = false;
  }
});

refreshHealth();
refreshHistory();
loadModels();
loadCliMeta();
loadCloudRepos();
restoreCliSession();
syncRuntimeUi();

function selectedModel() {
  return modelSelect?.value || state.model || "default";
}

function selectedAgentMode() {
  return agentMode?.value || state.agentMode || "agent";
}

function selectedRuntime() {
  return runtimeSelect?.value || state.runtime || "local";
}

function persistModel() {
  state.model = selectedModel();
  localStorage.setItem("hackteus_model", state.model);
}

function persistAgentMode() {
  state.agentMode = selectedAgentMode();
  localStorage.setItem("hackteus_agent_mode", state.agentMode);
}

function persistRuntime() {
  state.runtime = selectedRuntime();
  localStorage.setItem("hackteus_runtime", state.runtime);
  syncRuntimeUi();
}

function syncRuntimeUi() {
  if (cliCloudRow) cliCloudRow.hidden = selectedRuntime() !== "cloud";
  updateCliMetaLine();
}

function persistChatSession(id) {
  state.chatSessionId = id;
  if (id) localStorage.setItem("hackteus_cli_session", id);
  else localStorage.removeItem("hackteus_cli_session");
}

/** NEW CHAT: só limpa o diálogo atual. NÃO apaga o histórico salvo. */
function startNewDialog() {
  persistChatSession(null);
  renderCliMessages([]);
  cliError.hidden = true;
  updateCliMetaLine("new");
}

function autoResizeCli() {
  if (!cliInput) return;
  cliInput.style.height = "auto";
  cliInput.style.height = Math.min(cliInput.scrollHeight, 128) + "px";
}

function updateCliMetaLine(extra) {
  if (!cliMeta) return;
  const parts = [
    "stream",
    "mcp",
    "rules",
    selectedModel() === "default" ? "auto" : selectedModel(),
    selectedAgentMode(),
    selectedRuntime(),
  ];
  if (state.scanId) parts.push(`scan:${state.scanId}`);
  if (extra) parts.push(extra);
  cliMeta.textContent = parts.join(" · ");
}

function appendCliLine(role, text, { pending = false, streaming = false } = {}) {
  if (!cliLog) return null;
  const hint = cliLog.querySelector(".cli-line.muted");
  if (hint) hint.remove();

  const line = document.createElement("div");
  line.className = `cli-line ${role}${pending ? " pending" : ""}${streaming ? " streaming" : ""}`;
  const roleMap = {
    user: "you",
    assistant: "racker",
    tool: "tool",
    task: "task",
    thinking: "think",
    status: "status",
  };
  const roleLabel = roleMap[role] || role;
  const body = document.createElement("span");
  body.className = "cli-body";
  if (role === "assistant" && text && window.marked?.parse && !streaming) {
    body.innerHTML = window.marked.parse(text, { breaks: true });
  } else {
    body.textContent = text;
  }
  line.innerHTML = `<span class="cli-role">${roleLabel}&gt;</span>`;
  line.appendChild(body);
  cliLog.appendChild(line);
  cliLog.scrollTop = cliLog.scrollHeight;
  return line;
}

function setCliBodyText(line, text, { markdown = false } = {}) {
  if (!line) return;
  const body = line.querySelector(".cli-body");
  if (!body) return;
  if (markdown && window.marked?.parse) {
    body.innerHTML = window.marked.parse(text || "", { breaks: true });
  } else {
    body.textContent = text || "";
  }
  cliLog.scrollTop = cliLog.scrollHeight;
}

function renderCliMessages(messages) {
  if (!cliLog) return;
  cliLog.innerHTML = "";
  if (!messages?.length) {
    cliLog.innerHTML =
      '<div class="cli-line muted">_ racker online · Enter envia · Shift+Enter quebra linha</div>';
    return;
  }
  for (const m of messages) {
    appendCliLine(m.role === "user" ? "user" : "assistant", m.text || "");
  }
}

async function loadModels() {
  if (!modelSelect) return;
  try {
    const res = await fetch("/api/models");
    const data = await res.json();
    const models = data.models || [];
    modelSelect.innerHTML = "";
    if (!models.length) {
      modelSelect.innerHTML = '<option value="default" selected>auto</option>';
      return;
    }
    for (const m of models) {
      const opt = document.createElement("option");
      opt.value = m.id;
      opt.textContent = m.label || m.id;
      if (m.id === (state.model || "default")) opt.selected = true;
      modelSelect.appendChild(opt);
    }
    if (![...modelSelect.options].some((o) => o.selected)) {
      modelSelect.value = "default";
    }
    persistModel();
  } catch {
    modelSelect.innerHTML = '<option value="default" selected>auto</option>';
  }
  updateCliMetaLine();
}

async function loadCliMeta() {
  try {
    const res = await fetch("/api/cli");
    const data = await res.json();
    const mcp = data.mcp || {};
    const proj = (mcp.project?.servers || []).length;
    const user = (mcp.user?.servers || []).length;
    updateCliMetaLine(`mcp:${proj + user}`);
  } catch {
    updateCliMetaLine();
  }
}

async function loadCloudRepos() {
  if (!cloudRepoList) return;
  try {
    const res = await fetch("/api/repos");
    const data = await res.json();
    cloudRepoList.innerHTML = "";
    for (const r of data.repos || []) {
      const opt = document.createElement("option");
      opt.value = r.url;
      cloudRepoList.appendChild(opt);
    }
  } catch {
    /* ignore */
  }
}

async function restoreCliSession() {
  if (agentMode) agentMode.value = state.agentMode || "agent";
  if (runtimeSelect) runtimeSelect.value = state.runtime || "local";
  syncRuntimeUi();

  if (!state.chatSessionId) return;
  try {
    const res = await fetch(`/api/chat/${state.chatSessionId}`);
    if (!res.ok) {
      persistChatSession(null);
      return;
    }
    const data = await res.json();
    renderCliMessages(data.messages || []);
    if (data.model && modelSelect) {
      state.model = data.model;
      modelSelect.value = data.model;
    }
    if (data.mode && agentMode) {
      agentMode.value = data.mode;
      persistAgentMode();
    }
    if (data.runtime && runtimeSelect) {
      runtimeSelect.value = data.runtime;
      persistRuntime();
    }
    if (data.cloud_repo && cloudRepo) cloudRepo.value = data.cloud_repo;
  } catch {
    /* ignore */
  }
}

modelSelect?.addEventListener("change", () => {
  persistModel();
  // modelo vale da próxima mensagem — não limpa diálogo nem history
  updateCliMetaLine();
});

agentMode?.addEventListener("change", () => {
  persistAgentMode();
  updateCliMetaLine();
});

runtimeSelect?.addEventListener("change", () => {
  persistRuntime();
  updateCliMetaLine();
});

cliClear?.addEventListener("click", () => {
  startNewDialog();
  cliInput?.focus();
});

cliInput?.addEventListener("input", autoResizeCli);
cliInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    cliForm?.requestSubmit();
  }
});

cliForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  cliError.hidden = true;
  const text = (cliInput.value || "").trim();
  if (!text) return;

  appendCliLine("user", text);
  cliInput.value = "";
  autoResizeCli();
  cliSend.disabled = true;
  setAgentBusy(true);

  const streamLine = appendCliLine("assistant", "", { streaming: true });
  let reply = "";

  try {
    const res = await fetch("/api/chat/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: text,
        session_id: state.chatSessionId,
        model: selectedModel(),
        scan_id: state.scanId || null,
        runtime: selectedRuntime(),
        agent_mode: selectedAgentMode(),
        cloud_repo: cloudRepo?.value?.trim() || null,
      }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || res.statusText);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";
      for (const part of parts) {
        const line = part
          .split("\n")
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trim())
          .join("");
        if (!line) continue;
        let event;
        try {
          event = JSON.parse(line);
        } catch {
          continue;
        }
        if (event.type === "meta") {
          if (event.session_id) persistChatSession(event.session_id);
          updateCliMetaLine(event.mode);
        } else if (event.type === "text") {
          reply += event.text || "";
          setCliBodyText(streamLine, reply);
        } else if (event.type === "tool") {
          appendCliLine("tool", `${event.name || "tool"} ${event.status || ""}`.trim());
        } else if (event.type === "task") {
          appendCliLine("task", event.text || event.status || "task");
        } else if (event.type === "thinking") {
          appendCliLine("thinking", (event.text || "").slice(0, 240));
        } else if (event.type === "status") {
          appendCliLine("status", event.text || "");
        } else if (event.type === "error") {
          throw new Error(event.text || "erro no stream");
        } else if (event.type === "done") {
          persistChatSession(event.session_id);
          reply = event.reply || reply;
          if (streamLine) {
            streamLine.classList.remove("streaming", "pending");
            setCliBodyText(streamLine, reply, { markdown: true });
          }
          // atualiza HISTORY sem mexer no diálogo
          refreshChatHistory();
        }
      }
    }

    if (streamLine && reply) {
      streamLine.classList.remove("streaming", "pending");
      setCliBodyText(streamLine, reply, { markdown: true });
    } else if (streamLine && !reply) {
      streamLine.remove();
    }
  } catch (err) {
    if (streamLine && !reply) streamLine.remove();
    cliError.hidden = false;
    cliError.textContent = err.message || String(err);
  } finally {
    cliSend.disabled = false;
    setAgentBusy(false);
    cliInput?.focus();
  }
});

function setAgentBusy(on) {
  agentFab?.classList.toggle("busy", !!on);
  if (agentFabPulse) agentFabPulse.hidden = !on;
  agent3d?.setBusy?.(!!on);
  agentCanvas?.classList.toggle("is-busy", !!on);
}

function openAgentModal(tab) {
  if (!agentModal) return;
  agentModal.hidden = false;
  switchAgentTab(tab || "dialog");
  agent3d?.resize?.();
  if (tab === "history") refreshChatHistory();
  else setTimeout(() => cliInput?.focus(), 50);
}

function closeAgentModal() {
  if (agentModal) agentModal.hidden = true;
}

function switchAgentTab(name) {
  document.querySelectorAll(".agent-tab").forEach((b) => {
    b.classList.toggle("active", b.dataset.agentTab === name);
  });
  if (agentPaneDialog) agentPaneDialog.hidden = name !== "dialog";
  if (agentPaneHistory) agentPaneHistory.hidden = name !== "history";
  if (name === "history") refreshChatHistory();
}

async function refreshChatHistory() {
  if (!chatHistoryEl) return;
  chatHistError.hidden = true;
  try {
    const res = await fetch("/api/chat");
    const data = await res.json();
    chatHistoryEl.innerHTML = "";
    const sessions = data.sessions || [];
    if (!sessions.length) {
      chatHistoryEl.innerHTML =
        "<li><span class='chat-hist-sub'>nenhuma conversa ainda</span></li>";
      return;
    }
    for (const s of sessions) {
      const li = document.createElement("li");
      const title = s.label || s.preview || s.session_id;
      const when = (s.updated_at || s.created_at || "").replace("T", " ").slice(0, 19);
      li.innerHTML = `
        <div class="chat-hist-main">
          <div class="chat-hist-label">${escapeHtml(title)}</div>
          <div class="chat-hist-sub">${escapeHtml(s.session_id)} · ${escapeHtml(
            s.model || "?"
          )} · ${escapeHtml(s.mode || "?")} · ${escapeHtml(s.runtime || "?")} · ${
            s.message_count || 0
          } msgs · ${escapeHtml(when)}</div>
          ${
            s.preview
              ? `<div class="chat-hist-sub">${escapeHtml(s.preview)}</div>`
              : ""
          }
        </div>
        <div class="chat-hist-actions">
          <button type="button" data-act="open">OPEN</button>
          <button type="button" data-act="edit">EDIT</button>
          <button type="button" data-act="del" class="danger">DEL</button>
        </div>
      `;
      li.querySelector('[data-act="open"]').addEventListener("click", () =>
        openChatSession(s.session_id)
      );
      li.querySelector('[data-act="edit"]').addEventListener("click", () =>
        openChatEditModal(s)
      );
      li.querySelector('[data-act="del"]').addEventListener("click", () =>
        deleteChatSession(s.session_id)
      );
      chatHistoryEl.appendChild(li);
    }
  } catch (err) {
    chatHistError.hidden = false;
    chatHistError.textContent = err.message || String(err);
  }
}

async function openChatSession(sessionId) {
  const res = await fetch(`/api/chat/${sessionId}`);
  if (!res.ok) {
    alert("conversa não encontrada");
    return;
  }
  const data = await res.json();
  persistChatSession(data.session_id);
  renderCliMessages(data.messages || []);
  if (data.model && modelSelect) {
    modelSelect.value = data.model;
    persistModel();
  }
  if (data.mode && agentMode) {
    agentMode.value = data.mode;
    persistAgentMode();
  }
  if (data.runtime && runtimeSelect) {
    runtimeSelect.value = data.runtime;
    persistRuntime();
  }
  if (cloudRepo) cloudRepo.value = data.cloud_repo || "";
  switchAgentTab("dialog");
  updateCliMetaLine("resumed");
  cliInput?.focus();
}

async function deleteChatSession(sessionId) {
  const ok = confirm(`Apagar conversa ${sessionId}?`);
  if (!ok) return;
  const res = await fetch(`/api/chat/${sessionId}`, { method: "DELETE" });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(data.detail || "falha ao apagar");
    return;
  }
  if (state.chatSessionId === sessionId) {
    persistChatSession(null);
    renderCliMessages([]);
  }
  await refreshChatHistory();
}

function openChatEditModal(session) {
  if (!chatEditModal) return;
  chatEditError.hidden = true;
  chatEditId.value = session.session_id;
  chatEditLabel.value = session.label || "";
  chatEditNotes.value = session.notes || "";
  chatEditModal.hidden = false;
}

function closeChatEditModal() {
  if (chatEditModal) chatEditModal.hidden = true;
}

chatEditClose?.addEventListener("click", closeChatEditModal);
chatEditCancel?.addEventListener("click", closeChatEditModal);
chatEditModal?.addEventListener("click", (e) => {
  if (e.target === chatEditModal) closeChatEditModal();
});

chatEditForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  chatEditError.hidden = true;
  const id = chatEditId.value;
  try {
    const res = await fetch(`/api/chat/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: chatEditLabel.value.trim(),
        notes: chatEditNotes.value,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || res.statusText);
    closeChatEditModal();
    await refreshChatHistory();
  } catch (err) {
    chatEditError.hidden = false;
    chatEditError.textContent = err.message || String(err);
  }
});

document.querySelectorAll(".agent-tab").forEach((btn) => {
  btn.addEventListener("click", () => switchAgentTab(btn.dataset.agentTab));
});

agentClose?.addEventListener("click", closeAgentModal);
agentModal?.addEventListener("click", (e) => {
  if (e.target === agentModal) closeAgentModal();
});
chatHistRefresh?.addEventListener("click", refreshChatHistory);

function openAgentFromFab(e) {
  e?.preventDefault?.();
  e?.stopPropagation?.();
  openAgentModal("dialog");
}

agentFab?.addEventListener("click", openAgentFromFab);
agentFab?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    openAgentFromFab(e);
  }
});

if (agentCanvas && window.HackteusAgent3D) {
  agent3d = window.HackteusAgent3D.mount(agentCanvas);
}
