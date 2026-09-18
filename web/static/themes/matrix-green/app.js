const $ = (id) => document.getElementById(id);

const url = $("url");
const repo = $("repo");
const mode = $("mode");
const consent = $("consent");
const withAgent = $("with-agent");
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

function syncModeFromRepo() {
  if (repo.value.trim() && mode.value === "surface") {
    // sugestão leve — usuário pode mudar
  }
}

repo.addEventListener("input", syncModeFromRepo);

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    briefEl.hidden = tab !== "brief";
    reportEl.hidden = tab !== "report";
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
    if (data.cursor_api_key_configured) {
      healthEl.textContent = "uplink · key ok";
      healthEl.className = "pill ok";
    } else {
      healthEl.textContent = "uplink · missing key";
      healthEl.className = "pill bad";
    }
  } catch {
    healthEl.textContent = "uplink · offline";
    healthEl.className = "pill bad";
  }
}

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
    li.innerHTML = `
      <span><strong>${s.scan_id}</strong> · ${s.mode || "?"} · ${s.url || ""}</span>
      <button type="button" data-id="${s.scan_id}">OPEN</button>
    `;
    li.querySelector("button").addEventListener("click", () => openScan(s.scan_id));
    historyEl.appendChild(li);
  }
}

function renderResult(data) {
  setScanVisual(false);
  statusEl.className = "status done";
  statusText(`scan ${data.scan_id} · complete`);
  const s = data.summary || {};
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

  briefEl.textContent = data.brief_md || data.brief || "_ empty";
  reportEl.textContent = data.report_md || data.report || "_ no REPORT.md yet";
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
    summary: {},
    brief_md: data.brief_md,
    report_md: data.report_md,
  });
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
  if (!consent.value.trim()) {
    formError.hidden = false;
    formError.textContent = "Informe o consentimento (owner ou contract:…).";
    return;
  }

  submit.disabled = true;
  setScanVisual(true);
  statusEl.className = "status running";
  statusText(
    withAgent.checked
      ? "collecting · browser · agent uplink…"
      : "collecting · surface · browser…"
  );
  briefEl.textContent = "_ streaming evidence…";
  reportEl.textContent = "_ waiting analyst…";

  const payload = {
    url: targetUrl,
    repo: repo.value.trim() || null,
    mode: mode.value,
    consent: consent.value.trim(),
    with_agent: withAgent.checked,
    with_browser: withBrowser.checked,
    auth_user: authUser.value.trim() || null,
    auth_password: authPassword.value || null,
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
