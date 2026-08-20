const STATUS_LABELS = {
  expired: "Expirado",
  critical: "Crítico",
  warning: "Atenção",
  ok: "OK",
  wildcard: "Wildcard",
  unresolved: "Não resolvido",
  ct_only: "Só CT log",
};

const TERMINAL_STATES = new Set(["done", "partial_timeout", "failed"]);

const form = document.getElementById("scan-form");
const submitBtn = document.getElementById("submit-btn");
const progressCard = document.getElementById("progress-card");
const progressMessage = document.getElementById("progress-message");
const progressCounts = document.getElementById("progress-counts");
const progressFill = document.getElementById("progress-fill");
const resultsCard = document.getElementById("results-card");
const resultsBody = document.getElementById("results-body");
const errorCard = document.getElementById("error-card");
const errorMessage = document.getElementById("error-message");
const filterStatus = document.getElementById("filter-status");
const exportCsv = document.getElementById("export-csv");
const exportJson = document.getElementById("export-json");
const overviewCard = document.getElementById("overview-card");
const dashboardStatsCard = document.getElementById("dashboard-stats-card");
const dashboardEmptyCard = document.getElementById("dashboard-empty-card");
const chartIssuers = document.getElementById("chart-issuers");
const chartExpiry = document.getElementById("chart-expiry");
const detailModal = document.getElementById("detail-modal");

let currentRecords = [];
let currentFilteredRows = [];
let currentEventSource = null;

function resetUI() {
  errorCard.classList.add("hidden");
  resultsCard.classList.add("hidden");
  overviewCard.classList.add("hidden");
  dashboardStatsCard.classList.add("hidden");
  detailModal.classList.add("hidden");
  progressCard.classList.remove("hidden");
  progressFill.style.width = "0%";
  progressMessage.textContent = "Iniciando...";
  progressCounts.textContent = "";
  resultsBody.innerHTML = "";
  currentRecords = [];
  currentFilteredRows = [];
  if (currentEventSource) {
    currentEventSource.close();
    currentEventSource = null;
  }
}

function showError(message) {
  progressCard.classList.add("hidden");
  errorCard.classList.remove("hidden");
  errorMessage.textContent = message;
}

// Glifo por status, redundante com a cor — daltonismo atinge ~8% dos
// homens, então o status nunca deveria depender só da cor do badge pra ser
// lido.
const STATUS_GLYPHS = {
  expired: "✕",
  critical: "▲",
  warning: "◆",
  ok: "✓",
  wildcard: "•",
  unresolved: "•",
  ct_only: "•",
};

function badgeFor(status) {
  const label = STATUS_LABELS[status] || status;
  const glyph = STATUS_GLYPHS[status] || "";
  return `<span class="badge badge-${status}"><span aria-hidden="true">${glyph}</span> ${label}</span>`;
}

function renderSummaryStats() {
  // Cada card já declara seu status via data-filter (mesmo atributo usado
  // pelo listener de clique abaixo) — evita manter uma segunda lista de
  // status hardcoded em paralelo à do HTML.
  document.querySelectorAll("#summary-stats .stat-card").forEach((card) => {
    const status = card.dataset.filter;
    const count = currentRecords.filter((record) => record.status === status).length;
    card.querySelector(".stat-count").textContent = count;
  });
}

function renderTable() {
  const filter = filterStatus.value;
  const queueStatuses = new Set(["expired", "critical", "warning"]);

  currentFilteredRows = currentRecords.filter((record) => {
    if (filter === "all") return true;
    if (filter === "queue") return queueStatuses.has(record.status);
    return record.status === filter;
  });

  resultsBody.innerHTML = currentFilteredRows
    .map((record, index) => {
      const expiresAt = record.not_after
        ? new Date(record.not_after).toLocaleDateString("pt-BR")
        : "—";
      const daysLeft = record.days_until_expiry ?? "—";
      const origin = record.origin === "live" ? "Handshake ao vivo" : "CT log";
      const note = record.note ? record.note : "";
      // data-label alimenta o CSS que transforma cada <td> num par
      // rótulo/valor quando a tabela vira cartão empilhado em telas
      // estreitas (ver style.css, breakpoint de 640px).
      return `<tr data-row-index="${index}">
        <td data-label="Status">${badgeFor(record.status)}</td>
        <td data-label="Host">${escapeHtml(record.host)}</td>
        <td data-label="Emissor">${escapeHtml(record.issuer || "—")}</td>
        <td data-label="Expira em">${expiresAt}</td>
        <td data-label="Dias restantes">${daysLeft}</td>
        <td data-label="Origem">${origin}</td>
        <td data-label="Observação" class="note-cell">${escapeHtml(note)}</td>
      </tr>`;
    })
    .join("");
}

function formatDateTime(value) {
  return value ? new Date(value).toLocaleString("pt-BR") : "—";
}

function openDetailModal(record) {
  document.getElementById("detail-host").textContent = record.host;
  document.getElementById("detail-status").innerHTML = badgeFor(record.status);
  document.getElementById("detail-origin").textContent =
    record.origin === "live" ? "Handshake ao vivo" : "Só CT log";
  document.getElementById("detail-subject").textContent = record.subject_cn || "—";
  document.getElementById("detail-issuer").textContent = record.issuer || "—";
  document.getElementById("detail-not-before").textContent = formatDateTime(record.not_before);
  document.getElementById("detail-not-after").textContent = formatDateTime(record.not_after);
  document.getElementById("detail-days").textContent = record.days_until_expiry ?? "—";
  document.getElementById("detail-serial").textContent = record.serial_number || "—";
  document.getElementById("detail-fingerprint").textContent = record.sha256_fingerprint || "—";
  document.getElementById("detail-ip").textContent = record.resolved_ip || "—";
  document.getElementById("detail-sans").textContent =
    record.sans && record.sans.length ? record.sans.join(", ") : "—";
  document.getElementById("detail-note").textContent = record.note || "—";
  detailModal.classList.remove("hidden");
}

function closeDetailModal() {
  detailModal.classList.add("hidden");
}

function barChart(container, entries, { max } = {}) {
  if (!entries.length) {
    container.innerHTML = '<p class="empty">Sem dados suficientes.</p>';
    return;
  }
  const peak = max ?? Math.max(...entries.map(([, count]) => count));
  container.innerHTML = entries
    .map(([label, count]) => {
      const pct = peak > 0 ? Math.round((count / peak) * 100) : 0;
      return `<div class="bar-row">
        <span class="bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        <span class="bar-value">${count}</span>
      </div>`;
    })
    .join("");
}

function renderOverviewCharts() {
  const liveRecords = currentRecords.filter((record) => record.origin === "live");
  if (!liveRecords.length) {
    overviewCard.classList.add("hidden");
    return;
  }
  overviewCard.classList.remove("hidden");

  const issuerCounts = new Map();
  liveRecords.forEach((record) => {
    const issuer = record.issuer || "Desconhecido";
    issuerCounts.set(issuer, (issuerCounts.get(issuer) || 0) + 1);
  });
  const topIssuers = [...issuerCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  barChart(chartIssuers, topIssuers);

  const buckets = [
    ["Expirado", (d) => d < 0],
    ["0-7 dias", (d) => d >= 0 && d < 7],
    ["8-30 dias", (d) => d >= 7 && d < 30],
    ["31-90 dias", (d) => d >= 30 && d < 90],
    ["90+ dias", (d) => d >= 90],
  ];
  const expiryEntries = buckets.map(([label, match]) => [
    label,
    liveRecords.filter((r) => typeof r.days_until_expiry === "number" && match(r.days_until_expiry))
      .length,
  ]);
  barChart(chartExpiry, expiryEntries);
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}

function updateProgress(snapshot) {
  const total = snapshot.hosts_total || 0;
  const done = snapshot.hosts_done || 0;
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  progressFill.style.width = `${pct}%`;
  progressMessage.textContent = snapshot.progress_message || snapshot.state;
  progressCounts.textContent = total > 0 ? `${done}/${total} hosts` : "";
  currentRecords = snapshot.records || [];
}

function finish(snapshot, jobId) {
  updateProgress(snapshot);
  progressCard.classList.add("hidden");

  if (snapshot.state === "failed") {
    showError(snapshot.error || "Falha inesperada durante o scan.");
    return;
  }

  resultsCard.classList.remove("hidden");
  dashboardStatsCard.classList.remove("hidden");
  dashboardEmptyCard.classList.add("hidden");
  exportCsv.href = `/api/scan/${jobId}/export.csv`;
  exportJson.href = `/api/scan/${jobId}/export.json`;
  renderSummaryStats();
  renderTable();
  renderOverviewCharts();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  resetUI();
  submitBtn.disabled = true;

  const domain = document.getElementById("domain").value.trim();
  const manualHostsRaw = document.getElementById("manual-hosts").value;
  const manualHosts = manualHostsRaw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const consent = document.getElementById("consent").checked;

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, manual_hosts: manualHosts, consent }),
    });

    if (response.status === 401) {
      window.location.href = "/";
      return;
    }
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }

    const { job_id: jobId } = await response.json();
    const source = new EventSource(`/api/scan/${jobId}/events`);
    currentEventSource = source;

    source.onmessage = (event) => {
      const snapshot = JSON.parse(event.data);
      if (TERMINAL_STATES.has(snapshot.state)) {
        source.close();
        finish(snapshot, jobId);
      } else {
        updateProgress(snapshot);
      }
    };

    source.onerror = () => {
      source.close();
      showError("Conexão com o servidor perdida durante o scan.");
    };
  } catch (err) {
    showError(err.message || "Não foi possível iniciar o scan.");
  } finally {
    submitBtn.disabled = false;
  }
});

filterStatus.addEventListener("change", renderTable);

document.getElementById("summary-stats").addEventListener("click", (event) => {
  const card = event.target.closest(".stat-card");
  if (!card) return;
  filterStatus.value = card.dataset.filter;
  renderTable();
  location.hash = "#inventario";
});

resultsBody.addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-row-index]");
  if (!row) return;
  const record = currentFilteredRows[Number(row.dataset.rowIndex)];
  if (record) openDetailModal(record);
});

document.getElementById("detail-modal-close").addEventListener("click", closeDetailModal);

detailModal.addEventListener("click", (event) => {
  if (event.target === detailModal) closeDetailModal();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !detailModal.classList.contains("hidden")) {
    closeDetailModal();
  }
});

// Navegação por telas — cada função vive na sua própria tela (Dashboard /
// Inventário / Emissão / Renovação / Configurações), roteada pelo hash da
// URL. Isso dá link direto e botão voltar/avançar do navegador de graça,
// sem precisar de framework nenhum.
const SCREEN_NAMES = ["dashboard", "inventario", "emissao", "renovacao", "configuracoes"];
const screenSections = Object.fromEntries(
  SCREEN_NAMES.map((name) => [name, document.getElementById(`screen-${name}`)])
);
const navLinks = document.querySelectorAll("#main-nav a[data-screen]");

function showScreen(name) {
  if (!SCREEN_NAMES.includes(name)) name = "dashboard";
  Object.entries(screenSections).forEach(([key, el]) => {
    el.classList.toggle("hidden", key !== name);
  });
  navLinks.forEach((a) => {
    if (a.dataset.screen === name) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  if (name === "configuracoes") refreshSecurityStatus();
}

function routeFromHash() {
  showScreen((location.hash || "#dashboard").slice(1));
}

window.addEventListener("hashchange", routeFromHash);
// A chamada inicial fica no fim do arquivo (não aqui) — se a página
// carregar direto em #configuracoes, showScreen() chama
// refreshSecurityStatus(), que usa consts definidas mais abaixo.

// Segurança / MFA opcional — ativação exige provar (com um código válido)
// que o autenticador está configurado certo antes de marcar como ativo.
const securityError = document.getElementById("security-error");
const securityStatusView = document.getElementById("security-status-view");
const securityEnrollView = document.getElementById("security-enroll-view");
const securityDisableView = document.getElementById("security-disable-view");
const securityMfaState = document.getElementById("security-mfa-state");
const securityEnableBtn = document.getElementById("security-enable-btn");
const securityDisableBtn = document.getElementById("security-disable-btn");

function showSecurityError(message) {
  securityError.textContent = message;
  securityError.classList.remove("hidden");
}

function clearSecurityError() {
  securityError.classList.add("hidden");
}

function showSecurityView(view) {
  [securityStatusView, securityEnrollView, securityDisableView].forEach((section) =>
    section.classList.add("hidden")
  );
  view.classList.remove("hidden");
}

async function refreshSecurityStatus() {
  clearSecurityError();
  const response = await fetch("/api/auth/mfa/status");
  const { enabled } = await response.json();
  securityMfaState.textContent = enabled ? "ativado" : "desativado";
  securityEnableBtn.classList.toggle("hidden", enabled);
  securityDisableBtn.classList.toggle("hidden", !enabled);
  showSecurityView(securityStatusView);
}

securityEnableBtn.addEventListener("click", async () => {
  clearSecurityError();
  try {
    const response = await fetch("/api/auth/mfa/enroll", { method: "POST" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Erro ${response.status}`);
    document.getElementById("security-mfa-qr").src = data.qr_data_uri;
    document.getElementById("security-mfa-secret").textContent = data.secret;
    showSecurityView(securityEnrollView);
  } catch (err) {
    showSecurityError(err.message);
  }
});

securityDisableBtn.addEventListener("click", () => {
  clearSecurityError();
  showSecurityView(securityDisableView);
});

document.getElementById("security-enroll-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearSecurityError();
  const code = document.getElementById("security-enroll-code").value.trim();
  try {
    const response = await fetch("/api/auth/mfa/enroll/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Erro ${response.status}`);
    await refreshSecurityStatus();
  } catch (err) {
    showSecurityError(err.message);
  }
});

document.getElementById("security-disable-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearSecurityError();
  const password = document.getElementById("security-disable-password").value;
  try {
    const response = await fetch("/api/auth/mfa/disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Erro ${response.status}`);
    document.getElementById("security-disable-password").value = "";
    await refreshSecurityStatus();
  } catch (err) {
    showSecurityError(err.message);
  }
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  // Mesma proteção usada em auth.js: confirma que o cookie já foi
  // removido antes de navegar, para não recarregar como se ainda
  // estivesse autenticado.
  for (let attempt = 0; attempt < 15; attempt++) {
    const response = await fetch("/api/auth/status");
    const { state } = await response.json();
    if (state !== "authenticated") break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  // location.reload(), não location.href = "/": ver comentário equivalente
  // em auth.js::navigateToApp() — um reload de verdade é o único jeito
  // confiável de garantir que o navegador já considerou o cookie
  // atualizado antes de decidir qual página servir.
  window.location.reload();
});

// ACME DNS-01 (emissão/renovação real via Let's Encrypt + Cloudflare)
const acmeDnsStatus = document.getElementById("acme-dns-status");
const acmeDnsFormDetails = document.getElementById("acme-dns-form-details");
const acmeDnsForm = document.getElementById("acme-dns-form");
const acmeRenewForm = document.getElementById("acme-renew-form");
const acmeRenewBtn = document.getElementById("acme-renew-btn");
const acmeProgress = document.getElementById("acme-progress");
const acmeProgressMessage = document.getElementById("acme-progress-message");
const acmeResult = document.getElementById("acme-result");
const acmeResultMessage = document.getElementById("acme-result-message");
const acmeDownloadCert = document.getElementById("acme-download-cert");
const acmeDownloadKey = document.getElementById("acme-download-key");
const acmeError = document.getElementById("acme-error");
const acmeCertsList = document.getElementById("acme-certs-list");

const ACME_TERMINAL_STATES = new Set(["done", "failed"]);

function showAcmeError(message) {
  acmeError.textContent = message;
  acmeError.classList.remove("hidden");
}

function hideAcmeError() {
  acmeError.classList.add("hidden");
  acmeError.textContent = "";
}

async function refreshAcmeStatus() {
  try {
    const response = await fetch("/api/acme/status");
    if (!response.ok) return;
    const status = await response.json();
    if (status.dns_configured) {
      acmeDnsStatus.textContent = `DNS configurado (provedor: ${status.dns_provider}).`;
      acmeDnsFormDetails.open = false;
    } else {
      acmeDnsStatus.textContent = "Nenhum provedor de DNS configurado ainda.";
      acmeDnsFormDetails.open = true;
    }
  } catch {
    acmeDnsStatus.textContent = "";
  }
}

async function refreshAcmeCertificates() {
  try {
    const response = await fetch("/api/acme/certificates");
    if (!response.ok) return;
    const certs = await response.json();
    if (!certs.length) {
      acmeCertsList.innerHTML = "Nenhum certificado emitido ainda.";
      return;
    }
    acmeCertsList.innerHTML = certs
      .map((cert) => {
        const issuedAt = formatDateTime(cert.issued_at);
        const notAfter = formatDateTime(cert.not_after);
        return `<div class="acme-cert-row">
          <strong>${escapeHtml(cert.domain)}</strong>
          <span>${escapeHtml(cert.environment)}</span>
          <span>emitido em ${issuedAt}</span>
          <span>expira em ${notAfter}</span>
          <a class="button-link" href="/api/acme/certificates/${encodeURIComponent(cert.id)}/fullchain.pem">certificado</a>
          <a class="button-link" href="/api/acme/certificates/${encodeURIComponent(cert.id)}/privkey.pem">chave privada</a>
        </div>`;
      })
      .join("");
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

acmeDnsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideAcmeError();
  const token = document.getElementById("cloudflare-token").value.trim();
  const submitBtn = acmeDnsForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/acme/dns-credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_token: token }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    acmeDnsForm.reset();
    await refreshAcmeStatus();
  } catch (err) {
    showAcmeError(err.message || "Não foi possível salvar o token da Cloudflare.");
  } finally {
    submitBtn.disabled = false;
  }
});

acmeRenewForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideAcmeError();
  acmeResult.classList.add("hidden");
  acmeRenewBtn.disabled = true;

  const domain = document.getElementById("acme-domain").value.trim();
  const environment = document.getElementById("acme-environment").value;

  try {
    const response = await fetch("/api/acme/renew", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, environment }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }

    const { job_id: jobId } = await response.json();
    acmeProgress.classList.remove("hidden");
    acmeProgressMessage.textContent = "Iniciando emissão...";

    const source = new EventSource(`/api/acme/renew/${jobId}/events`);
    source.onmessage = async (event) => {
      const job = JSON.parse(event.data);
      acmeProgressMessage.textContent = job.progress_message || job.state;

      if (!ACME_TERMINAL_STATES.has(job.state)) return;
      source.close();
      acmeProgress.classList.add("hidden");
      acmeRenewBtn.disabled = false;

      if (job.state === "failed") {
        showAcmeError(job.error || "Falha inesperada durante a emissão do certificado.");
        return;
      }

      acmeResultMessage.textContent = `Certificado emitido para ${job.domain} (${job.environment}).`;
      acmeDownloadCert.href = `/api/acme/certificates/${job.certificate_id}/fullchain.pem`;
      acmeDownloadKey.href = `/api/acme/certificates/${job.certificate_id}/privkey.pem`;
      acmeResult.classList.remove("hidden");
      await refreshAcmeCertificates();
    };
    source.onerror = () => {
      source.close();
      acmeProgress.classList.add("hidden");
      acmeRenewBtn.disabled = false;
      showAcmeError("Conexão com o servidor perdida durante a emissão.");
    };
  } catch (err) {
    acmeRenewBtn.disabled = false;
    showAcmeError(err.message || "Não foi possível iniciar a emissão do certificado.");
  }
});

refreshAcmeStatus();
refreshAcmeCertificates();

// Rota inicial — por último, depois que toda função/const que uma tela
// pode precisar (ex: refreshSecurityStatus) já foi definida.
routeFromHash();

