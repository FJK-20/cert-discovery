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
  // Largura da barra via propriedade CSSOM (.style.width) depois de
  // montar o HTML, não como atributo style="" inline — mantém o CSP sem
  // precisar de style-src 'unsafe-inline'.
  container.innerHTML = entries
    .map(
      ([label, count]) => `<div class="bar-row">
        <span class="bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
        <div class="bar-track"><div class="bar-fill"></div></div>
        <span class="bar-value">${count}</span>
      </div>`
    )
    .join("");
  container.querySelectorAll(".bar-fill").forEach((el, index) => {
    const [, count] = entries[index];
    const pct = peak > 0 ? Math.round((count / peak) * 100) : 0;
    el.style.width = `${pct}%`;
  });
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
  refreshScanHistory();
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

// ACME DNS-01 (emissão/renovação real via Let's Encrypt). Modo padrão é
// manual (funciona com qualquer provedor de DNS); Cloudflare é um plugin
// opcional pra quem quer automação total — ver "A decisão de arquitetura"
// no roadmap.
const acmeDnsMode = document.getElementById("acme-dns-mode");
const acmeCloudflareConfig = document.getElementById("acme-cloudflare-config");
const acmeDnsStatus = document.getElementById("acme-dns-status");
const acmeDnsFormDetails = document.getElementById("acme-dns-form-details");
const acmeDnsForm = document.getElementById("acme-dns-form");
const acmeRenewForm = document.getElementById("acme-renew-form");
const acmeRenewBtn = document.getElementById("acme-renew-btn");
const acmeDnsInstructions = document.getElementById("acme-dns-instructions");
const acmeDnsInstrTitle = document.getElementById("acme-dns-instr-title");
const acmeDnsInstrType = document.getElementById("acme-dns-instr-type");
const acmeDnsInstrName = document.getElementById("acme-dns-instr-name");
const acmeDnsInstrValue = document.getElementById("acme-dns-instr-value");
const acmeDnsInstrHint = document.getElementById("acme-dns-instr-hint");
const acmeConfirmDnsBtn = document.getElementById("acme-confirm-dns-btn");
const acmeConfirmDnsMessage = document.getElementById("acme-confirm-dns-message");
const acmeProgress = document.getElementById("acme-progress");
const acmeProgressMessage = document.getElementById("acme-progress-message");
const acmeResult = document.getElementById("acme-result");
const acmeResultMessage = document.getElementById("acme-result-message");
const acmeDownloadCert = document.getElementById("acme-download-cert");
const acmeDownloadKey = document.getElementById("acme-download-key");
const acmeError = document.getElementById("acme-error");
const acmeCertsList = document.getElementById("acme-certs-list");

const ACME_TERMINAL_STATES = new Set(["done", "failed"]);
let currentAcmeJobId = null;

// Cloudflare e delegação CNAME compartilham a mesma credencial (a
// delegação usa o token pra publicar TXT na zona de delegação, não na
// zona do domínio emitido) — os dois precisam do painel de configuração.
acmeDnsMode.addEventListener("change", () => {
  const needsCredentials = acmeDnsMode.value === "cloudflare" || acmeDnsMode.value === "cname_delegation";
  acmeCloudflareConfig.classList.toggle("hidden", !needsCredentials);
});

document.querySelectorAll(".copy-btn[data-copy-target]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const target = document.getElementById(btn.dataset.copyTarget);
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.textContent);
      const original = btn.textContent;
      btn.textContent = "copiado!";
      setTimeout(() => {
        btn.textContent = original;
      }, 1500);
    } catch {
      // clipboard pode falhar (permissão, contexto não-seguro) — o valor
      // já está selecionável na tela, então não é um caminho sem saída.
    }
  });
});

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
      acmeDnsStatus.textContent = status.delegation_zone
        ? `DNS configurado (provedor: ${status.dns_provider}, zona de delegação: ${status.delegation_zone}).`
        : `DNS configurado (provedor: ${status.dns_provider}). Sem zona de delegação — modo "Delegação CNAME" não vai funcionar até configurar uma.`;
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
    const AUTO_RENEWABLE = new Set(["cloudflare", "cname_delegation"]);
    acmeCertsList.innerHTML = certs
      .map((cert) => {
        const issuedAt = formatDateTime(cert.issued_at);
        const notAfter = formatDateTime(cert.not_after);
        const renewalNote = AUTO_RENEWABLE.has(cert.dns_mode)
          ? "renovação automática"
          : "renovação manual";
        return `<div class="acme-cert-row">
          <strong>${escapeHtml(cert.domain)}</strong>
          <span>${escapeHtml(cert.environment)}</span>
          <span>emitido em ${issuedAt}</span>
          <span>expira em ${notAfter}</span>
          <span>${renewalNote}</span>
          <a class="button-link" href="/api/acme/certificates/${encodeURIComponent(cert.id)}/fullchain.pem">certificado</a>
          <a class="button-link" data-requires-role="admin,operador" href="/api/acme/certificates/${encodeURIComponent(cert.id)}/privkey.pem">chave privada</a>
        </div>`;
      })
      .join("");
    applyRoleVisibility();
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

acmeDnsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideAcmeError();
  const token = document.getElementById("cloudflare-token").value.trim();
  const delegationZone = document.getElementById("cloudflare-delegation-zone").value.trim();
  const submitBtn = acmeDnsForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/acme/dns-credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_token: token, delegation_zone: delegationZone || null }),
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
  acmeDnsInstructions.classList.add("hidden");
  acmeConfirmDnsMessage.textContent = "";
  acmeRenewBtn.disabled = true;

  const domain = document.getElementById("acme-domain").value.trim();
  const environment = document.getElementById("acme-environment").value;
  const dnsMode = acmeDnsMode.value;

  try {
    const response = await fetch("/api/acme/renew", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, environment, dns_mode: dnsMode }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }

    const { job_id: jobId } = await response.json();
    currentAcmeJobId = jobId;
    acmeProgress.classList.remove("hidden");
    acmeProgressMessage.textContent = "Iniciando emissão...";

    const source = new EventSource(`/api/acme/renew/${jobId}/events`);
    source.onmessage = async (event) => {
      const job = JSON.parse(event.data);
      acmeProgressMessage.textContent = job.progress_message || job.state;

      if (job.state === "awaiting_dns") {
        acmeProgress.classList.add("hidden");
        const isCname = job.dns_record_type === "CNAME";
        acmeDnsInstrTitle.textContent = isCname
          ? "Configure este CNAME uma vez (fica valendo pras próximas renovações)"
          : "Crie este registro no DNS do seu domínio";
        acmeDnsInstrType.textContent = job.dns_record_type || "TXT";
        acmeDnsInstrName.textContent = job.dns_record_name || "";
        acmeDnsInstrValue.textContent = job.dns_record_value || "";
        acmeDnsInstrHint.textContent = isCname
          ? "Depois de criar o CNAME, clique abaixo — verificamos se já propagou. A partir da próxima vez, esse passo nem aparece mais: a emissão fica automática."
          : "Depois de criar o registro, clique abaixo — verificamos se já propagou antes de avisar a Let's Encrypt. Se ainda não propagou, é só tentar de novo em alguns instantes.";
        acmeDnsInstructions.classList.remove("hidden");
        return;
      }
      acmeDnsInstructions.classList.add("hidden");

      if (!ACME_TERMINAL_STATES.has(job.state)) {
        acmeProgress.classList.remove("hidden");
        return;
      }
      source.close();
      acmeProgress.classList.add("hidden");
      acmeRenewBtn.disabled = false;

      if (job.state === "failed") {
        showAcmeError(job.error || "Falha inesperada durante a emissão do certificado.");
        await refreshRenewalHistory();
        return;
      }

      acmeResultMessage.textContent = `Certificado emitido para ${job.domain} (${job.environment}).`;
      acmeDownloadCert.href = `/api/acme/certificates/${job.certificate_id}/fullchain.pem`;
      acmeDownloadKey.href = `/api/acme/certificates/${job.certificate_id}/privkey.pem`;
      acmeResult.classList.remove("hidden");
      await refreshAcmeCertificates();
      await refreshRenewalHistory();
    };
    source.onerror = () => {
      source.close();
      acmeProgress.classList.add("hidden");
      acmeDnsInstructions.classList.add("hidden");
      acmeRenewBtn.disabled = false;
      showAcmeError("Conexão com o servidor perdida durante a emissão.");
    };
  } catch (err) {
    acmeRenewBtn.disabled = false;
    showAcmeError(err.message || "Não foi possível iniciar a emissão do certificado.");
  }
});

acmeConfirmDnsBtn.addEventListener("click", async () => {
  if (!currentAcmeJobId) return;
  acmeConfirmDnsBtn.disabled = true;
  acmeConfirmDnsMessage.textContent = "Verificando...";
  try {
    const response = await fetch(`/api/acme/renew/${currentAcmeJobId}/confirm-dns`, {
      method: "POST",
    });
    const data = await response.json();
    if (!response.ok) {
      // 409 aqui é esperado (ainda não propagou) — não é um erro fatal,
      // a pessoa só tenta de novo.
      acmeConfirmDnsMessage.textContent = data.detail || "Ainda não encontramos o registro.";
      return;
    }
    acmeConfirmDnsMessage.textContent = "DNS confirmado — continuando com a emissão...";
  } catch {
    acmeConfirmDnsMessage.textContent = "Não foi possível verificar agora. Tente de novo.";
  } finally {
    acmeConfirmDnsBtn.disabled = false;
  }
});

refreshAcmeStatus();
refreshAcmeCertificates();

// CSR manual — pra CA que não fala ACME. Gera chave+CSR aqui (a chave
// nunca sai do servidor), a pessoa leva o CSR pra CA escolhida e cola o
// certificado assinado de volta quando chegar; os dois caminhos (esse e o
// ACME acima) convergem na mesma lista de certificados emitidos.
const csrGenerateForm = document.getElementById("csr-generate-form");
const csrError = document.getElementById("csr-error");
const csrPendingList = document.getElementById("csr-pending-list");

function showCsrError(message) {
  csrError.textContent = message;
  csrError.classList.remove("hidden");
}

function hideCsrError() {
  csrError.classList.add("hidden");
  csrError.textContent = "";
}

async function refreshPendingCsrs() {
  try {
    const response = await fetch("/api/csr");
    if (!response.ok) return;
    const items = await response.json();
    if (!items.length) {
      csrPendingList.innerHTML = "Nenhum CSR pendente.";
      return;
    }
    csrPendingList.innerHTML = items
      .map(
        (item) => `<div class="csr-pending-item" data-csr-id="${escapeHtml(item.id)}">
          <strong>${escapeHtml(item.domains.join(", "))}</strong>
          <p class="hint">Gerado em ${formatDateTime(item.created_at)}</p>
          <div class="csr-actions">
            <a class="button-link" href="/api/csr/${encodeURIComponent(item.id)}/download">Baixar CSR</a>
            <button type="button" class="csr-discard-btn" data-requires-role="admin,operador">Descartar</button>
          </div>
          <form class="csr-complete-form" data-requires-role="admin,operador">
            <label>Cole aqui o certificado recebido da CA (PEM)</label>
            <textarea class="csr-cert-input" rows="6" placeholder="-----BEGIN CERTIFICATE-----" required></textarea>
            <button type="submit">Concluir e salvar certificado</button>
          </form>
          <p class="csr-item-message hint"></p>
        </div>`
      )
      .join("");
    applyRoleVisibility();
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

csrGenerateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideCsrError();
  const raw = document.getElementById("csr-domains").value;
  const domains = raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const submitBtn = csrGenerateForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/csr", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domains }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    csrGenerateForm.reset();
    await refreshPendingCsrs();
  } catch (err) {
    showCsrError(err.message || "Não foi possível gerar o CSR.");
  } finally {
    submitBtn.disabled = false;
  }
});

csrPendingList.addEventListener("click", async (event) => {
  const discardBtn = event.target.closest(".csr-discard-btn");
  if (!discardBtn) return;
  const id = discardBtn.closest("[data-csr-id]").dataset.csrId;
  await fetch(`/api/csr/${encodeURIComponent(id)}`, { method: "DELETE" });
  await refreshPendingCsrs();
});

csrPendingList.addEventListener("submit", async (event) => {
  const form = event.target.closest(".csr-complete-form");
  if (!form) return;
  event.preventDefault();
  const item = form.closest("[data-csr-id]");
  const id = item.dataset.csrId;
  const messageEl = item.querySelector(".csr-item-message");
  const certPem = form.querySelector(".csr-cert-input").value.trim();
  const submitBtn = form.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  messageEl.textContent = "";
  try {
    const response = await fetch(`/api/csr/${encodeURIComponent(id)}/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ certificate_pem: certPem }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || `Erro ${response.status}`);
    await refreshPendingCsrs();
    await refreshAcmeCertificates();
  } catch (err) {
    messageEl.textContent = err.message || "Não foi possível salvar o certificado.";
    submitBtn.disabled = false;
  }
});

refreshPendingCsrs();

// Notificações (webhook/e-mail) — configuráveis em Configurações,
// disparadas pelo agendador de renovação (ver seção abaixo).
const notifyStatus = document.getElementById("notify-status");
const notifyFormDetails = document.getElementById("notify-form-details");
const notifyForm = document.getElementById("notify-form");
const notifyError = document.getElementById("notify-error");
const notifyTestBtn = document.getElementById("notify-test-btn");
const notifyTestMessage = document.getElementById("notify-test-message");

function showNotifyError(message) {
  notifyError.textContent = message;
  notifyError.classList.remove("hidden");
}

function hideNotifyError() {
  notifyError.classList.add("hidden");
  notifyError.textContent = "";
}

async function refreshNotifyStatus() {
  try {
    const response = await fetch("/api/notifications/config");
    if (!response.ok) return;
    const config = await response.json();
    const parts = [];
    parts.push(config.webhook_configured ? "webhook configurado" : "webhook não configurado");
    parts.push(config.email_configured ? `e-mail configurado (${escapeHtml(config.smtp_host)})` : "e-mail não configurado");
    notifyStatus.textContent = parts.join(" · ");
    notifyFormDetails.open = !config.webhook_configured && !config.email_configured;

    if (config.smtp_host) document.getElementById("notify-smtp-host").value = config.smtp_host;
    if (config.smtp_port) document.getElementById("notify-smtp-port").value = config.smtp_port;
    document.getElementById("notify-smtp-tls").checked = config.smtp_use_tls !== false;
    if (config.smtp_username) document.getElementById("notify-smtp-username").value = config.smtp_username;
    if (config.smtp_from) document.getElementById("notify-smtp-from").value = config.smtp_from;
    if (config.smtp_to) document.getElementById("notify-smtp-to").value = config.smtp_to;
  } catch {
    notifyStatus.textContent = "";
  }
}

notifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideNotifyError();
  const submitBtn = notifyForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  const payload = {
    webhook_url: document.getElementById("notify-webhook-url").value.trim() || null,
    smtp_host: document.getElementById("notify-smtp-host").value.trim() || null,
    smtp_port: Number(document.getElementById("notify-smtp-port").value) || 587,
    smtp_use_tls: document.getElementById("notify-smtp-tls").checked,
    smtp_username: document.getElementById("notify-smtp-username").value.trim() || null,
    smtp_password: document.getElementById("notify-smtp-password").value || null,
    smtp_from: document.getElementById("notify-smtp-from").value.trim() || null,
    smtp_to: document.getElementById("notify-smtp-to").value.trim() || null,
  };
  try {
    const response = await fetch("/api/notifications/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    document.getElementById("notify-webhook-url").value = "";
    document.getElementById("notify-smtp-password").value = "";
    await refreshNotifyStatus();
  } catch (err) {
    showNotifyError(err.message || "Não foi possível salvar a configuração.");
  } finally {
    submitBtn.disabled = false;
  }
});

notifyTestBtn.addEventListener("click", async () => {
  hideNotifyError();
  notifyTestMessage.textContent = "Enviando...";
  notifyTestBtn.disabled = true;
  try {
    const response = await fetch("/api/notifications/test", { method: "POST" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || `Erro ${response.status}`);
    notifyTestMessage.textContent = `Enviado via: ${body.sent_via.join(", ")}.`;
  } catch (err) {
    notifyTestMessage.textContent = "";
    showNotifyError(err.message || "Não foi possível enviar a notificação de teste.");
  } finally {
    notifyTestBtn.disabled = false;
  }
});

refreshNotifyStatus();

// Agendador de renovação — verifica em segundo plano e também sob demanda
// (botão "Verificar agora" na tela de Renovação).
const schedulerStatusEl = document.getElementById("scheduler-status");
const schedulerCheckNowBtn = document.getElementById("scheduler-check-now-btn");
const schedulerCheckMessage = document.getElementById("scheduler-check-message");

async function refreshSchedulerStatus() {
  try {
    const response = await fetch("/api/scheduler/status");
    if (!response.ok) return;
    const status = await response.json();
    const intervalHours = Math.round(status.check_interval_seconds / 3600);
    schedulerStatusEl.textContent = status.last_check_at
      ? `Última verificação: ${formatDateTime(status.last_check_at)} (a cada ~${intervalHours}h).`
      : `Ainda não verificou desde que o servidor subiu (roda a cada ~${intervalHours}h).`;
  } catch {
    schedulerStatusEl.textContent = "";
  }
}

schedulerCheckNowBtn.addEventListener("click", async () => {
  schedulerCheckNowBtn.disabled = true;
  schedulerCheckMessage.textContent = "Verificando...";
  try {
    const response = await fetch("/api/scheduler/check-now", { method: "POST" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || `Erro ${response.status}`);
    schedulerCheckMessage.textContent = body.results.length
      ? `${body.results.length} certificado(s) processado(s): ${body.results.map((r) => `${r.domain} (${r.action})`).join(", ")}.`
      : "Nenhum certificado entrando na janela de renovação agora.";
    await refreshSchedulerStatus();
    await refreshAcmeCertificates();
    await refreshRenewalHistory();
  } catch (err) {
    schedulerCheckMessage.textContent = err.message || "Não foi possível verificar agora.";
  } finally {
    schedulerCheckNowBtn.disabled = false;
  }
});

refreshSchedulerStatus();

// Fila de renovação com estado visível — histórico persistente (SQLite),
// sobrevive a restart. Mesma tabela mostra emissões manuais (tela Emissão)
// e renovações automáticas (agendador), numa lista só.
const RENEWAL_STATE_LABELS = {
  running: "Em andamento",
  done: "Concluído",
  failed: "Falhou",
};
const RENEWAL_TRIGGER_LABELS = {
  manual: "Manual (tela Emissão)",
  scheduler: "Automático (agendador)",
};
const renewalHistoryBody = document.getElementById("renewal-history-body");
const renewalHistoryEmpty = document.getElementById("renewal-history-empty");

async function refreshRenewalHistory() {
  try {
    const response = await fetch("/api/acme/renewal-history");
    if (!response.ok) return;
    const attempts = await response.json();
    renewalHistoryEmpty.classList.toggle("hidden", attempts.length > 0);
    renewalHistoryBody.innerHTML = attempts
      .map((attempt) => {
        const stateLabel = RENEWAL_STATE_LABELS[attempt.state] || attempt.state;
        const triggerLabel = RENEWAL_TRIGGER_LABELS[attempt.trigger_source] || attempt.trigger_source;
        return `<tr>
          <td>${escapeHtml(attempt.domain)}</td>
          <td>${escapeHtml(attempt.environment)}</td>
          <td>${escapeHtml(attempt.dns_mode || "manual (CSR)")}</td>
          <td>${escapeHtml(triggerLabel)}</td>
          <td>${attempt.attempt_number}</td>
          <td><span class="badge badge-${attempt.state}">${escapeHtml(stateLabel)}</span></td>
          <td>${formatDateTime(attempt.created_at)}</td>
          <td class="note-cell">${escapeHtml(attempt.error || "—")}</td>
        </tr>`;
      })
      .join("");
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

refreshRenewalHistory();

// Scans recentes (Dashboard) — histórico persistente (SQLite), sobrevive a
// restart. Clicar num item reabre o resultado com o mesmo renderizador
// usado pra um scan recém-terminado (finish()).
const SCAN_STATE_LABELS = {
  done: "Concluído",
  partial_timeout: "Parcial (tempo esgotado)",
  failed: "Falhou",
  pending: "Pendente",
  discovering_hosts: "Descobrindo hosts",
  probing_tls: "Testando TLS",
};
const scanHistoryCard = document.getElementById("scan-history-card");
const scanHistoryList = document.getElementById("scan-history-list");

async function loadHistoricalScan(jobId) {
  try {
    const response = await fetch(`/api/scan/${jobId}`);
    if (!response.ok) return;
    const snapshot = await response.json();
    resetUI();
    location.hash = "#inventario";
    finish(snapshot, jobId);
  } catch {
    // silencioso — item continua na lista, dá pra tentar de novo
  }
}

async function refreshScanHistory() {
  try {
    const response = await fetch("/api/scan/history");
    if (!response.ok) return;
    const scans = await response.json();
    scanHistoryCard.classList.toggle("hidden", scans.length === 0);
    scanHistoryList.innerHTML = scans
      .map((scan) => {
        const stateLabel = SCAN_STATE_LABELS[scan.state] || scan.state;
        const counts = scan.hosts_total ? `${scan.hosts_done}/${scan.hosts_total} hosts · ` : "";
        return `<li>
          <button type="button" class="scan-history-item" data-job-id="${escapeHtml(scan.id)}">
            <span class="scan-history-domain">${escapeHtml(scan.domain)}</span>
            <span class="scan-history-meta">${counts}${stateLabel} · ${formatDateTime(scan.created_at)}</span>
          </button>
        </li>`;
      })
      .join("");
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

scanHistoryList.addEventListener("click", (event) => {
  const button = event.target.closest(".scan-history-item");
  if (!button) return;
  loadHistoricalScan(button.dataset.jobId);
});

refreshScanHistory();

// Papéis (Fase 4-5): quatro papéis sem hierarquia entre operador/auditor
// (ver app/auth/store.py). Todo elemento marcado data-requires-role="a,b"
// fica escondido pra quem não estiver num desses papéis — o backend já
// bloqueia a rota correspondente com 403 de qualquer forma (ver
// app/auth/dependencies.py); isso é só a UI não oferecer um controle que a
// pessoa não pode usar.
let currentUserRole = null;

// Reaplicada sempre que conteúdo novo pode ter introduzido elementos
// data-requires-role na página (ex: itens de CSR renderizados depois do
// carregamento inicial) — não é só um toggle de uma vez só.
function applyRoleVisibility() {
  document.querySelectorAll("[data-requires-role]").forEach((el) => {
    const allowedRoles = el.dataset.requiresRole.split(",").map((r) => r.trim());
    el.classList.toggle("hidden", !allowedRoles.includes(currentUserRole));
  });
}

async function refreshCurrentUser() {
  try {
    const response = await fetch("/api/auth/me");
    if (!response.ok) return;
    const me = await response.json();
    currentUserRole = me.role;
    window.__currentUsername = me.username;
    applyRoleVisibility();
    if (currentUserRole === "admin" || currentUserRole === "auditor") {
      refreshUsers();
      refreshApiKeys();
      refreshAuditLog();
    }
  } catch {
    // mantém a UI como está se o fetch falhar
  }
}

// Usuários (admin only) — criar/listar/remover.
const ROLE_LABELS = { admin: "Admin", operador: "Operador", auditor: "Auditor", leitor: "Leitor" };
const usersBody = document.getElementById("users-body");
const usersError = document.getElementById("users-error");
const userCreateForm = document.getElementById("user-create-form");

async function refreshUsers() {
  try {
    const response = await fetch("/api/auth/users");
    if (!response.ok) return;
    const users = await response.json();
    usersBody.innerHTML = users
      .map((user) => {
        const mfaLabel = user.mfa_enabled ? "ativado" : "desligado";
        const isSelf = user.username === (window.__currentUsername || null);
        const deleteBtn = isSelf
          ? ""
          : `<button type="button" class="button-link user-delete-btn" data-requires-role="admin" data-username="${escapeHtml(user.username)}">remover</button>`;
        return `<tr>
          <td>${escapeHtml(user.username)}</td>
          <td>${ROLE_LABELS[user.role] || escapeHtml(user.role)}</td>
          <td>${mfaLabel}</td>
          <td>${deleteBtn}</td>
        </tr>`;
      })
      .join("");
    applyRoleVisibility();
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

userCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  usersError.classList.add("hidden");
  const username = document.getElementById("user-create-username").value.trim();
  const password = document.getElementById("user-create-password").value;
  const role = document.getElementById("user-create-role").value;
  const submitBtn = userCreateForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/auth/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    userCreateForm.reset();
    await refreshUsers();
    await refreshAuditLog();
  } catch (err) {
    usersError.textContent = err.message || "Não foi possível criar o usuário.";
    usersError.classList.remove("hidden");
  } finally {
    submitBtn.disabled = false;
  }
});

usersBody.addEventListener("click", async (event) => {
  const button = event.target.closest(".user-delete-btn");
  if (!button) return;
  const username = button.dataset.username;
  if (!confirm(`Remover o usuário "${username}"?`)) return;
  try {
    const response = await fetch(`/api/auth/users/${encodeURIComponent(username)}`, {
      method: "DELETE",
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    await refreshUsers();
    await refreshAuditLog();
  } catch (err) {
    usersError.textContent = err.message || "Não foi possível remover o usuário.";
    usersError.classList.remove("hidden");
  }
});

// API keys (admin cria/revoga, admin+auditor enxergam) — acesso
// programático via Authorization: Bearer <chave>.
const apiKeysBody = document.getElementById("api-keys-body");
const apiKeysError = document.getElementById("api-keys-error");
const apiKeyCreateForm = document.getElementById("api-key-create-form");
const apiKeyNewValue = document.getElementById("api-key-new-value");
const apiKeyNewValueText = document.getElementById("api-key-new-value-text");

async function refreshApiKeys() {
  try {
    const response = await fetch("/api/auth/api-keys");
    if (!response.ok) return;
    const keys = await response.json();
    apiKeysBody.innerHTML = keys
      .map(
        (key) => `<tr>
          <td>${escapeHtml(key.name)}</td>
          <td>${ROLE_LABELS[key.role] || escapeHtml(key.role)}</td>
          <td>${escapeHtml(key.created_by || "—")}</td>
          <td>${key.last_used_at ? formatDateTime(key.last_used_at) : "nunca usada"}</td>
          <td><button type="button" class="button-link api-key-revoke-btn" data-requires-role="admin" data-key-id="${escapeHtml(key.id)}">revogar</button></td>
        </tr>`
      )
      .join("");
    applyRoleVisibility();
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

apiKeyCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  apiKeysError.classList.add("hidden");
  apiKeyNewValue.classList.add("hidden");
  const name = document.getElementById("api-key-create-name").value.trim();
  const role = document.getElementById("api-key-create-role").value;
  const submitBtn = apiKeyCreateForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/auth/api-keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, role }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    const body = await response.json();
    apiKeyNewValueText.textContent = body.key;
    apiKeyNewValue.classList.remove("hidden");
    apiKeyCreateForm.reset();
    await refreshApiKeys();
  } catch (err) {
    apiKeysError.textContent = err.message || "Não foi possível gerar a chave.";
    apiKeysError.classList.remove("hidden");
  } finally {
    submitBtn.disabled = false;
  }
});

apiKeysBody.addEventListener("click", async (event) => {
  const button = event.target.closest(".api-key-revoke-btn");
  if (!button) return;
  if (!confirm("Revogar essa chave? Qualquer integração usando ela para de funcionar.")) return;
  try {
    const response = await fetch(`/api/auth/api-keys/${encodeURIComponent(button.dataset.keyId)}`, {
      method: "DELETE",
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    await refreshApiKeys();
  } catch (err) {
    apiKeysError.textContent = err.message || "Não foi possível revogar a chave.";
    apiKeysError.classList.remove("hidden");
  }
});

// Log de auditoria (admin+auditor enxergam, ninguém escreve nele por essa
// tela — é append-only) — inclui verificação de integridade da cadeia de
// hashes (ver app/audit/log.py).
const auditLogBody = document.getElementById("audit-log-body");
const auditLogEmpty = document.getElementById("audit-log-empty");
const auditLogVerifyBtn = document.getElementById("audit-log-verify-btn");
const auditLogVerifyMessage = document.getElementById("audit-log-verify-message");

async function refreshAuditLog() {
  try {
    const response = await fetch("/api/audit-log");
    if (!response.ok) return;
    const entries = await response.json();
    auditLogEmpty.classList.toggle("hidden", entries.length > 0);
    auditLogBody.innerHTML = entries
      .map(
        (entry) => `<tr>
          <td>${formatDateTime(entry.created_at)}</td>
          <td>${escapeHtml(entry.username || "sistema")}</td>
          <td>${escapeHtml(entry.action)}</td>
          <td class="note-cell">${escapeHtml(entry.detail || "—")}</td>
        </tr>`
      )
      .join("");
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

auditLogVerifyBtn.addEventListener("click", async () => {
  auditLogVerifyBtn.disabled = true;
  auditLogVerifyMessage.textContent = "Verificando...";
  try {
    const response = await fetch("/api/audit-log/verify");
    const body = await response.json();
    auditLogVerifyMessage.textContent = body.ok
      ? "Cadeia íntegra — nenhuma linha foi adulterada."
      : `Cadeia quebrada a partir da linha ${body.broken_at_id} — algo foi alterado fora da API.`;
  } catch {
    auditLogVerifyMessage.textContent = "Não foi possível verificar agora.";
  } finally {
    auditLogVerifyBtn.disabled = false;
  }
});

refreshCurrentUser();

// Rota inicial — por último, depois que toda função/const que uma tela
// pode precisar (ex: refreshSecurityStatus) já foi definida.
routeFromHash();

