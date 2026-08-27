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

// Radar hand-rolled em SVG (sem lib de gráfico) — cada eixo é um risco
// 0-100 (0 = centro = tranquilo, 100 = borda = urgente). Coordenadas vão
// direto como atributos SVG (cx/cy/points), não style="" inline, então não
// precisa da CSSOM trick que o barChart usa pro CSP.
function radarChart(container, axes) {
  if (axes.length < 3) {
    container.innerHTML =
      '<p class="empty">Precisa de pelo menos 3 autoridades certificadoras diferentes pra desenhar o radar.</p>';
    return;
  }
  const size = 280;
  const center = size / 2;
  const maxRadius = center - 46;
  const angleStep = (2 * Math.PI) / axes.length;
  const pointFor = (index, fraction) => {
    const angle = -Math.PI / 2 + index * angleStep;
    return [center + Math.cos(angle) * maxRadius * fraction, center + Math.sin(angle) * maxRadius * fraction];
  };

  const rings = [0.25, 0.5, 0.75, 1]
    .map((fraction) => {
      const points = axes.map((_, i) => pointFor(i, fraction).join(",")).join(" ");
      return `<polygon points="${points}" class="radar-ring" />`;
    })
    .join("");

  const axisLines = axes
    .map((_, i) => {
      const [x, y] = pointFor(i, 1);
      return `<line x1="${center}" y1="${center}" x2="${x}" y2="${y}" class="radar-axis" />`;
    })
    .join("");

  const dataPoints = axes.map((axis, i) => pointFor(i, Math.max(0, Math.min(100, axis.value)) / 100));
  const dataPolygon = dataPoints.map((p) => p.join(",")).join(" ");

  const dots = axes
    .map((axis, i) => {
      const [x, y] = dataPoints[i];
      return `<circle cx="${x}" cy="${y}" r="4" class="radar-dot radar-dot-${axis.risk}" />`;
    })
    .join("");

  const labels = axes
    .map((axis, i) => {
      const [x, y] = pointFor(i, 1.2);
      const anchor = Math.abs(x - center) < 4 ? "middle" : x > center ? "start" : "end";
      return `<text x="${x}" y="${y}" text-anchor="${anchor}" class="radar-label">${escapeHtml(axis.label)}</text>`;
    })
    .join("");

  container.innerHTML = `<svg viewBox="0 0 ${size} ${size}" class="radar-svg" role="img" aria-label="Radar de risco por autoridade certificadora">
    ${rings}
    ${axisLines}
    <polygon points="${dataPolygon}" class="radar-fill" />
    ${dots}
    ${labels}
  </svg>`;
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
  // Achado numa auditoria de robustez: div.innerHTML sozinho escapa & < >
  // (o que basta pra contexto de texto entre tags, os únicos usos atuais)
  // mas não " nem ' — um helper chamado "escapeHtml" que não escapa aspas
  // vira XSS real no dia em que alguém usar o valor dentro de um atributo
  // (href=, title=), então escapa também por completude do contrato.
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML.replaceAll('"', "&quot;").replaceAll("'", "&#39;");
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
  const enumerateSubdomains = document.getElementById("enumerate-subdomains").checked;

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domain,
        manual_hosts: manualHosts,
        consent,
        enumerate_subdomains: enumerateSubdomains,
      }),
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
  if (event.key !== "Escape") return;
  if (!detailModal.classList.contains("hidden")) closeDetailModal();
  if (!certDetailModal.classList.contains("hidden")) closeCertDetailModal();
});

// Navegação por telas — cada função vive na sua própria tela (Dashboard /
// Inventário / Emissão / Renovação / Configurações), roteada pelo hash da
// URL. Isso dá link direto e botão voltar/avançar do navegador de graça,
// sem precisar de framework nenhum.
const SCREEN_NAMES = [
  "dashboard",
  "inventario",
  "emissao",
  "certificados",
  "renovacao",
  "cadastros",
  "autoridades",
  "configuracoes",
];
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
  closeSidebar();
}

function routeFromHash() {
  showScreen((location.hash || "#dashboard").slice(1));
}

window.addEventListener("hashchange", routeFromHash);

// Sidebar em drawer no mobile (≤768px) — no desktop/tablet ela já fica
// sempre visível (ver breakpoints em style.css), esses controles só têm
// efeito visual abaixo desse breakpoint.
const sidebar = document.getElementById("sidebar");
const sidebarBackdrop = document.getElementById("sidebar-backdrop");
const sidebarToggleBtn = document.getElementById("sidebar-toggle");

function openSidebar() {
  sidebar.classList.add("open");
  sidebarBackdrop.classList.add("visible");
}

function closeSidebar() {
  sidebar.classList.remove("open");
  sidebarBackdrop.classList.remove("visible");
}

sidebarToggleBtn.addEventListener("click", () => {
  sidebar.classList.contains("open") ? closeSidebar() : openSidebar();
});
sidebarBackdrop.addEventListener("click", closeSidebar);
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
const acmeDnsStatus = document.getElementById("acme-dns-status");
const acmeDnsFormDetails = document.getElementById("acme-dns-form-details");
const acmeDnsForm = document.getElementById("acme-dns-form");
const acmeCa = document.getElementById("acme-ca");
const acmeEnvironment = document.getElementById("acme-environment");
const acmeEnvironmentHint = document.getElementById("acme-environment-hint");
const acmeZerosslStatus = document.getElementById("acme-zerossl-status");
const acmeZerosslFormDetails = document.getElementById("acme-zerossl-form-details");
const acmeZerosslForm = document.getElementById("acme-zerossl-form");
const acmeAzureStatus = document.getElementById("acme-azure-status");
const acmeAzureFormDetails = document.getElementById("acme-azure-form-details");
const acmeAzureForm = document.getElementById("acme-azure-form");
const selfdnsStatus = document.getElementById("selfdns-status");
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
const certsList = document.getElementById("certs-list");
const certsSearch = document.getElementById("certs-search");
const certsFilterCa = document.getElementById("certs-filter-ca");
const certsFilterMode = document.getElementById("certs-filter-mode");
const certsFilterStatus = document.getElementById("certs-filter-status");
const managedOverviewCard = document.getElementById("managed-overview-card");
const chartManagedCa = document.getElementById("chart-managed-ca");
const chartManagedEnvironment = document.getElementById("chart-managed-environment");
const chartManagedKeyalg = document.getElementById("chart-managed-keyalg");
const chartManagedOrg = document.getElementById("chart-managed-org");
const riskRadarCard = document.getElementById("risk-radar-card");
const chartRiskRadar = document.getElementById("chart-risk-radar");
const riskRadarLegend = document.getElementById("risk-radar-legend");

const ACME_TERMINAL_STATES = new Set(["done", "failed"]);
let currentAcmeJobId = null;

// ZeroSSL não tem staging separado — todo certificado emitido por ela sai
// real, mesmo com "Staging" selecionado (o campo Ambiente vira só
// bookkeeping/exibição nesse caso, não afeta rate limit real). Os
// painéis de configurar credencial (Cloudflare/ZeroSSL/Azure DNS) moraram
// aqui antes; agora vivem na tela Autoridades (Fase 8), não precisam
// mais aparecer/sumir junto com o modo escolhido aqui.
acmeCa.addEventListener("change", () => {
  const isZerossl = acmeCa.value === "zerossl";
  acmeEnvironmentHint.textContent = isZerossl
    ? "ZeroSSL não tem ambiente de teste separado — o certificado sai real independente da opção acima."
    : "";
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

    if (status.zerossl_configured) {
      acmeZerosslStatus.textContent = "Credenciais EAB da ZeroSSL configuradas.";
      acmeZerosslFormDetails.open = false;
    } else {
      acmeZerosslStatus.textContent = "Nenhuma credencial EAB da ZeroSSL configurada ainda.";
      acmeZerosslFormDetails.open = true;
    }

    if (status.azure_dns_configured) {
      acmeAzureStatus.textContent = `Azure DNS configurado (zona: ${status.azure_dns_zone}).`;
      acmeAzureFormDetails.open = false;
    } else {
      acmeAzureStatus.textContent = "Nenhum service principal do Azure DNS configurado ainda.";
      acmeAzureFormDetails.open = true;
    }

    if (selfdnsStatus) {
      selfdnsStatus.textContent = status.selfdns_enabled
        ? `Ligado — zona própria: ${status.selfdns_zone}. Selecione "CNAME manual, sem credencial" na Emissão.`
        : "Desligado nesta instância — precisa ser habilitado no deploy (variáveis de ambiente).";
    }
  } catch {
    acmeDnsStatus.textContent = "";
  }
}

const AUTO_RENEWABLE_MODES = new Set([
  "cloudflare",
  "azure_dns",
  "cname_delegation",
  "azure_cname_delegation",
  "self_hosted_dns",
]);
const CA_LABELS = { zerossl: "ZeroSSL", letsencrypt: "Let's Encrypt" };
const ENVIRONMENT_LABELS = {
  production: "Produção (ACME)",
  staging: "Staging (ACME)",
  imported: "Importado",
  manual: "CSR manual",
};
let allCertificates = [];

// Status derivado (não vem pronto da API): "monitorado" é sobre não ter
// chave, os outros três são sobre prazo de expiração — mesmo corte de
// 30 dias usado nos cards de urgência do Dashboard.
function certStatus(cert) {
  if (!cert.has_private_key) return "monitored";
  if (!cert.not_after) return "valid";
  const daysLeft = (new Date(cert.not_after) - new Date()) / (1000 * 60 * 60 * 24);
  if (daysLeft < 0) return "expired";
  if (daysLeft < 30) return "expiring";
  return "valid";
}

const CERT_STATUS_LABELS = {
  valid: "Válido",
  expiring: "Expirando",
  expired: "Expirado",
  monitored: "Monitorado",
};
const CERT_STATUS_GLYPHS = { valid: "✓", expiring: "◆", expired: "✕", monitored: "•" };
const DNS_MODE_LABELS = {
  cloudflare: "Cloudflare (automático)",
  azure_dns: "Azure DNS (automático)",
  cname_delegation: "Delegação CNAME via Cloudflare (automático)",
  azure_cname_delegation: "Delegação CNAME via Azure DNS (automático)",
  self_hosted_dns: "CNAME manual, sem credencial (automático)",
  manual: "Manual — TXT (avisa, não renova sozinho)",
};

// Vocabulário próprio (valid/expiring/expired/monitored), separado do
// badgeFor() do Inventário (expired/critical/warning/ok/...) — são eixos
// de status diferentes, forçar um no outro só confundiria os dois.
function certBadge(status) {
  const label = CERT_STATUS_LABELS[status] || status;
  const glyph = CERT_STATUS_GLYPHS[status] || "";
  return `<span class="badge badge-${status}"><span aria-hidden="true">${glyph}</span> ${label}</span>`;
}

function renderCertificateRow(cert) {
  const notAfter = formatDateTime(cert.not_after);
  const renewalNote = AUTO_RENEWABLE_MODES.has(cert.dns_mode)
    ? "renovação automática"
    : "renovação manual";
  const caLabel = CA_LABELS[cert.ca] || "Manual/importado";
  const contextParts = [
    cert.organization_id ? catalogNameCache.organization[cert.organization_id] : null,
    cert.system_id ? catalogNameCache.system[cert.system_id] : null,
    cert.project_id ? catalogNameCache.project[cert.project_id] : null,
  ].filter(Boolean);
  const contextLine = contextParts.length
    ? `<div class="cert-card-context hint">${escapeHtml(contextParts.join(" · "))}</div>`
    : "";
  return `<div class="cert-card">
    <div class="cert-card-head">
      <div class="cert-card-domain">
        ${certBadge(certStatus(cert))}
        <strong title="${escapeHtml(cert.domain)}">${escapeHtml(cert.domain)}</strong>
      </div>
      <button type="button" class="button-link cert-detail-btn" data-cert-id="${encodeURIComponent(cert.id)}">Detalhes</button>
    </div>
    <div class="cert-card-facts">
      <span><strong>${caLabel}</strong></span>
      <span>${renewalNote}</span>
      <span>expira em ${notAfter}</span>
    </div>
    ${contextLine}
  </div>`;
}

const certDetailModal = document.getElementById("cert-detail-modal");

let currentCertDetailId = null;

function openCertDetailModal(cert) {
  currentCertDetailId = cert.id;
  document.getElementById("cert-detail-delete-error").classList.add("hidden");
  const status = certStatus(cert);
  const daysLeft = cert.not_after
    ? Math.round((new Date(cert.not_after) - new Date()) / (1000 * 60 * 60 * 24))
    : null;

  document.getElementById("cert-detail-domain").textContent = cert.domain;
  document.getElementById("cert-detail-sans").textContent =
    cert.sans && cert.sans.length > 1 ? `SANs: ${cert.sans.join(", ")}` : "";
  document.getElementById("cert-detail-status").innerHTML = certBadge(status);
  document.getElementById("cert-detail-ca").textContent = CA_LABELS[cert.ca] || "Manual/importado";
  document.getElementById("cert-detail-issuer").textContent = cert.issuer_cn || "—";
  document.getElementById("cert-detail-environment").textContent =
    ENVIRONMENT_LABELS[cert.environment] || cert.environment;
  document.getElementById("cert-detail-mode").textContent = cert.dns_mode
    ? DNS_MODE_LABELS[cert.dns_mode] || cert.dns_mode
    : "— (CSR manual/importado, não renova sozinho)";
  document.getElementById("cert-detail-privkey").textContent = cert.has_private_key
    ? "Sim"
    : "Não (só monitorado)";
  document.getElementById("cert-detail-key").textContent = cert.key_algorithm
    ? `${cert.key_algorithm} ${cert.key_size ?? "?"}`
    : "—";
  document.getElementById("cert-detail-issued").textContent = formatDateTime(cert.issued_at);
  document.getElementById("cert-detail-not-after").textContent = formatDateTime(cert.not_after);
  document.getElementById("cert-detail-days").textContent = daysLeft === null ? "—" : daysLeft;
  document.getElementById("cert-detail-org").textContent = cert.organization_id
    ? catalogNameCache.organization[cert.organization_id] || "—"
    : "—";
  document.getElementById("cert-detail-system").textContent = cert.system_id
    ? catalogNameCache.system[cert.system_id] || "—"
    : "—";
  document.getElementById("cert-detail-project").textContent = cert.project_id
    ? catalogNameCache.project[cert.project_id] || "—"
    : "—";
  document.getElementById("cert-detail-serial").textContent = cert.serial_number || "—";
  document.getElementById("cert-detail-fingerprint").textContent = cert.sha256_fingerprint || "—";

  document.getElementById("cert-detail-download-cert").href =
    `/api/acme/certificates/${encodeURIComponent(cert.id)}/fullchain.pem`;
  // Duas condições independentes controlam esse link — papel (gerido por
  // applyRoleVisibility via .hidden) e ter chave privada pra baixar. Não dá
  // pra usar a mesma classe .hidden pras duas: applyRoleVisibility roda
  // logo abaixo e reaplicaria .hidden só com base no papel, apagando esse
  // toggle. Classe separada evita a briga.
  const downloadKey = document.getElementById("cert-detail-download-key");
  downloadKey.classList.toggle("no-private-key", !cert.has_private_key);
  if (cert.has_private_key) {
    downloadKey.href = `/api/acme/certificates/${encodeURIComponent(cert.id)}/privkey.pem`;
  }

  certDetailModal.classList.remove("hidden");
  applyRoleVisibility();
}

function closeCertDetailModal() {
  certDetailModal.classList.add("hidden");
}

document.getElementById("cert-detail-modal-close").addEventListener("click", closeCertDetailModal);
certDetailModal.addEventListener("click", (event) => {
  if (event.target === certDetailModal) closeCertDetailModal();
});

document.getElementById("cert-detail-delete-btn").addEventListener("click", async () => {
  if (!currentCertDetailId) return;
  const cert = allCertificates.find((c) => c.id === currentCertDetailId);
  const domainLabel = cert ? cert.domain : "este certificado";
  if (!confirm(`Excluir o certificado de "${domainLabel}"? Isso não pode ser desfeito.`)) return;

  const errorEl = document.getElementById("cert-detail-delete-error");
  errorEl.classList.add("hidden");
  try {
    const response = await fetch(`/api/acme/certificates/${encodeURIComponent(currentCertDetailId)}`, {
      method: "DELETE",
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || `Erro ${response.status}`);
    }
    closeCertDetailModal();
    await refreshAcmeCertificates();
  } catch (err) {
    errorEl.textContent = err.message || "Falha ao excluir o certificado.";
    errorEl.classList.remove("hidden");
  }
});

function applyCertificateFilters() {
  if (!certsList) return;
  const search = certsSearch.value.trim().toLowerCase();
  const caFilter = certsFilterCa.value;
  const modeFilter = certsFilterMode.value;
  const statusFilter = certsFilterStatus.value;

  const filtered = allCertificates.filter((cert) => {
    if (search && !cert.domain.toLowerCase().includes(search)) return false;
    if (caFilter === "none" && cert.ca) return false;
    if (caFilter && caFilter !== "none" && cert.ca !== caFilter) return false;
    if (modeFilter === "none" && cert.dns_mode) return false;
    if (modeFilter && modeFilter !== "none" && cert.dns_mode !== modeFilter) return false;
    if (statusFilter && certStatus(cert) !== statusFilter) return false;
    return true;
  });

  if (!allCertificates.length) {
    certsList.classList.remove("certs-cards");
    certsList.classList.add("hint");
    certsList.innerHTML = "Nenhum certificado emitido ainda.";
  } else if (!filtered.length) {
    certsList.classList.remove("certs-cards");
    certsList.classList.add("hint");
    certsList.innerHTML = "Nenhum certificado bate com o filtro atual.";
  } else {
    certsList.classList.remove("hint");
    certsList.classList.add("certs-cards");
    certsList.innerHTML = filtered.map(renderCertificateRow).join("");
    applyRoleVisibility();
  }
}

[certsSearch, certsFilterCa, certsFilterMode, certsFilterStatus].forEach((el) => {
  if (!el) return;
  el.addEventListener(el.tagName === "SELECT" ? "change" : "input", applyCertificateFilters);
});

certsList.addEventListener("click", (event) => {
  const btn = event.target.closest(".cert-detail-btn");
  if (!btn) return;
  const certId = decodeURIComponent(btn.dataset.certId);
  const cert = allCertificates.find((c) => c.id === certId);
  if (cert) openCertDetailModal(cert);
});

function sortedCounts(map) {
  return [...map.entries()].sort((a, b) => b[1] - a[1]);
}

// Painel do Dashboard sobre os certificados GERENCIADOS (emitidos/CSR/
// importados) — eixo diferente do painel de descoberta (chart-issuers/
// chart-expiry, que é sobre o que o scan achou na internet). Roda toda
// vez que a lista de certificados ou os cadastros mudam, já que o
// cruzamento por organização depende do catalogNameCache.
function renderManagedCertsOverview() {
  if (!managedOverviewCard) return;
  if (!allCertificates.length) {
    managedOverviewCard.classList.add("hidden");
    return;
  }
  managedOverviewCard.classList.remove("hidden");

  const caCounts = new Map();
  const envCounts = new Map();
  const keyCounts = new Map();
  const orgCounts = new Map();
  allCertificates.forEach((cert) => {
    const caLabel = CA_LABELS[cert.ca] || "Manual/importado";
    caCounts.set(caLabel, (caCounts.get(caLabel) || 0) + 1);

    const envLabel = ENVIRONMENT_LABELS[cert.environment] || cert.environment;
    envCounts.set(envLabel, (envCounts.get(envLabel) || 0) + 1);

    const keyLabel = cert.key_algorithm ? `${cert.key_algorithm} ${cert.key_size ?? "?"}` : "Desconhecido";
    keyCounts.set(keyLabel, (keyCounts.get(keyLabel) || 0) + 1);

    const orgLabel = cert.organization_id
      ? catalogNameCache.organization[cert.organization_id] || "Organização removida"
      : "Sem organização";
    orgCounts.set(orgLabel, (orgCounts.get(orgLabel) || 0) + 1);
  });

  barChart(chartManagedCa, sortedCounts(caCounts));
  barChart(chartManagedEnvironment, sortedCounts(envCounts));
  barChart(chartManagedKeyalg, sortedCounts(keyCounts));
  barChart(chartManagedOrg, sortedCounts(orgCounts).slice(0, 8));
}

// 0 dias (ou já expirado) = risco 100 (borda do radar); 90+ dias = risco 0
// (centro). 90 dias é a janela de validade típica da Let's Encrypt — não é
// um número arbitrário, é "toda a vida útil normal de um certificado".
function riskScoreFromDays(days) {
  const capped = Math.max(0, Math.min(90, days));
  return Math.round((1 - capped / 90) * 100);
}

function riskBucket(days) {
  if (days < 0) return "expired";
  if (days < 7) return "critical";
  if (days < 30) return "warning";
  return "ok";
}

// Um eixo por CA — pro certificado MAIS urgente daquela CA (não a média,
// que esconderia um certificado prestes a vencer atrás de vários saudáveis).
function computeCaRiskAxes() {
  const worstDaysByCa = new Map();
  allCertificates.forEach((cert) => {
    if (!cert.not_after) return;
    const label = CA_LABELS[cert.ca] || "Manual/importado";
    const days = (new Date(cert.not_after) - new Date()) / (1000 * 60 * 60 * 24);
    if (!worstDaysByCa.has(label) || days < worstDaysByCa.get(label)) {
      worstDaysByCa.set(label, days);
    }
  });
  return [...worstDaysByCa.entries()].map(([label, worstDays]) => ({
    label,
    worstDays: Math.round(worstDays),
    value: riskScoreFromDays(worstDays),
    risk: riskBucket(worstDays),
  }));
}

function renderRiskRadar() {
  if (!riskRadarCard) return;
  const axes = computeCaRiskAxes();
  if (axes.length < 3) {
    riskRadarCard.classList.add("hidden");
    return;
  }
  riskRadarCard.classList.remove("hidden");
  radarChart(chartRiskRadar, axes);
  riskRadarLegend.innerHTML = axes
    .map((axis) => {
      const daysText = axis.worstDays < 0 ? "expirado" : `${axis.worstDays} dias até o próximo vencimento`;
      return `<li><span class="radar-dot-inline radar-dot-${axis.risk}"></span>${escapeHtml(axis.label)}: ${daysText}</li>`;
    })
    .join("");
}

async function refreshAcmeCertificates() {
  try {
    const response = await fetch("/api/acme/certificates");
    if (!response.ok) return;
    allCertificates = await response.json();
    applyCertificateFilters();
    renderManagedCertsOverview();
    renderRiskRadar();
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

acmeZerosslForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideAcmeError();
  const eabKid = document.getElementById("zerossl-eab-kid").value.trim();
  const eabHmacKey = document.getElementById("zerossl-eab-hmac").value.trim();
  const submitBtn = acmeZerosslForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/acme/ca-credentials/zerossl", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ eab_kid: eabKid, eab_hmac_key: eabHmacKey }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    acmeZerosslForm.reset();
    await refreshAcmeStatus();
  } catch (err) {
    showAcmeError(err.message || "Não foi possível salvar as credenciais da ZeroSSL.");
  } finally {
    submitBtn.disabled = false;
  }
});

acmeAzureForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  hideAcmeError();
  const payload = {
    tenant_id: document.getElementById("azure-tenant-id").value.trim(),
    client_id: document.getElementById("azure-client-id").value.trim(),
    client_secret: document.getElementById("azure-client-secret").value.trim(),
    subscription_id: document.getElementById("azure-subscription-id").value.trim(),
    resource_group: document.getElementById("azure-resource-group").value.trim(),
    zone_name: document.getElementById("azure-zone-name").value.trim(),
  };
  const submitBtn = acmeAzureForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/acme/dns-credentials/azure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    acmeAzureForm.reset();
    await refreshAcmeStatus();
  } catch (err) {
    showAcmeError(err.message || "Não foi possível salvar as credenciais do Azure DNS.");
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
  const ca = acmeCa.value;
  const organizationId = document.getElementById("acme-organization").value || null;
  const systemId = document.getElementById("acme-system").value || null;
  const projectId = document.getElementById("acme-project").value || null;

  try {
    const response = await fetch("/api/acme/renew", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domain,
        environment,
        dns_mode: dnsMode,
        ca,
        organization_id: organizationId,
        system_id: systemId,
        project_id: projectId,
      }),
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
            <label>Motivo (opcional — fica no log de auditoria)</label>
            <input type="text" class="csr-reason-input" placeholder="Por que esse certificado foi pedido" />
            <label>Número do chamado (opcional)</label>
            <input type="text" class="csr-ticket-input" />
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
  const csrOrganizationId = document.getElementById("csr-organization").value || null;
  const csrSystemId = document.getElementById("csr-system").value || null;
  const csrProjectId = document.getElementById("csr-project").value || null;
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/csr", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domains,
        organization_id: csrOrganizationId,
        system_id: csrSystemId,
        project_id: csrProjectId,
      }),
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

// Importação de certificado existente — converge no mesmo acme_store dos
// emitidos via ACME/CSR, então basta reusar refreshAcmeCertificates() pra
// ele aparecer em Renovação depois de importado.
const importForm = document.getElementById("import-form");
const importError = document.getElementById("import-error");
const importSuccess = document.getElementById("import-success");
const importCertFile = document.getElementById("import-cert-file");

importCertFile.addEventListener("change", () => {
  const file = importCertFile.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    document.getElementById("import-cert-pem").value = String(reader.result || "");
  };
  reader.readAsText(file);
});

importForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  importError.classList.add("hidden");
  importSuccess.classList.add("hidden");
  const certificatePem = document.getElementById("import-cert-pem").value.trim();
  const privateKeyPem = document.getElementById("import-key-pem").value.trim();
  const importOrganizationId = document.getElementById("import-organization").value || null;
  const importSystemId = document.getElementById("import-system").value || null;
  const importProjectId = document.getElementById("import-project").value || null;
  const submitBtn = importForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/import/certificate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        certificate_pem: certificatePem,
        private_key_pem: privateKeyPem || null,
        organization_id: importOrganizationId,
        system_id: importSystemId,
        project_id: importProjectId,
      }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    const body = await response.json();
    importForm.reset();
    importSuccess.textContent = body.has_private_key
      ? `Certificado de ${body.domain} importado — aparece em Renovação.`
      : `Certificado de ${body.domain} importado como só monitorado (sem chave privada) — aparece em Renovação.`;
    importSuccess.classList.remove("hidden");
    await refreshAcmeCertificates();
  } catch (err) {
    importError.textContent = err.message || "Não foi possível importar o certificado.";
    importError.classList.remove("hidden");
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
  const reason = form.querySelector(".csr-reason-input").value.trim();
  const ticketNumber = form.querySelector(".csr-ticket-input").value.trim();
  const submitBtn = form.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  messageEl.textContent = "";
  try {
    const response = await fetch(`/api/csr/${encodeURIComponent(id)}/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        certificate_pem: certPem,
        reason,
        ticket_number: ticketNumber,
      }),
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
          <td data-label="Domínio">${escapeHtml(attempt.domain)}</td>
          <td data-label="Ambiente">${escapeHtml(attempt.environment)}</td>
          <td data-label="Modo">${escapeHtml(attempt.dns_mode || "manual (CSR)")}</td>
          <td data-label="Gatilho">${escapeHtml(triggerLabel)}</td>
          <td data-label="Tentativa">${attempt.attempt_number}</td>
          <td data-label="Estado"><span class="badge badge-${attempt.state}">${escapeHtml(stateLabel)}</span></td>
          <td data-label="Quando">${formatDateTime(attempt.created_at)}</td>
          <td data-label="Erro" class="note-cell">${escapeHtml(attempt.error || "—")}</td>
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

// Achado numa varredura de qualidade: ao logar, Dashboard e Inventário
// ficavam vazios ("Nenhum dado ainda") mesmo com um scan recente sentado
// bem ali em "Scans recentes" — só populavam depois de clicar nele à mão.
// Silenciosamente carrega o mais recente (se existir) no boot da página,
// sem forçar navegação pra #inventario (diferente de loadHistoricalScan,
// que a pessoa aciona de propósito) — só preenche o estado, cada tela
// mostra o que já teria pra mostrar quando a pessoa chegar nela.
async function autoLoadMostRecentScan() {
  try {
    const historyResponse = await fetch("/api/scan/history");
    if (!historyResponse.ok) return;
    const scans = await historyResponse.json();
    if (!scans.length) return;
    const snapshotResponse = await fetch(`/api/scan/${scans[0].id}`);
    if (!snapshotResponse.ok) return;
    const snapshot = await snapshotResponse.json();
    finish(snapshot, scans[0].id);
  } catch {
    // silencioso — pior caso é continuar com "nenhum dado ainda" até a
    // pessoa rodar ou reabrir um scan manualmente
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
autoLoadMostRecentScan();

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

const currentUserBadge = document.getElementById("current-user-badge");

async function refreshCurrentUser() {
  try {
    const response = await fetch("/api/auth/me");
    if (!response.ok) return;
    const me = await response.json();
    currentUserRole = me.role;
    window.__currentUsername = me.username;
    currentUserBadge.innerHTML = `${escapeHtml(me.display_name || me.username)} · <strong>${ROLE_LABELS[me.role] || escapeHtml(me.role)}</strong>`;
    currentUserBadge.classList.remove("hidden");
    applyRoleVisibility();
    if (currentUserRole === "admin" || currentUserRole === "auditor") {
      refreshUsers();
      refreshApiKeys();
      refreshAuditLog();
    }
    if (currentUserRole === "admin") {
      refreshSamlStatus();
    }
  } catch {
    // mantém a UI como está se o fetch falhar
  }
}

// Usuários (admin only) — criar/listar/trocar papel/remover.
const ROLE_LABELS = { admin: "Admin", operador: "Operador", auditor: "Auditor", leitor: "Leitor" };
const ROLES_ORDERED = ["leitor", "operador", "auditor", "admin"];
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
        // Só admin pode trocar papel (auditor enxerga a lista, mas não age
        // em nada — ver o texto no topo do card "Usuários").
        const roleCell =
          currentUserRole === "admin"
            ? `<select class="user-role-select" data-username="${escapeHtml(user.username)}">
                ${ROLES_ORDERED.map(
                  (role) =>
                    `<option value="${role}"${role === user.role ? " selected" : ""}>${ROLE_LABELS[role]}</option>`
                ).join("")}
              </select>`
            : ROLE_LABELS[user.role] || escapeHtml(user.role);
        const usernameCell = user.display_name
          ? `${escapeHtml(user.username)} <span class="hint">(${escapeHtml(user.display_name)})</span>`
          : escapeHtml(user.username);
        return `<tr>
          <td data-label="Usuário">${usernameCell}</td>
          <td data-label="Papel">${roleCell}</td>
          <td data-label="MFA">${mfaLabel}</td>
          <td data-label="">${deleteBtn}</td>
        </tr>`;
      })
      .join("");
    applyRoleVisibility();
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

usersBody.addEventListener("change", async (event) => {
  const select = event.target.closest(".user-role-select");
  if (!select) return;
  usersError.classList.add("hidden");
  const username = select.dataset.username;
  const role = select.value;
  select.disabled = true;
  try {
    const response = await fetch(`/api/auth/users/${encodeURIComponent(username)}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    await refreshAuditLog();
  } catch (err) {
    usersError.textContent = err.message || "Não foi possível trocar o papel.";
    usersError.classList.remove("hidden");
  } finally {
    // Sempre atualiza pra refletir o estado real — reverte o <select> se a
    // troca falhou, confirma se deu certo.
    await refreshUsers();
  }
});

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
          <td data-label="Nome">${escapeHtml(key.name)}</td>
          <td data-label="Papel">${ROLE_LABELS[key.role] || escapeHtml(key.role)}</td>
          <td data-label="Criada por">${escapeHtml(key.created_by || "—")}</td>
          <td data-label="Último uso">${key.last_used_at ? formatDateTime(key.last_used_at) : "nunca usada"}</td>
          <td data-label=""><button type="button" class="button-link api-key-revoke-btn" data-requires-role="admin" data-key-id="${escapeHtml(key.id)}">revogar</button></td>
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

// SSO via SAML (admin only) — mostra os valores do SP pra cadastrar no
// IdP e um formulário pra salvar os valores do IdP de volta.
const samlStatus = document.getElementById("saml-status");
const samlSpEntityId = document.getElementById("saml-sp-entity-id");
const samlAcsUrl = document.getElementById("saml-acs-url");
const samlConfigFormDetails = document.getElementById("saml-config-form-details");
const samlConfigForm = document.getElementById("saml-config-form");
const samlError = document.getElementById("saml-error");

async function refreshSamlStatus() {
  try {
    const response = await fetch("/api/auth/saml/status");
    if (!response.ok) return;
    const status = await response.json();
    samlSpEntityId.textContent = status.sp_entity_id;
    samlAcsUrl.textContent = status.acs_url;
    if (status.configured) {
      samlStatus.textContent = "SSO configurado.";
      samlConfigFormDetails.open = false;
    } else {
      samlStatus.textContent = "Nenhum IdP configurado ainda — login continua só por usuário/senha.";
      samlConfigFormDetails.open = true;
    }
  } catch {
    // mantém o status anterior se o fetch falhar
  }
}

samlConfigForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  samlError.classList.add("hidden");
  const payload = {
    entity_id: document.getElementById("saml-entity-id").value.trim(),
    sso_url: document.getElementById("saml-sso-url").value.trim(),
    x509_cert: document.getElementById("saml-x509-cert").value.trim(),
  };
  const submitBtn = samlConfigForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch("/api/auth/saml/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    samlConfigForm.reset();
    await refreshSamlStatus();
  } catch (err) {
    samlError.textContent = err.message || "Não foi possível salvar a configuração do IdP.";
    samlError.classList.remove("hidden");
  } finally {
    submitBtn.disabled = false;
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
          <td data-label="Quando">${formatDateTime(entry.created_at)}</td>
          <td data-label="Usuário">${escapeHtml(entry.username || "sistema")}</td>
          <td data-label="Ação">${escapeHtml(entry.action)}</td>
          <td data-label="Detalhe" class="note-cell">${escapeHtml(entry.detail || "—")}</td>
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

// Cadastros (Fase 8): Organizações/Sistemas/Projetos — contexto opcional
// pra emissão/importação/CSR. Leitura liberada pra qualquer sessão
// (populam os <select> de Emissão/CSR/Importar mesmo pra quem não vê a
// tela de Cadastros); escrita (criar/editar/remover) é admin-only, mesmo
// padrão de qualquer outra configuração do sistema.
const CATALOG_SELECTS = {
  organization: ["acme-organization", "csr-organization", "import-organization"],
  system: ["acme-system", "csr-system", "import-system"],
  project: ["acme-project", "csr-project", "import-project"],
};

// Os <select> dos formulários só precisam do id, mas listagens (Renovação)
// mostram o nome — cache simples id->nome, preenchido toda vez que um
// cadastro é recarregado, sem precisar de outro fetch só pra resolver nome.
const catalogNameCache = { organization: {}, system: {}, project: {} };

function populateCatalogSelects(kind, items) {
  catalogNameCache[kind] = Object.fromEntries(items.map((item) => [item.id, item.name]));
  for (const selectId of CATALOG_SELECTS[kind]) {
    const select = document.getElementById(selectId);
    if (!select) continue;
    const previousValue = select.value;
    const placeholder = select.options[0];
    select.innerHTML = "";
    select.appendChild(placeholder);
    items
      .filter((item) => item.status === "active")
      .forEach((item) => {
        const option = document.createElement("option");
        option.value = item.id;
        option.textContent = item.name;
        select.appendChild(option);
      });
    if ([...select.options].some((o) => o.value === previousValue)) {
      select.value = previousValue;
    }
  }
  // Cadastros e certificados carregam em paralelo — se os certificados
  // chegaram primeiro, contextLine/chart-managed-org ficaram com "removido"
  // por falta de nome ainda; re-renderiza agora que o cache tem o nome.
  applyCertificateFilters();
  renderManagedCertsOverview();
}

// Organizações
const orgsBody = document.getElementById("orgs-body");
const orgsEmpty = document.getElementById("orgs-empty");
const orgsError = document.getElementById("orgs-error");
const orgForm = document.getElementById("org-form");
const orgFormDetails = document.getElementById("org-form-details");
const orgFormSubmit = document.getElementById("org-form-submit");
const orgFormCancel = document.getElementById("org-form-cancel");

async function refreshOrganizations() {
  try {
    const response = await fetch("/api/organizations");
    if (!response.ok) return;
    const orgs = await response.json();
    populateCatalogSelects("organization", orgs);
    orgsEmpty.classList.toggle("hidden", orgs.length > 0);
    orgsBody.innerHTML = orgs
      .map(
        (org) => `<tr>
          <td data-label="Nome">${escapeHtml(org.name)}</td>
          <td data-label="Unidade">${escapeHtml(org.unit || "—")}</td>
          <td data-label="Cidade/UF">${escapeHtml([org.city, org.state].filter(Boolean).join("/") || "—")}</td>
          <td data-label="Categoria">${escapeHtml(org.category || "—")}</td>
          <td data-label="Status">${org.status === "active" ? "Ativo" : "Inativo"}</td>
          <td data-label="">
            <button type="button" class="button-link org-edit-btn" data-requires-role="admin" data-id="${escapeHtml(org.id)}">editar</button>
            <button type="button" class="button-link org-delete-btn" data-requires-role="admin" data-id="${escapeHtml(org.id)}" data-name="${escapeHtml(org.name)}">remover</button>
          </td>
        </tr>`
      )
      .join("");
    applyRoleVisibility();
  } catch {
    // mantém a lista anterior se o fetch falhar
  }
}

function resetOrgForm() {
  orgForm.reset();
  document.getElementById("org-form-id").value = "";
  orgFormSubmit.textContent = "Criar organização";
  orgFormCancel.classList.add("hidden");
}

orgForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  orgsError.classList.add("hidden");
  const editId = document.getElementById("org-form-id").value;
  const payload = {
    name: document.getElementById("org-name").value.trim(),
    unit: document.getElementById("org-unit").value.trim(),
    city: document.getElementById("org-city").value.trim(),
    state: document.getElementById("org-state").value.trim(),
    country: document.getElementById("org-country").value.trim(),
    phone: document.getElementById("org-phone").value.trim(),
    category: document.getElementById("org-category").value.trim(),
    status: document.getElementById("org-status").value,
  };
  const submitBtn = orgForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    const response = await fetch(
      editId ? `/api/organizations/${encodeURIComponent(editId)}` : "/api/organizations",
      {
        method: editId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }
    );
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.detail || `Erro ${response.status}`);
    }
    resetOrgForm();
    orgFormDetails.open = false;
    await refreshOrganizations();
  } catch (err) {
    orgsError.textContent = err.message || "Não foi possível salvar a organização.";
    orgsError.classList.remove("hidden");
  } finally {
    submitBtn.disabled = false;
  }
});

orgFormCancel.addEventListener("click", resetOrgForm);

orgsBody.addEventListener("click", async (event) => {
  const editBtn = event.target.closest(".org-edit-btn");
  const deleteBtn = event.target.closest(".org-delete-btn");
  if (editBtn) {
    const response = await fetch("/api/organizations");
    const orgs = await response.json();
    const org = orgs.find((o) => o.id === editBtn.dataset.id);
    if (!org) return;
    document.getElementById("org-form-id").value = org.id;
    document.getElementById("org-name").value = org.name;
    document.getElementById("org-unit").value = org.unit;
    document.getElementById("org-city").value = org.city;
    document.getElementById("org-state").value = org.state;
    document.getElementById("org-country").value = org.country;
    document.getElementById("org-phone").value = org.phone;
    document.getElementById("org-category").value = org.category;
    document.getElementById("org-status").value = org.status;
    orgFormSubmit.textContent = "Salvar alterações";
    orgFormCancel.classList.remove("hidden");
    orgFormDetails.open = true;
    return;
  }
  if (deleteBtn) {
    if (!confirm(`Remover a organização "${deleteBtn.dataset.name}"?`)) return;
    try {
      const response = await fetch(`/api/organizations/${encodeURIComponent(deleteBtn.dataset.id)}`, {
        method: "DELETE",
      });
      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(errorBody.detail || `Erro ${response.status}`);
      }
      await refreshOrganizations();
    } catch (err) {
      orgsError.textContent = err.message || "Não foi possível remover a organização.";
      orgsError.classList.remove("hidden");
    }
  }
});

// Sistemas e Projetos — estruturalmente idênticos (nome + descrição +
// status), uma função genérica cobre os dois em vez de duas cópias coladas.
function setupCatalogCrud(kind, endpoint) {
  const body = document.getElementById(`${kind}s-body`);
  const empty = document.getElementById(`${kind}s-empty`);
  const errorEl = document.getElementById(`${kind}s-error`);
  const form = document.getElementById(`${kind}-form`);
  const formDetails = document.getElementById(`${kind}-form-details`);
  const formSubmit = document.getElementById(`${kind}-form-submit`);
  const formCancel = document.getElementById(`${kind}-form-cancel`);
  const labelCap = kind === "system" ? "sistema" : "projeto";

  function resetForm() {
    form.reset();
    document.getElementById(`${kind}-form-id`).value = "";
    formSubmit.textContent = `Criar ${labelCap}`;
    formCancel.classList.add("hidden");
  }

  async function refresh() {
    try {
      const response = await fetch(endpoint);
      if (!response.ok) return;
      const items = await response.json();
      populateCatalogSelects(kind, items);
      empty.classList.toggle("hidden", items.length > 0);
      body.innerHTML = items
        .map(
          (item) => `<tr>
            <td data-label="Nome">${escapeHtml(item.name)}</td>
            <td data-label="Descrição">${escapeHtml(item.description || "—")}</td>
            <td data-label="Status">${item.status === "active" ? "Ativo" : "Inativo"}</td>
            <td data-label="">
              <button type="button" class="button-link ${kind}-edit-btn" data-requires-role="admin" data-id="${escapeHtml(item.id)}">editar</button>
              <button type="button" class="button-link ${kind}-delete-btn" data-requires-role="admin" data-id="${escapeHtml(item.id)}" data-name="${escapeHtml(item.name)}">remover</button>
            </td>
          </tr>`
        )
        .join("");
      applyRoleVisibility();
    } catch {
      // mantém a lista anterior se o fetch falhar
    }
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorEl.classList.add("hidden");
    const editId = document.getElementById(`${kind}-form-id`).value;
    const payload = {
      name: document.getElementById(`${kind}-name`).value.trim(),
      description: document.getElementById(`${kind}-description`).value.trim(),
      status: document.getElementById(`${kind}-status`).value,
    };
    const submitBtn = form.querySelector("button[type=submit]");
    submitBtn.disabled = true;
    try {
      const response = await fetch(
        editId ? `${endpoint}/${encodeURIComponent(editId)}` : endpoint,
        {
          method: editId ? "PUT" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );
      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(errorBody.detail || `Erro ${response.status}`);
      }
      resetForm();
      formDetails.open = false;
      await refresh();
    } catch (err) {
      errorEl.textContent = err.message || `Não foi possível salvar o ${labelCap}.`;
      errorEl.classList.remove("hidden");
    } finally {
      submitBtn.disabled = false;
    }
  });

  formCancel.addEventListener("click", resetForm);

  body.addEventListener("click", async (event) => {
    const editBtn = event.target.closest(`.${kind}-edit-btn`);
    const deleteBtn = event.target.closest(`.${kind}-delete-btn`);
    if (editBtn) {
      const response = await fetch(endpoint);
      const items = await response.json();
      const item = items.find((i) => i.id === editBtn.dataset.id);
      if (!item) return;
      document.getElementById(`${kind}-form-id`).value = item.id;
      document.getElementById(`${kind}-name`).value = item.name;
      document.getElementById(`${kind}-description`).value = item.description;
      document.getElementById(`${kind}-status`).value = item.status;
      formSubmit.textContent = "Salvar alterações";
      formCancel.classList.remove("hidden");
      formDetails.open = true;
      return;
    }
    if (deleteBtn) {
      if (!confirm(`Remover "${deleteBtn.dataset.name}"?`)) return;
      try {
        const response = await fetch(`${endpoint}/${encodeURIComponent(deleteBtn.dataset.id)}`, {
          method: "DELETE",
        });
        if (!response.ok) {
          const errorBody = await response.json().catch(() => ({}));
          throw new Error(errorBody.detail || `Erro ${response.status}`);
        }
        await refresh();
      } catch (err) {
        errorEl.textContent = err.message || `Não foi possível remover o ${labelCap}.`;
        errorEl.classList.remove("hidden");
      }
    }
  });

  return refresh;
}

const refreshSystems = setupCatalogCrud("system", "/api/systems");
const refreshProjects = setupCatalogCrud("project", "/api/projects");

function refreshCatalogs() {
  refreshOrganizations();
  refreshSystems();
  refreshProjects();
}

refreshCurrentUser();
// Carrega os cadastros sempre (não só pra quem vê a tela de Cadastros) —
// os <select> de Emissão/CSR/Importar precisam deles pra qualquer papel
// que possa criar certificado (operador não vê Cadastros, mas escolhe
// entre o que já está cadastrado lá).
refreshCatalogs();

// Rota inicial — por último, depois que toda função/const que uma tela
// pode precisar (ex: refreshSecurityStatus) já foi definida.
routeFromHash();

