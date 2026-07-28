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

function badgeFor(status) {
  const label = STATUS_LABELS[status] || status;
  return `<span class="badge badge-${status}">${label}</span>`;
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
      return `<tr data-row-index="${index}">
        <td>${badgeFor(record.status)}</td>
        <td>${escapeHtml(record.host)}</td>
        <td>${escapeHtml(record.issuer || "—")}</td>
        <td>${expiresAt}</td>
        <td>${daysLeft}</td>
        <td>${origin}</td>
        <td class="note-cell">${escapeHtml(note)}</td>
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
  window.location.href = "/";
});
