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

let currentRecords = [];
let currentEventSource = null;

function resetUI() {
  errorCard.classList.add("hidden");
  resultsCard.classList.add("hidden");
  progressCard.classList.remove("hidden");
  progressFill.style.width = "0%";
  progressMessage.textContent = "Iniciando...";
  progressCounts.textContent = "";
  resultsBody.innerHTML = "";
  currentRecords = [];
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

function renderTable() {
  const filter = filterStatus.value;
  const queueStatuses = new Set(["expired", "critical", "warning"]);

  const rows = currentRecords.filter((record) => {
    if (filter === "all") return true;
    if (filter === "queue") return queueStatuses.has(record.status);
    return record.status === filter;
  });

  resultsBody.innerHTML = rows
    .map((record) => {
      const expiresAt = record.not_after
        ? new Date(record.not_after).toLocaleDateString("pt-BR")
        : "—";
      const daysLeft = record.days_until_expiry ?? "—";
      const origin = record.origin === "live" ? "Handshake ao vivo" : "CT log";
      const note = record.note ? record.note : "";
      return `<tr>
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
  renderTable();
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
