const sections = {
  register: document.getElementById("setup-register"),
  mfaEnroll: document.getElementById("mfa-enroll"),
  loginPassword: document.getElementById("login-password"),
  loginMfa: document.getElementById("login-mfa"),
  error: document.getElementById("auth-error"),
};

let pendingLoginToken = null;

function showSection(name) {
  Object.values(sections).forEach((section) => section.classList.add("hidden"));
  sections[name].classList.remove("hidden");
}

function showError(message) {
  document.getElementById("auth-error-message").textContent = message;
  showSection("error");
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Erro ${response.status}`);
  }
  return data;
}

function renderEnrollment(data) {
  document.getElementById("mfa-qr").src = data.qr_data_uri;
  document.getElementById("mfa-secret").textContent = data.secret;
  showSection("mfaEnroll");
}

async function init() {
  try {
    const response = await fetch("/api/auth/status");
    const { state } = await response.json();

    if (state === "authenticated") {
      window.location.href = "/";
      return;
    }
    if (state === "needs_setup") {
      showSection("register");
      return;
    }
    if (state === "setup_pending_mfa") {
      const data = await (await fetch("/api/auth/setup/qr")).json();
      renderEnrollment(data);
      return;
    }
    showSection("loginPassword");
  } catch (err) {
    showError("Não foi possível carregar a página de acesso. Recarregue e tente novamente.");
  }
}

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const username = document.getElementById("register-username").value.trim();
  const password = document.getElementById("register-password").value;
  const confirmPassword = document.getElementById("register-password-confirm").value;

  if (password !== confirmPassword) {
    showError("As senhas não coincidem.");
    return;
  }

  try {
    const data = await postJson("/api/auth/setup", { username, password });
    renderEnrollment(data);
  } catch (err) {
    showError(err.message);
  }
});

document.getElementById("mfa-enroll-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const code = document.getElementById("mfa-enroll-code").value.trim();
  try {
    await postJson("/api/auth/setup/verify-mfa", { code });
    window.location.href = "/";
  } catch (err) {
    showError(err.message);
  }
});

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  try {
    const data = await postJson("/api/auth/login", { username, password });
    pendingLoginToken = data.pending_token;
    showSection("loginMfa");
  } catch (err) {
    showError(err.message);
  }
});

document.getElementById("login-mfa-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const code = document.getElementById("login-mfa-code").value.trim();
  try {
    await postJson("/api/auth/login/verify-mfa", { pending_token: pendingLoginToken, code });
    window.location.href = "/";
  } catch (err) {
    showError(err.message);
  }
});

init();
