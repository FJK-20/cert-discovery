const sections = {
  register: document.getElementById("setup-register"),
  mfaEnroll: document.getElementById("mfa-enroll"),
  loginPassword: document.getElementById("login-password-section"),
  loginMfa: document.getElementById("login-mfa"),
};

const errorBanner = document.getElementById("auth-error-message");
let pendingLoginToken = null;

function showSection(name) {
  Object.values(sections).forEach((section) => section.classList.add("hidden"));
  const section = sections[name];
  section.classList.remove("hidden");
  section.querySelector("input")?.focus();
}

// Erro aparece acima do card atual, sem esconder o formulário — o usuário
// pode corrigir e tentar de novo sem perder o passo em que está (ex: não
// perde a tela de MFA se digitar o código errado).
function showError(message) {
  errorBanner.textContent = message;
  errorBanner.classList.remove("hidden");
}

function clearError() {
  errorBanner.classList.add("hidden");
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

// Confirma que o cookie de sessão recém-emitido já é reconhecido pelo
// servidor antes de navegar. Sem isso, em alguns navegadores o
// window.location.href logo após o Set-Cookie corre com o commit do
// cookie e a página recarrega como se ainda não estivesse autenticado —
// travando na mesma tela até um F5 manual.
async function goToApp() {
  for (let attempt = 0; attempt < 15; attempt++) {
    const response = await fetch("/api/auth/status");
    const { state } = await response.json();
    if (state === "authenticated") break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  window.location.href = "/";
}

async function withSubmitLock(form, action) {
  clearError();
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    await action();
  } catch (err) {
    showError(err.message || "Algo deu errado. Tente novamente.");
  } finally {
    button.disabled = false;
  }
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

document.getElementById("register-form").addEventListener("submit", (event) => {
  event.preventDefault();
  withSubmitLock(event.target, async () => {
    const username = document.getElementById("register-username").value.trim();
    const password = document.getElementById("register-password").value;
    const confirmPassword = document.getElementById("register-password-confirm").value;

    if (password !== confirmPassword) {
      throw new Error("As senhas não coincidem.");
    }

    const data = await postJson("/api/auth/setup", { username, password });
    renderEnrollment(data);
  });
});

document.getElementById("mfa-enroll-form").addEventListener("submit", (event) => {
  event.preventDefault();
  withSubmitLock(event.target, async () => {
    const code = document.getElementById("mfa-enroll-code").value.trim();
    await postJson("/api/auth/setup/verify-mfa", { code });
    await goToApp();
  });
});

document.getElementById("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  withSubmitLock(event.target, async () => {
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;
    const data = await postJson("/api/auth/login", { username, password });
    pendingLoginToken = data.pending_token;
    showSection("loginMfa");
  });
});

document.getElementById("login-mfa-form").addEventListener("submit", (event) => {
  event.preventDefault();
  withSubmitLock(event.target, async () => {
    const code = document.getElementById("login-mfa-code").value.trim();
    await postJson("/api/auth/login/verify-mfa", { pending_token: pendingLoginToken, code });
    await goToApp();
  });
});

init();
