const sections = {
  register: document.getElementById("setup-register"),
  loginPassword: document.getElementById("login-password-section"),
  loginMfa: document.getElementById("login-mfa"),
  manualContinue: document.getElementById("manual-continue"),
};

const errorBanner = document.getElementById("auth-error-message");
let pendingLoginToken = null;

// Trava contra loop de redirecionamento: se o navegador não estiver
// aceitando/reenviando o cookie de sessão por qualquer motivo (extensão de
// privacidade, bloqueio de cookies para localhost, etc.), o servidor e o
// próprio cliente podem discordar sobre "autenticado ou não" e ficar
// redirecionando infinitamente entre auth.html e "/". Isso garante que a
// tentativa automática só acontece uma vez por aba; se ela não resolver,
// mostramos uma saída manual em vez de continuar piscando a tela.
const REDIRECT_KEY = "certdisc_redirect_attempted";

function showSection(name) {
  Object.values(sections).forEach((section) => section.classList.add("hidden"));
  const section = sections[name];
  section.classList.remove("hidden");
  section.querySelector("input")?.focus();
}

function showManualContinue() {
  Object.values(sections).forEach((section) => section.classList.add("hidden"));
  sections.manualContinue.classList.remove("hidden");
}

// Já estamos em "/" (auth.html é servido nesse mesmo caminho) — por isso é
// `location.reload()`, não `location.href = "/"`. Medido em teste real: uma
// atribuição a `location.href` com a MESMA URL atual às vezes navega antes
// do cookie recém-recebido (via fetch) estar comprometido na camada de rede
// do navegador, fazendo o servidor decidir com base no cookie antigo e
// devolver auth.html de novo — só um reload de verdade (equivalente a
// apertar F5) mostrou-se confiável nesse cenário.
function navigateToApp() {
  if (sessionStorage.getItem(REDIRECT_KEY)) {
    showManualContinue();
    return;
  }
  sessionStorage.setItem(REDIRECT_KEY, "1");
  window.location.reload();
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

// Confirma (via fetch, sempre same-origin, não afetado por SameSite) que o
// servidor já reconhece a sessão antes de navegar — dá uma chance de o
// cookie assentar antes da navegação, mas a garantia real contra loop é o
// navigateToApp()/REDIRECT_KEY acima, não esse polling.
async function goToApp() {
  for (let attempt = 0; attempt < 15; attempt++) {
    const response = await fetch("/api/auth/status");
    const { state } = await response.json();
    if (state === "authenticated") break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  navigateToApp();
}

async function withSubmitLock(form, action) {
  clearError();
  // Cada novo envio de formulário (login/cadastro) merece uma tentativa
  // fresca de redirecionamento automático.
  sessionStorage.removeItem(REDIRECT_KEY);
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
      navigateToApp();
      return;
    }
    if (state === "needs_setup") {
      showSection("register");
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

    await postJson("/api/auth/setup", { username, password });
    await goToApp();
  });
});

document.getElementById("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  withSubmitLock(event.target, async () => {
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;
    const data = await postJson("/api/auth/login", { username, password });
    if (!data.mfa_required) {
      await goToApp();
      return;
    }
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

document.getElementById("manual-continue-btn").addEventListener("click", () => {
  // Mesmo motivo do navigateToApp(): um reload de verdade, não navegação
  // via link/href para a mesma URL.
  window.location.reload();
});

init();
