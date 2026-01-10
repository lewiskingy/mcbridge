const DEFAULT_THEME = "dark";
const THEME_STORAGE_KEY = "theme";

function updateThemeButton(theme) {
  const btn = document.getElementById("themeBtn");
  if (!btn) return;

  btn.textContent = theme === "dark" ? "🌙" : "☀️";
}

function applyTheme(theme) {
  document.body.dataset.theme = theme;
  localStorage.setItem(THEME_STORAGE_KEY, theme);
  updateThemeButton(theme);
}

function toggleTheme() {
  const current = document.body.dataset.theme || DEFAULT_THEME;
  const next = current === "dark" ? "light" : "dark";
  applyTheme(next);
}

function initTheme() {
  const savedTheme = localStorage.getItem(THEME_STORAGE_KEY) || DEFAULT_THEME;
  document.body.dataset.theme = savedTheme;
  updateThemeButton(savedTheme);

  const btn = document.getElementById("themeBtn");
  if (btn) {
    btn.addEventListener("click", toggleTheme);
  }
}

document.addEventListener("DOMContentLoaded", initTheme);

window.toggleTheme = toggleTheme;
