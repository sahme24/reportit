/* Shared chrome: announcement bar, navbar, theme toggle, session helpers. */

const ReportIT = {
  esc(s) {
    return (s ?? "").toString()
      .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  },

  logo: `
    <svg width="26" height="26" viewBox="0 0 26 26" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M13 1.5 L23 5.5 V12 C23 18.5 18.8 23.2 13 24.5 C7.2 23.2 3 18.5 3 12 V5.5 Z"
            fill="var(--primary)" opacity="0.15"/>
      <path d="M13 1.5 L23 5.5 V12 C23 18.5 18.8 23.2 13 24.5 C7.2 23.2 3 18.5 3 12 V5.5 Z"
            stroke="var(--primary)" stroke-width="2" stroke-linejoin="round"/>
      <path d="M8.5 12.5 L11.7 15.7 L17.5 9.5" stroke="var(--primary)" stroke-width="2.4"
            stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,

  theme: {
    get() { return localStorage.getItem("reportit-theme") || "light"; },
    set(mode) {
      localStorage.setItem("reportit-theme", mode);
      document.documentElement.dataset.theme = mode;
      const btn = document.querySelector(".theme-toggle");
      if (btn) btn.textContent = mode === "dark" ? "☀" : "☾";
    },
    toggle() { this.set(this.get() === "dark" ? "light" : "dark"); },
  },

  async me() {
    try {
      const r = await fetch("/api/me");
      return (await r.json()).user;
    } catch { return null; }
  },

  async logout() {
    await fetch("/api/logout", { method: "POST" });
    location.href = "/";
  },

  dismissBanner() {
    localStorage.setItem("reportit-banner", "off");
    const el = document.querySelector(".announce");
    if (el) el.remove();
  },

  /* Renders the announcement bar + navbar into #topbar. `active` = current path. */
  async topbar(active) {
    const user = await this.me();
    const link = (href, label) =>
      `<a href="${href}" class="${active === href ? "active" : ""}">${label}</a>`;

    const banner = localStorage.getItem("reportit-banner") === "off" ? "" : `
      <div class="announce">
        New! ReportIT.ai is fully open source —
        <a href="https://github.com/YOURUSERNAME/reportit">star it on GitHub →</a>
        <button class="dismiss" aria-label="Dismiss" onclick="ReportIT.dismissBanner()">✕</button>
      </div>`;

    let links, right;
    if (user) {
      links = `
        ${link("/scan", "Scanner")}
        ${link("/history", "Case History")}
        ${user.is_admin ? link("/dashboard", "Dashboard") : ""}`;
      right = `
        <span class="welcome">Welcome, <b>${this.esc(user.name)}</b></span>
        <button class="btn outline pill" onclick="ReportIT.logout()">Sign out</button>`;
    } else {
      links = `
        ${link("/#how", "How it works")}
        ${link("/#why", "Why ReportIT")}
        ${link("/#trust", "Open Source")}
        ${link("/#faq", "FAQ")}`;
      right = `
        <a href="/login" class="btn outline pill">Login</a>
        <a href="/login" class="btn primary pill">Start Free</a>`;
    }

    document.getElementById("topbar").innerHTML = `
      ${banner}
      <div class="navbar">
        <div class="nav-inner">
          <a class="brand" href="/">
            ${this.logo}
            <span class="brand-name">ReportIT<span class="tld">.ai</span></span>
          </a>
          <nav class="nav-links">${links}</nav>
          <div class="nav-right">
            ${right}
            <button class="theme-toggle" title="Toggle theme"
                    onclick="ReportIT.theme.toggle()"></button>
          </div>
        </div>
      </div>`;
    this.theme.set(this.theme.get());
    return user;
  },
};

/* Apply saved theme before first paint to avoid a flash. */
document.documentElement.dataset.theme = ReportIT.theme.get();
