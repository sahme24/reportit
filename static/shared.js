/* Shared chrome: announcement bar, navbar, theme toggle, session helpers. */

const CatPhish = {
  esc(s) {
    return (s ?? "").toString()
      .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  },

  /* A shield that peaks into two ears: the security read and the cat read in
     one silhouette, which is the only way this survives at navbar size. The
     cat is the one CATCHING the phish, not doing it -- worth keeping in mind
     if this ever gets redrawn. */
  logo: `
    <svg width="26" height="26" viewBox="0 0 26 26" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M4 8 L5.4 2.4 L9.8 5.6 H16.2 L20.6 2.4 L22 8 V12.2
               C22 18.3 18.2 22.7 13 24.4 C7.8 22.7 4 18.3 4 12.2 Z"
            fill="var(--primary)" opacity="0.15"/>
      <path d="M4 8 L5.4 2.4 L9.8 5.6 H16.2 L20.6 2.4 L22 8 V12.2
               C22 18.3 18.2 22.7 13 24.4 C7.8 22.7 4 18.3 4 12.2 Z"
            stroke="var(--primary)" stroke-width="1.9" stroke-linejoin="round"/>
      <ellipse cx="10.2" cy="13.1" rx="1.15" ry="1.7" fill="var(--primary)"/>
      <ellipse cx="15.8" cy="13.1" rx="1.15" ry="1.7" fill="var(--primary)"/>
    </svg>`,

  icon: {
    email: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:3px;"><rect x="2" y="4.5" width="20" height="15" rx="2"/><path d="M3 6.5 L12 13 L21 6.5"/></svg>`,
    sms: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:3px;"><path d="M3 4.5 H21 V16 H9 L4.5 20 V16 H3 Z"/></svg>`,
  },

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
        New! Every scan now opens the links in a sandbox and shows you
        the page they lead to.
        <button class="dismiss" aria-label="Dismiss" onclick="CatPhish.dismissBanner()">✕</button>
      </div>`;

    let links, right;
    if (user) {
      links = `
        ${link("/dashboard", "Dashboard")}
        ${link("/scan", "Scanner")}
        ${link("/history", "Case History")}`;
      right = `
        <span class="welcome">Welcome, <b>${this.esc(user.name)}</b></span>
        <button class="btn outline pill" onclick="CatPhish.logout()">Sign out</button>`;
    } else {
      // These must match real section ids in index.html -- there is no
      // section#why any more, and a nav link to a missing anchor just
      // silently does nothing.
      links = `
        ${link("/#how", "How it works")}
        ${link("/#usage", "When to use it")}
        ${link("/#trust", "Privacy")}
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
            <!-- "Phish" carries the accent colour: the eye lands on the
                 security word, not the cat, which is what stops the name
                 reading as a dating-scam tool. -->
            <span class="brand-name">Cat<span class="tld">Phish</span></span>
          </a>
          <nav class="nav-links">${links}</nav>
          <div class="nav-right">
            ${right}
            <button class="theme-toggle" title="Toggle theme"
                    onclick="CatPhish.theme.toggle()"></button>
          </div>
        </div>
      </div>`;
    this.theme.set(this.theme.get());
    return user;
  },
};

/* Apply saved theme before first paint to avoid a flash. */
document.documentElement.dataset.theme = CatPhish.theme.get();
