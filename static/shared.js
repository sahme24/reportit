/* Shared chrome: theme toggle, topbar, session helpers. */

const Threadline = {
  esc(s) {
    return (s ?? "").toString()
      .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  },

  theme: {
    get() { return localStorage.getItem("threadline-theme") || "dark"; },
    set(mode) {
      localStorage.setItem("threadline-theme", mode);
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

  /* Renders the shared topbar into #topbar. `active` = current page path. */
  async topbar(active) {
    const user = await this.me();
    const link = (href, label) =>
      `<a href="${href}" class="${active === href ? "active" : ""}">${label}</a>`;
    let right;
    if (user) {
      right = `
        ${link("/scan", "Open a Case")}
        ${link("/history", "Case History")}
        ${user.is_admin ? link("/dashboard", "Dashboard") : ""}
        <span class="userchip">${this.esc(user.name)}</span>
        <button class="btn ghost" onclick="Threadline.logout()">Sign out</button>`;
    } else {
      right = `
        ${link("/#how", "How it works")}
        ${link("/#trust", "Open source")}
        ${link("/login", "Sign in")}
        <a href="/login?mode=signup" class="btn primary" style="text-decoration:none">Start free</a>`;
    }
    document.getElementById("topbar").innerHTML = `
      <a class="brand" href="/">
        <div class="brand-mark"></div>
        <span class="brand-name">Threadline</span>
      </a>
      <nav class="nav">
        ${right}
        <button class="theme-toggle" title="Toggle theme"
                onclick="Threadline.theme.toggle()"></button>
      </nav>`;
    this.theme.set(this.theme.get());
    return user;
  },
};

/* Apply saved theme before first paint to avoid a flash. */
document.documentElement.dataset.theme = Threadline.theme.get();
