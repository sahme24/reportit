/* Vanilla ports of three React Bits components (SplitText, MagnetLines,
   Beams) for this no-build static site. Same visual behavior and knobs as
   the originals, but no React, no three.js, no GSAP: SplitText is spans +
   staggered CSS transitions, MagnetLines is the original's own DOM math,
   and Beams is a 2D-canvas re-creation of the shader (value noise driving
   vertical light beams). All three respect prefers-reduced-motion by
   rendering their final state statically. */

const ReportITFX = (() => {
  const reduceMotion =
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------------------------------------------- SplitText ---- */
  function splitText(el, { delay = 40, duration = 0.7 } = {}) {
    if (!el) return;
    el.setAttribute("aria-label", el.textContent);
    const chars = [];

    const splitTextNode = node => {
      const frag = document.createDocumentFragment();
      let word = null;
      for (const ch of node.textContent) {
        if (ch.trim() === "") {
          frag.appendChild(document.createTextNode(ch));
          word = null;
          continue;
        }
        if (!word) {
          word = document.createElement("span");
          word.className = "split-word";
          frag.appendChild(word);
        }
        const s = document.createElement("span");
        s.className = "split-char";
        s.setAttribute("aria-hidden", "true");
        s.textContent = ch;
        word.appendChild(s);
        chars.push(s);
      }
      node.replaceWith(frag);
    };

    const walk = node => {
      [...node.childNodes].forEach(child => {
        if (child.nodeType === Node.TEXT_NODE) splitTextNode(child);
        else if (child.nodeType === Node.ELEMENT_NODE) walk(child);
      });
    };
    walk(el);

    if (reduceMotion) {
      el.classList.add("split-done");
      return;
    }
    chars.forEach((s, i) => {
      s.style.transition =
        `transform ${duration}s cubic-bezier(0.16,1,0.3,1) ${i * delay}ms, ` +
        `opacity ${duration}s ease ${i * delay}ms`;
    });
    // Double rAF so the initial (hidden) state paints before transitioning,
    // with a timer fallback in case rAF is throttled (e.g. a backgrounded
    // tab) -- the reveal must never depend on rAF actually firing.
    let done = false;
    const reveal = () => { if (!done) { done = true; el.classList.add("split-done"); } };
    requestAnimationFrame(() => requestAnimationFrame(reveal));
    setTimeout(reveal, 150);
  }

  /* -------------------------------------------------- MagnetLines ---- */
  function magnetLines(container, {
    rows = 9, columns = 9, lineWidth = "2px", lineHeight = "16px",
    baseAngle = -10,
  } = {}) {
    if (!container) return;
    container.style.gridTemplateColumns = `repeat(${columns}, 1fr)`;
    container.style.gridTemplateRows = `repeat(${rows}, 1fr)`;
    const items = [];
    for (let i = 0; i < rows * columns; i++) {
      const s = document.createElement("span");
      s.style.setProperty("--rotate", `${baseAngle}deg`);
      s.style.width = lineWidth;
      s.style.height = lineHeight;
      container.appendChild(s);
      items.push(s);
    }
    if (reduceMotion) return;

    let ticking = false;
    const point = { x: 0, y: 0 };
    const apply = () => {
      ticking = false;
      for (const item of items) {
        const rect = item.getBoundingClientRect();
        const b = point.x - (rect.x + rect.width / 2);
        const a = point.y - (rect.y + rect.height / 2);
        const c = Math.sqrt(a * a + b * b) || 1;
        const r = (Math.acos(b / c) * 180 / Math.PI) * (a > 0 ? 1 : -1);
        item.style.setProperty("--rotate", `${r}deg`);
      }
    };
    window.addEventListener("pointermove", e => {
      point.x = e.clientX;
      point.y = e.clientY;
      if (!ticking) { ticking = true; requestAnimationFrame(apply); }
    }, { passive: true });

    const mid = items[Math.floor(items.length / 2)].getBoundingClientRect();
    point.x = mid.x;
    point.y = mid.y;
    apply();
  }

  /* -------------------------------------------------------- Beams ---- */
  const _fract = x => x - Math.floor(x);
  const _rnd = (x, y) => _fract(Math.sin(x * 12.9898 + y * 78.233) * 43758.5453);
  function _vnoise(x, y) {
    const ix = Math.floor(x), iy = Math.floor(y);
    const fx = x - ix, fy = y - iy;
    const ux = fx * fx * (3 - 2 * fx), uy = fy * fy * (3 - 2 * fy);
    const a = _rnd(ix, iy), b = _rnd(ix + 1, iy);
    const c = _rnd(ix, iy + 1), d = _rnd(ix + 1, iy + 1);
    return a + (b - a) * ux + (c - a) * uy * (1 - ux) + (d - b) * ux * uy;
  }

  function beams(canvas, {
    beamNumber = 12, speed = 2, noiseIntensity = 1.75, scale = 1.6,
    rotation = 30, lightColor = "#8fb3ff", background = "#080d1d",
  } = {}) {
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const hex = lightColor.replace("#", "");
    const lr = parseInt(hex.slice(0, 2), 16);
    const lg = parseInt(hex.slice(2, 4), 16);
    const lb = parseInt(hex.slice(4, 6), 16);
    const seeds = Array.from({ length: beamNumber },
                             () => Math.random() * 300);
    const SEGS = 80;
    let w = 0, h = 0, running = !reduceMotion, raf = 0;

    const resize = () => {
      const rect = canvas.parentElement.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = rect.width;
      h = rect.height;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    new ResizeObserver(resize).observe(canvas.parentElement);

    const draw = t => {
      ctx.setTransform(canvas.width / w / 1, 0, 0, canvas.height / h / 1, 0, 0);
      ctx.fillStyle = background;
      ctx.fillRect(0, 0, w, h);

      // Rotate the whole beam field like the original's group rotation,
      // drawing an oversized field so corners stay covered.
      const diag = Math.sqrt(w * w + h * h) * 1.2;
      ctx.save();
      ctx.translate(w / 2, h / 2);
      ctx.rotate(rotation * Math.PI / 180);
      const beamW = diag / beamNumber;
      const segH = diag / SEGS;
      for (let i = 0; i < beamNumber; i++) {
        const x = -diag / 2 + i * beamW;
        for (let j = 0; j < SEGS; j++) {
          const y = -diag / 2 + j * segH;
          let n = _vnoise(seeds[i] + j / SEGS * scale * 4,
                          seeds[i] + t * speed * 0.35);
          n = Math.max(0, n * 1.5 - 0.55);
          // Screen-space grain, the uNoiseIntensity part of the shader.
          n -= _rnd(i * SEGS + j, Math.floor(t * 8)) * 0.02 * noiseIntensity;
          if (n <= 0.005) continue;
          ctx.fillStyle =
            `rgba(${lr},${lg},${lb},${Math.min(n * 0.85, 0.85)})`;
          ctx.fillRect(x + beamW * 0.12, y - 1, beamW * 0.76, segH + 2);
        }
      }
      ctx.restore();

      // Soft directional-light glow from the top, like the original's
      // white directional light.
      const glow = ctx.createRadialGradient(w / 2, -h * 0.25, 0,
                                            w / 2, -h * 0.25, h * 1.1);
      glow.addColorStop(0, "rgba(255,255,255,0.14)");
      glow.addColorStop(1, "rgba(255,255,255,0)");
      ctx.fillStyle = glow;
      ctx.fillRect(0, 0, w, h);
    };

    draw(3.7); // one static frame immediately, so there's never a blank canvas
    if (!running) return;
    const loop = now => {
      draw(now / 1000);
      raf = requestAnimationFrame(loop);
    };
    // Only animate while on screen.
    new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !raf) raf = requestAnimationFrame(loop);
      else if (!entry.isIntersecting && raf) {
        cancelAnimationFrame(raf);
        raf = 0;
      }
    }).observe(canvas);
  }

  return { splitText, magnetLines, beams };
})();
