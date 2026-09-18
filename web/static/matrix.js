(() => {
  const canvas = document.getElementById("matrix-rain");
  if (!canvas) return;

  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) {
    canvas.style.display = "none";
    return;
  }

  const ctx = canvas.getContext("2d");
  // glyphs estilo terminal / hex — sem verde “Matrix clássico”
  const glyphs = "01<>/$#@%&*HACKTEUSABCDEF0123456789[]{}|=+";

  let width = 0;
  let height = 0;
  let columns = [];
  let fontSize = 14;
  let raf = 0;
  let boost = 1;

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    const dense = width < 700 ? 55 : 95;
    fontSize = Math.max(11, Math.floor(width / dense));
    const cols = Math.ceil(width / fontSize);
    columns = Array.from({ length: cols }, () => Math.random() * -80);
  }

  function frame() {
    ctx.fillStyle = "rgba(12, 12, 12, 0.1)";
    ctx.fillRect(0, 0, width, height);
    ctx.font = `${fontSize}px Consolas, "Cascadia Mono", monospace`;

    for (let i = 0; i < columns.length; i++) {
      const x = i * fontSize;
      const y = columns[i] * fontSize;
      const ch = glyphs[(Math.random() * glyphs.length) | 0];
      const head = Math.random() > 0.97;
      // branco / cinza / azul cmd — sem verde neon
      ctx.fillStyle = head ? "#f3f3f3" : i % 9 === 0 ? "#3b78ff" : "#6a6a6a";
      ctx.globalAlpha = head ? 0.75 : 0.22 + Math.random() * 0.28;
      ctx.fillText(ch, x, y);
      ctx.globalAlpha = 1;

      if (y > height && Math.random() > 0.975 / boost) {
        columns[i] = 0;
      }
      columns[i] += (0.55 + Math.random() * 0.45) * boost;
    }
    raf = requestAnimationFrame(frame);
  }

  window.HackteusMatrix = {
    setBoost(v) {
      boost = Math.max(0.6, Math.min(2.2, v));
    },
  };

  resize();
  window.addEventListener("resize", resize);
  raf = requestAnimationFrame(frame);

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) cancelAnimationFrame(raf);
    else raf = requestAnimationFrame(frame);
  });
})();
