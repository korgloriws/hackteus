(() => {
  const canvas = document.getElementById("matrix-rain");
  if (!canvas) return;

  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) {
    canvas.style.display = "none";
    return;
  }

  const ctx = canvas.getContext("2d");
  const glyphs =
    "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789<>/$#@%&*HACKTEUS";

  let width = 0;
  let height = 0;
  let columns = [];
  let fontSize = 14;
  let raf = 0;
  let boost = 1;

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    fontSize = Math.max(12, Math.floor(width / 90));
    const cols = Math.ceil(width / fontSize);
    columns = Array.from({ length: cols }, () => Math.random() * -80);
  }

  function frame() {
    ctx.fillStyle = "rgba(2, 8, 5, 0.08)";
    ctx.fillRect(0, 0, width, height);
    ctx.font = `${fontSize}px "JetBrains Mono", monospace`;

    for (let i = 0; i < columns.length; i++) {
      const x = i * fontSize;
      const y = columns[i] * fontSize;
      const ch = glyphs[(Math.random() * glyphs.length) | 0];
      const head = Math.random() > 0.975;
      ctx.fillStyle = head ? "#e8fff0" : i % 7 === 0 ? "#5cffd7" : "#00ff88";
      ctx.globalAlpha = head ? 0.95 : 0.35 + Math.random() * 0.45;
      ctx.fillText(ch, x, y);
      ctx.globalAlpha = 1;

      if (y > height && Math.random() > 0.975 / boost) {
        columns[i] = 0;
      }
      columns[i] += (0.65 + Math.random() * 0.55) * boost;
    }
    raf = requestAnimationFrame(frame);
  }

  window.HackteusMatrix = {
    setBoost(v) {
      boost = Math.max(0.6, Math.min(2.4, v));
    },
  };

  resize();
  window.addEventListener("resize", resize);
  raf = requestAnimationFrame(frame);

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      cancelAnimationFrame(raf);
    } else {
      raf = requestAnimationFrame(frame);
    }
  });
})();
