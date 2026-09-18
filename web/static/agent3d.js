/**
 * Máscara V / Anonymous (Guy Fawkes) — só o rosto.
 */
(function () {
  const SVG = `
<svg viewBox="0 0 80 90" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <defs>
    <linearGradient id="maskFace" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#f4f1ea"/>
      <stop offset="100%" stop-color="#d8d2c4"/>
    </linearGradient>
  </defs>
  <!-- sombra -->
  <ellipse cx="40" cy="84" rx="18" ry="3.5" fill="#000" opacity="0.3"/>
  <!-- rosto / máscara -->
  <ellipse cx="40" cy="44" rx="28" ry="34" fill="url(#maskFace)" stroke="#2a2a2a" stroke-width="1.2"/>
  <!-- sobrancelhas arqueadas -->
  <path d="M22 32 Q28 26 36 30" fill="none" stroke="#1a1a1a" stroke-width="2.2" stroke-linecap="round"/>
  <path d="M44 30 Q52 26 58 32" fill="none" stroke="#1a1a1a" stroke-width="2.2" stroke-linecap="round"/>
  <!-- olhos estreitos -->
  <ellipse cx="30" cy="40" rx="6.5" ry="3.2" fill="#111" class="racker-eyes"/>
  <ellipse cx="50" cy="40" rx="6.5" ry="3.2" fill="#111" class="racker-eyes"/>
  <!-- brilho nos olhos -->
  <circle cx="32" cy="39" r="1.2" fill="#61d6d6" class="racker-tip"/>
  <circle cx="52" cy="39" r="1.2" fill="#61d6d6" class="racker-tip"/>
  <!-- nariz sutil -->
  <path d="M40 42 L37 52 L43 52 Z" fill="#cfc8ba" opacity="0.85"/>
  <!-- bigode -->
  <path d="M28 56 Q40 62 52 56 Q46 60 40 59 Q34 60 28 56 Z" fill="#1a1a1a"/>
  <!-- sorriso -->
  <path d="M30 62 Q40 70 50 62" fill="none" stroke="#1a1a1a" stroke-width="2" stroke-linecap="round"/>
  <!-- cavanhaque -->
  <path d="M36 68 Q40 78 44 68 Q40 72 36 68 Z" fill="#1a1a1a"/>
</svg>`;

  function mount(host) {
    if (!host) return null;
    host.innerHTML = SVG;
    const svg = host.querySelector("svg");
    if (svg) {
      svg.style.width = "100%";
      svg.style.height = "100%";
      svg.style.display = "block";
    }
    return {
      setBusy(v) {
        host.classList.toggle("is-busy", !!v);
      },
      resize() {},
      destroy() {
        host.innerHTML = "";
      },
    };
  }

  window.HackteusAgent3D = { mount };
})();
