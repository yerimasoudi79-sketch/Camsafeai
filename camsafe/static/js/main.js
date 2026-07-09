// Menu mobile
document.addEventListener('DOMContentLoaded', function () {
  const toggle = document.getElementById('navToggle');
  const nav = document.getElementById('mainNav');
  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      nav.classList.toggle('open');
      nav.style.display = nav.classList.contains('open') ? 'flex' : '';
      if (nav.classList.contains('open')) {
        nav.style.position = 'absolute';
        nav.style.top = '68px';
        nav.style.left = '0';
        nav.style.right = '0';
        nav.style.background = '#0f1826';
        nav.style.flexDirection = 'column';
        nav.style.padding = '20px 24px';
        nav.style.borderBottom = '1px solid #223350';
      }
    });
  }

  // Génère des points aléatoires sur le radar (élément signature)
  const radar = document.querySelector('.radar-visual');
  if (radar) {
    const colors = ['#e8342a', '#f2b705', '#1fa65a'];
    for (let i = 0; i < 6; i++) {
      const blip = document.createElement('div');
      blip.className = 'radar-blip';
      const angle = Math.random() * 2 * Math.PI;
      const radius = 15 + Math.random() * 35;
      const x = 50 + radius * Math.cos(angle);
      const y = 50 + radius * Math.sin(angle);
      blip.style.left = x + '%';
      blip.style.top = y + '%';
      const color = colors[Math.floor(Math.random() * colors.length)];
      blip.style.background = color;
      blip.style.color = color;
      blip.style.opacity = (0.5 + Math.random() * 0.5).toFixed(2);
      radar.appendChild(blip);
    }
    const sweep = document.createElement('div');
    sweep.className = 'radar-sweep';
    radar.appendChild(sweep);
  }

  // Score rings : applique la variable CSS --score et --ring-color
  document.querySelectorAll('.score-ring').forEach(function (ring) {
    const score = ring.getAttribute('data-score');
    const color = ring.getAttribute('data-color');
    ring.style.setProperty('--score', score);
    ring.style.setProperty('--ring-color', color);
  });

  // Aperçu du nom de fichier sélectionné
  const fileInput = document.getElementById('media_file');
  const fileLabel = document.getElementById('fileDropLabel');
  if (fileInput && fileLabel) {
    fileInput.addEventListener('change', function () {
      if (fileInput.files.length > 0) {
        fileLabel.textContent = fileInput.files[0].name;
      }
    });
  }
});
