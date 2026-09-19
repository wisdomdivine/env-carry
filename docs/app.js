document.addEventListener('DOMContentLoaded', () => {
  // 1. Copy button functionality
  const copyButtons = document.querySelectorAll('.copy-btn');
  copyButtons.forEach((btn) => {
    btn.addEventListener('click', async () => {
      const text = btn.getAttribute('data-copy');
      if (!text) return;

      try {
        await navigator.clipboard.writeText(text);
        const icon = btn.querySelector('i');
        const span = btn.querySelector('span');
        
        if (icon) icon.className = 'ti ti-check';
        if (span) span.textContent = 'Copied';
        btn.classList.add('purple-text');

        setTimeout(() => {
          if (icon) icon.className = 'ti ti-copy';
          if (span) span.textContent = 'Copy';
          btn.classList.remove('purple-text');
        }, 1800);
      } catch (err) {
        console.error('Clipboard copy failed:', err);
      }
    });
  });

  // 2. Active section tracking on scroll
  const navLinks = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('.doc-section');
  const contentArea = document.getElementById('contentArea');

  function updateActiveNav() {
    let currentId = '';
    const scrollPos = contentArea.scrollTop + 100;

    sections.forEach((section) => {
      const top = section.offsetTop;
      const height = section.offsetHeight;
      if (scrollPos >= top && scrollPos < top + height) {
        currentId = section.getAttribute('id');
      }
    });

    if (currentId) {
      navLinks.forEach((link) => {
        if (link.getAttribute('href') === `#${currentId}`) {
          link.classList.add('active');
        } else {
          link.classList.remove('active');
        }
      });
    }
  }

  contentArea.addEventListener('scroll', updateActiveNav, { passive: true });

  // 3. Smooth scroll on sidebar link click
  navLinks.forEach((link) => {
    link.addEventListener('click', (e) => {
      const targetId = link.getAttribute('href');
      if (!targetId || !targetId.startsWith('#')) return;

      const targetEl = document.querySelector(targetId);
      if (targetEl) {
        e.preventDefault();
        contentArea.scrollTo({
          top: targetEl.offsetTop - 20,
          behavior: 'smooth'
        });
        history.replaceState(null, '', targetId);
      }
    });
  });

  // 4. Global search shortcut '/'
  const searchInput = document.getElementById('searchInput');
  window.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== searchInput) {
      e.preventDefault();
      searchInput.focus();
    }
    if (e.key === 'Escape' && document.activeElement === searchInput) {
      searchInput.blur();
    }
  });

  // 5. Interactive search filtering
  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    if (!query) {
      sections.forEach((sec) => (sec.style.display = ''));
      navLinks.forEach((link) => (link.style.display = ''));
      return;
    }

    sections.forEach((section) => {
      const text = section.innerText.toLowerCase();
      if (text.includes(query)) {
        section.style.display = '';
      } else {
        section.style.display = 'none';
      }
    });

    navLinks.forEach((link) => {
      const text = link.innerText.toLowerCase();
      if (text.includes(query)) {
        link.style.display = 'block';
      } else {
        link.style.display = 'none';
      }
    });
  });
});
