/* Hamburglar custom JavaScript for MkDocs */

// Add copy button functionality enhancement
document.addEventListener('DOMContentLoaded', function() {
  // Add smooth scrolling for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      const targetId = this.getAttribute('href');
      if (targetId && targetId !== '#') {
        const target = document.querySelector(targetId);
        if (target) {
          e.preventDefault();
          target.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
          });
        }
      }
    });
  });
});

// Version selector enhancement (if using mike for versioning)
document.addEventListener('DOMContentLoaded', function() {
  const versionSelector = document.querySelector('.md-version');
  if (versionSelector) {
    versionSelector.title = 'Select documentation version';
  }
});
