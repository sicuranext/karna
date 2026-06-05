/* Karna docs — sidebar scrollspy + heading anchor links. No dependencies. */
(function () {
  // Highlight the sidebar link for the section currently in view.
  var links = Array.prototype.slice.call(document.querySelectorAll('.doc-side a[href^="#"]'));
  if (links.length) {
    var byId = {};
    links.forEach(function (a) {
      var id = a.getAttribute('href').slice(1);
      if (id) byId[id] = a;
    });
    var sections = Object.keys(byId)
      .map(function (id) { return document.getElementById(id); })
      .filter(Boolean);

    var setActive = function (id) {
      links.forEach(function (a) { a.classList.remove('active'); });
      if (byId[id]) byId[id].classList.add('active');
    };

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) setActive(e.target.id);
      });
    }, { rootMargin: '-20% 0px -70% 0px', threshold: 0 });

    sections.forEach(function (s) { observer.observe(s); });
  }

  // Add a click-to-copy anchor (#) to every section heading that has an id.
  document.querySelectorAll('.doc-main h2[id], .doc-main h3[id]').forEach(function (h) {
    var a = document.createElement('a');
    a.className = 'anchor';
    a.href = '#' + h.id;
    a.textContent = '#';
    a.setAttribute('aria-label', 'Link to this section');
    h.appendChild(a);
  });
})();
