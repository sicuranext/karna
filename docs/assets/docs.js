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

  // Copy the given text to the clipboard, with a fallback for non-secure
  // contexts / older browsers. Calls done() on success.
  function copyText(text, done) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text, done); });
    } else {
      legacyCopy(text, done);
    }
  }
  function legacyCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* no-op */ }
    document.body.removeChild(ta);
  }

  // Add a copy-to-clipboard button to every code block.
  document.querySelectorAll('.code-card').forEach(function (card) {
    var pre = card.querySelector('.code-body pre') || card.querySelector('pre');
    if (!pre) return;
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.setAttribute('aria-label', 'Copy code to clipboard');
    var reset;
    btn.addEventListener('click', function () {
      copyText(pre.textContent, function () {
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        clearTimeout(reset);
        reset = setTimeout(function () {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 1500);
      });
    });
    var head = card.querySelector('.code-head');
    if (head) {
      head.appendChild(btn);
    } else {
      card.style.position = 'relative';
      btn.classList.add('copy-btn-float');
      card.appendChild(btn);
    }
  });
})();
