/* ==========================================================================
   BetGlobal front-end behaviours
   Vanilla replacement for the Bootstrap bundle: modals, alerts, dropdown,
   collapsible sidebar. No dependencies beyond feather-icons.
   ========================================================================== */
(function () {
  'use strict';

  var BG = {};

  /* ----------------------------------------------------------- feather -- */
  function icons() {
    if (window.feather) window.feather.replace();
  }
  BG.icons = icons;

  /* ------------------------------------------------------------ modals -- */
  var openStack = [];

  function openModal(id) {
    var el = typeof id === 'string' ? document.getElementById(id) : id;
    if (!el) return null;
    el.classList.add('is-open');
    el.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    if (openStack.indexOf(el) === -1) openStack.push(el);
    var focusable = el.querySelector('[autofocus], button, [href], input, select, textarea');
    if (focusable) focusable.focus({ preventScroll: true });
    icons();
    return el;
  }

  function closeModal(id) {
    var el = typeof id === 'string' ? document.getElementById(id) : id;
    if (!el) return;
    el.classList.remove('is-open');
    el.setAttribute('aria-hidden', 'true');
    openStack = openStack.filter(function (m) { return m !== el; });
    if (!openStack.length) document.body.classList.remove('modal-open');
  }

  function closeTopModal() {
    if (openStack.length) closeModal(openStack[openStack.length - 1]);
  }

  BG.openModal = openModal;
  BG.closeModal = closeModal;

  /* -------------------------------------------------- shared modal HTML -- */
  /* Injected once so every page gets confirm / notify / image dialogs
     without repeating the markup in each template. */
  function ensureSharedModals() {
    if (document.getElementById('bgConfirmModal')) return;

    var html =
      '<div class="modal-backdrop" id="bgConfirmModal" role="dialog" aria-modal="true" aria-hidden="true">' +
        '<div class="modal" style="max-width:440px">' +
          '<div class="modal-head">' +
            '<span class="tile" id="bgConfirmTile"><i data-feather="help-circle"></i></span>' +
            '<h2 id="bgConfirmTitle">Are you sure?</h2>' +
            '<button type="button" class="modal-close" data-modal-close aria-label="Close">' +
              '<i data-feather="x"></i></button>' +
          '</div>' +
          '<div class="modal-body"><p class="body-sm" id="bgConfirmBody" style="margin:0"></p></div>' +
          '<div class="modal-foot">' +
            '<div class="spacer"></div>' +
            '<button type="button" class="btn btn-ghost btn-sm" data-modal-close>Cancel</button>' +
            '<button type="button" class="btn btn-primary btn-sm" id="bgConfirmOk">Confirm</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="modal-backdrop" id="bgNotifyModal" role="dialog" aria-modal="true" aria-hidden="true">' +
        '<div class="modal" style="max-width:420px">' +
          '<div class="modal-head">' +
            '<span class="tile" id="bgNotifyTile"><i data-feather="info"></i></span>' +
            '<h2 id="bgNotifyTitle">Notice</h2>' +
            '<button type="button" class="modal-close" data-modal-close aria-label="Close">' +
              '<i data-feather="x"></i></button>' +
          '</div>' +
          '<div class="modal-body"><p class="body-sm" id="bgNotifyBody" style="margin:0"></p></div>' +
          '<div class="modal-foot">' +
            '<div class="spacer"></div>' +
            '<button type="button" class="btn btn-primary btn-sm" data-modal-close>OK</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="modal-backdrop" id="bgImageModal" role="dialog" aria-modal="true" aria-hidden="true">' +
        '<div class="modal modal-lg">' +
          '<div class="modal-head">' +
            '<h2 id="bgImageTitle">Evidence</h2>' +
            '<button type="button" class="modal-close" data-modal-close aria-label="Close">' +
              '<i data-feather="x"></i></button>' +
          '</div>' +
          '<div class="modal-body" style="text-align:center">' +
            '<img id="bgImageTarget" alt="" style="max-width:100%;border-radius:6px">' +
          '</div>' +
        '</div>' +
      '</div>';

    var host = document.createElement('div');
    host.innerHTML = html;
    while (host.firstChild) document.body.appendChild(host.firstChild);
  }

  function setTile(tileEl, icon, color) {
    if (!tileEl) return;
    /* feather names only — never interpolate caller text into markup */
    var safe = /^[a-z0-9-]+$/.test(String(icon || '')) ? icon : 'info';
    var i = document.createElement('i');
    i.setAttribute('data-feather', safe);
    tileEl.replaceChildren(i);
    tileEl.style.color = color || '';
    tileEl.style.background = color ? 'color-mix(in srgb, ' + color + ' 12%, #fff)' : '';
  }

  /* Signatures kept identical to the previous Bootstrap-backed helpers so
     existing page scripts (dashboard, index, admin_disputes) keep working. */
  function showConfirmationModal(title, message, icon, iconColor, action) {
    ensureSharedModals();
    document.getElementById('bgConfirmTitle').textContent = title || 'Are you sure?';
    document.getElementById('bgConfirmBody').textContent = message || '';
    setTile(document.getElementById('bgConfirmTile'), icon || 'help-circle', iconColor);

    var okOld = document.getElementById('bgConfirmOk');
    var ok = okOld.cloneNode(true); // drop any previously bound handler
    okOld.parentNode.replaceChild(ok, okOld);
    ok.addEventListener('click', function () {
      closeModal('bgConfirmModal');
      if (typeof action === 'function') action();
    });

    openModal('bgConfirmModal');
  }

  function showNotificationModal(type, title, message) {
    ensureSharedModals();
    var map = {
      success: ['check-circle', '#00A331'],
      error:   ['alert-circle', '#C0392B'],
      warning: ['alert-triangle', '#A9660B'],
      info:    ['info', '#334E68']
    };
    var pair = map[type] || map.info;
    document.getElementById('bgNotifyTitle').textContent = title || '';
    document.getElementById('bgNotifyBody').textContent = message || '';
    setTile(document.getElementById('bgNotifyTile'), pair[0], pair[1]);
    openModal('bgNotifyModal');
  }

  function showImageModal(src, fileName) {
    ensureSharedModals();
    document.getElementById('bgImageTitle').textContent = fileName || 'Evidence';
    var img = document.getElementById('bgImageTarget');
    /* evidence paths are server-supplied; refuse anything but a plain URL */
    img.src = /^(https?:|\/)[^\s]*$/i.test(String(src || '')) ? src : '';
    img.alt = fileName || '';
    openModal('bgImageModal');
  }

  BG.showConfirmationModal = showConfirmationModal;
  BG.showNotificationModal = showNotificationModal;
  BG.showImageModal = showImageModal;

  /* --------------------------------------------------------- delegation -- */
  document.addEventListener('click', function (e) {
    /* open a modal */
    var opener = e.target.closest('[data-modal-open]');
    if (opener) {
      e.preventDefault();
      openModal(opener.getAttribute('data-modal-open'));
      return;
    }

    /* close a modal */
    var closer = e.target.closest('[data-modal-close]');
    if (closer) {
      e.preventDefault();
      var owner = closer.closest('.modal-backdrop');
      if (owner) closeModal(owner);
      return;
    }

    /* click on the backdrop itself (not the dialog) closes */
    if (e.target.classList && e.target.classList.contains('modal-backdrop')) {
      closeModal(e.target);
      return;
    }

    /* dismiss an alert */
    var dismiss = e.target.closest('[data-dismiss-alert]');
    if (dismiss) {
      e.preventDefault();
      var alert = dismiss.closest('.alert');
      if (alert) alert.remove();
      return;
    }

    /* toggle the user menu */
    var trigger = e.target.closest('[data-usermenu-toggle]');
    if (trigger) {
      e.preventDefault();
      var panel = document.getElementById('userMenuPanel');
      if (panel) {
        var isOpen = panel.classList.toggle('is-open');
        trigger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      }
      return;
    }

    /* toggle the mobile sidebar */
    var burger = e.target.closest('[data-sidebar-toggle]');
    if (burger) {
      e.preventDefault();
      var sb = document.querySelector('.sidebar');
      var scrim = document.querySelector('.scrim');
      if (sb) sb.classList.toggle('is-open');
      if (scrim) scrim.classList.toggle('is-open');
      return;
    }
    if (e.target.classList && e.target.classList.contains('scrim')) {
      document.querySelector('.sidebar').classList.remove('is-open');
      e.target.classList.remove('is-open');
      return;
    }

    /* click outside closes the user menu */
    var menu = document.getElementById('userMenuPanel');
    if (menu && menu.classList.contains('is-open') && !e.target.closest('.usermenu')) {
      menu.classList.remove('is-open');
    }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    if (openStack.length) { closeTopModal(); return; }
    var menu = document.getElementById('userMenuPanel');
    if (menu) menu.classList.remove('is-open');
    var sb = document.querySelector('.sidebar.is-open');
    if (sb) {
      sb.classList.remove('is-open');
      var scrim = document.querySelector('.scrim');
      if (scrim) scrim.classList.remove('is-open');
    }
  });

  /* -------------------------------------------------------------- misc --- */
  function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
  }

  function setButtonLoading(button, isLoading) {
    if (!button) return;
    if (isLoading) {
      button.disabled = true;
      button.dataset.originalHtml = button.innerHTML;
      button.textContent = 'Working…';
    } else {
      button.disabled = false;
      if (button.dataset.originalHtml) button.innerHTML = button.dataset.originalHtml;
      icons();
    }
  }

  BG.formatCurrency = formatCurrency;
  BG.setButtonLoading = setButtonLoading;

  /* ------------------------------------------------------------- init --- */
  document.addEventListener('DOMContentLoaded', function () {
    icons();
    ensureSharedModals();
    icons();

    /* auto-dismiss transient flash messages */
    document.querySelectorAll('.alert:not(.alert-permanent)').forEach(function (alert) {
      setTimeout(function () {
        alert.style.transition = 'opacity .3s';
        alert.style.opacity = '0';
        setTimeout(function () { alert.remove(); }, 300);
      }, 6000);
    });

    /* two-decimal normalisation on currency inputs */
    document.querySelectorAll('input[data-currency]').forEach(function (input) {
      input.addEventListener('blur', function () {
        var v = parseFloat(this.value);
        if (!isNaN(v)) this.value = v.toFixed(2);
      });
    });

    /* auto-growing textareas */
    document.querySelectorAll('textarea[data-auto-resize]').forEach(function (ta) {
      function resize() { ta.style.height = 'auto'; ta.style.height = ta.scrollHeight + 'px'; }
      ta.addEventListener('input', resize);
      resize();
    });

    /* smooth in-page anchors */
    document.querySelectorAll('a[href^="#"]').forEach(function (a) {
      a.addEventListener('click', function (e) {
        var href = this.getAttribute('href');
        if (!href || href === '#') return;
        var target = document.querySelector(href);
        if (!target) return;
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });

    /* preset buttons write into their paired input */
    document.querySelectorAll('[data-preset-target]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var input = document.querySelector(this.getAttribute('data-preset-target'));
        if (!input) return;
        input.value = this.getAttribute('data-preset-value') || this.textContent.replace(/[$,]/g, '').trim();
        input.dispatchEvent(new Event('input', { bubbles: true }));
        var group = this.parentNode;
        group.querySelectorAll('.preset').forEach(function (p) { p.classList.remove('is-active'); });
        this.classList.add('is-active');
      });
    });
  });

  /* legacy globals used by inline page scripts */
  window.BG = BG;
  window.showConfirmationModal = showConfirmationModal;
  window.showNotificationModal = showNotificationModal;
  window.showImageModal = showImageModal;
  window.BettingPlatform = {
    formatCurrency: formatCurrency,
    setButtonLoading: setButtonLoading,
    showToast: function (message, type) { showNotificationModal(type || 'info', '', message); }
  };
})();
