/*
 * Clipboard helper and toast.
 *
 *   <button class="copy-btn" data-copy="literal text">Copy</button>
 *   <button class="copy-btn" data-copy-from="#some-element">Copy</button>
 *
 * One delegated listener handles every copy button, including ones added later
 * by render.js. Works on plain-HTTP origins (internal SOC hosts) through a
 * textarea fallback, because navigator.clipboard needs a secure context.
 *
 * Exposes window.PhishClipboard = { copy(text) -> Promise<boolean>, toast(message, isError) }.
 * Text is only ever written with textContent / value, never as HTML.
 */
(() => {
  'use strict';

  const TOAST_MS = 2200;
  const FEEDBACK_MS = 1400;
  let toastTimer = null;

  function toast(message, isError = false) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = String(message);
    el.classList.toggle('border-red-500', Boolean(isError));
    el.classList.toggle('border-slate-700', !isError);
    el.classList.remove('opacity-0');
    el.classList.add('opacity-100');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      el.classList.remove('opacity-100');
      el.classList.add('opacity-0');
    }, TOAST_MS);
  }

  function legacyCopy(text) {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.setAttribute('aria-hidden', 'true');
    area.style.cssText = 'position:fixed;top:0;left:-9999px;opacity:0;';
    const previous = document.activeElement;
    document.body.appendChild(area);
    area.focus();
    area.select();
    area.setSelectionRange(0, text.length);
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch (_) {
      ok = false;
    }
    area.remove();
    if (previous && typeof previous.focus === 'function') previous.focus();
    return ok;
  }

  async function copy(text) {
    const value = String(text ?? '');
    if (!value) return false;
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(value);
        return true;
      } catch (_) {
        /* permission denied or unfocused document: use the fallback */
      }
    }
    return legacyCopy(value);
  }

  function resolveText(button) {
    if (button.hasAttribute('data-copy')) return button.getAttribute('data-copy') || '';
    const selector = button.getAttribute('data-copy-from');
    if (!selector) return '';
    try {
      const source = document.querySelector(selector);
      return source ? (source.textContent || '').trim() : '';
    } catch (_) {
      return ''; // invalid selector
    }
  }

  function flash(button, label) {
    if (!(button instanceof HTMLButtonElement)) return;
    if (!button.dataset.label) button.dataset.label = button.textContent || 'Copy';
    button.textContent = label;
    clearTimeout(Number(button.dataset.timer));
    button.dataset.timer = String(
      setTimeout(() => {
        button.textContent = button.dataset.label || 'Copy';
      }, FEEDBACK_MS),
    );
  }

  document.addEventListener('click', async (event) => {
    const origin = event.target instanceof Element ? event.target : null;
    const button = origin ? origin.closest('[data-copy], [data-copy-from]') : null;
    if (!button) return;
    event.preventDefault();

    const text = resolveText(button);
    if (!text) {
      toast('Nothing to copy', true);
      return;
    }
    const ok = await copy(text);
    flash(button, ok ? 'Copied' : 'Failed');
    toast(ok ? 'Copied to clipboard' : 'Copy failed: select the text and press Ctrl+C', !ok);
  });

  window.PhishClipboard = Object.freeze({ copy, toast });
})();