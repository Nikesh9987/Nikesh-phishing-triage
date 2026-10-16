/*
 * Upload flow: file selection (click or drag-and-drop), client-side checks,
 * the fetch to /api/analyze, loading state, error mapping, and the hand-off to
 * render.js.
 *
 * Contract with render.js:
 *   window.PhishRender.show(data)   data = the /api/analyze JSON ({summary, report, retention_seconds})
 *   window.PhishRender.clear()      empty every result section
 *
 * Client-side limits are a convenience only; the server enforces them again.
 * All server-provided text is shown with textContent.
 */
(() => {
  'use strict';

  const ANALYZE_URL = '/api/analyze';
  const REPORT_URL = '/api/report/';
  const REQUEST_TIMEOUT_MS = 170000; // the server gives up at 150 s and answers 504
  const SLOW_HINT_AFTER_S = 8;
  const MAX_HOPS = 100;
  const MAX_AUTHSERV_IDS = 10;
  const MAX_MESSAGE_CHARS = 600;

  const $ = (id) => document.getElementById(id);
  const app = $('app');
  const form = $('analyze-form');
  const input = $('file-input');
  if (!app || !form || !input) return;

  const el = {
    dropzone: $('dropzone'),
    chosen: $('file-chosen'),
    name: $('file-name'),
    size: $('file-size'),
    clear: $('clear-file-btn'),
    analyze: $('analyze-btn'),
    loading: $('status-loading'),
    loadingText: $('status-loading-text'),
    errBox: $('error-banner'),
    errTitle: $('error-title'),
    errMsg: $('error-message'),
    results: $('results'),
    hops: $('opt-trusted-hops'),
    authserv: $('opt-trusted-authserv'),
    enrich: $('opt-enrich'),
    macros: $('opt-macros'),
    newBtn: $('new-analysis-btn'),
    deleteBtn: $('delete-report-btn'),
  };
  if (Object.values(el).some((node) => !node)) {
    console.error('Phishing Triage: the dashboard markup is incomplete.');
    return;
  }

  const maxBytes = Number.parseInt(app.dataset.maxBytes || '', 10) || 25 * 1024 * 1024;
  const extensions = (app.dataset.extensions || '.eml,.msg')
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);
  const offline = app.dataset.offline === 'true';
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let selectedFile = null;
  let busy = false;
  let reportId = null;
  let controller = null;

  // ------------------------------------------------------------------ helpers
  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  }

  function extensionOf(name) {
    const dot = name.lastIndexOf('.');
    return dot > 0 ? name.slice(dot).toLowerCase() : '';
  }

  function parseJson(text) {
    try {
      const value = JSON.parse(text);
      return value !== null && typeof value === 'object' ? value : null;
    } catch (_) {
      return null; // empty body, or an HTML error page from a proxy
    }
  }

  function toast(message, isError = false) {
    if (window.PhishClipboard) window.PhishClipboard.toast(message, isError);
  }

  function showError(title, message) {
    el.errTitle.textContent = title;
    el.errMsg.textContent = String(message || '').slice(0, MAX_MESSAGE_CHARS);
    el.errBox.hidden = false;
    el.errBox.scrollIntoView({ block: 'nearest', behavior: reduceMotion ? 'auto' : 'smooth' });
  }

  function hideError() {
    el.errBox.hidden = true;
    el.errTitle.textContent = '';
    el.errMsg.textContent = '';
  }

  function render() {
    return window.PhishRender && typeof window.PhishRender.show === 'function' ? window.PhishRender : null;
  }

  // ---------------------------------------------------------- file selection
  function validate(file) {
    if (file.size === 0) return 'The file is empty.';
    if (file.size > maxBytes) {
      return `The file is ${formatBytes(file.size)}; the limit is ${formatBytes(maxBytes)}.`;
    }
    const ext = extensionOf(file.name);
    if (!extensions.includes(ext)) {
      return `Only ${extensions.join(', ')} files are accepted${ext ? ` (this one is ${ext})` : ''}.`;
    }
    return '';
  }

  function updateButton() {
    el.analyze.disabled = busy || selectedFile === null;
  }

  function clearSelection() {
    selectedFile = null;
    input.value = '';
    el.chosen.hidden = true;
    el.name.textContent = '';
    el.size.textContent = '';
    updateButton();
  }

  function setFile(file) {
    hideError();
    const problem = validate(file);
    if (problem) {
      clearSelection();
      showError('This file cannot be analyzed', problem);
      return;
    }
    selectedFile = file;
    el.name.textContent = file.name;
    el.size.textContent = `(${formatBytes(file.size)})`;
    el.chosen.hidden = false;
    updateButton();
  }

  function handleFiles(list) {
    if (busy || !list || list.length === 0) return;
    if (list.length > 1) toast('Only one file at a time: using the first one.');
    setFile(list[0]);
  }

  input.addEventListener('change', () => handleFiles(input.files));
  el.clear.addEventListener('click', () => {
    hideError();
    clearSelection();
  });

  // ----------------------------------------------------------- drag and drop
  let dragDepth = 0;
  const hasFiles = (event) =>
    Boolean(event.dataTransfer) && Array.from(event.dataTransfer.types || []).includes('Files');

  function setDragging(on) {
    el.dropzone.dataset.dragover = on ? 'true' : 'false';
    el.dropzone.classList.toggle('border-emerald-500', on);
    el.dropzone.classList.toggle('bg-emerald-500/5', on);
  }

  el.dropzone.addEventListener('dragenter', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    dragDepth += 1;
    setDragging(true);
  });
  el.dropzone.addEventListener('dragover', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = busy ? 'none' : 'copy';
  });
  el.dropzone.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) setDragging(false);
  });
  el.dropzone.addEventListener('drop', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    dragDepth = 0;
    setDragging(false);
    handleFiles(event.dataTransfer.files);
  });
  // A file dropped anywhere else would make the browser open the email as a page.
  ['dragover', 'drop'].forEach((type) =>
    window.addEventListener(type, (event) => {
      if (hasFiles(event) && !el.dropzone.contains(event.target)) {
        event.preventDefault();
        if (event.dataTransfer) event.dataTransfer.dropEffect = 'none';
      }
    }),
  );

  // ----------------------------------------------------------------- options
  function readOptions() {
    const hops = el.hops.value.trim();
    if (hops) {
      const n = /^\d+$/.test(hops) ? Number.parseInt(hops, 10) : NaN;
      if (!Number.isInteger(n) || n < 1 || n > MAX_HOPS) {
        el.hops.focus();
        throw new Error(`Trusted hops must be a whole number between 1 and ${MAX_HOPS}.`);
      }
    }
    const authserv = el.authserv.value.trim();
    const ids = authserv.split(',').filter((part) => part.trim());
    if (ids.length > MAX_AUTHSERV_IDS) {
      el.authserv.focus();
      throw new Error(`Give at most ${MAX_AUTHSERV_IDS} trusted authserv-ids.`);
    }
    return { hops, authserv };
  }

  function buildForm(options) {
    const data = new FormData();
    data.append('file', selectedFile, selectedFile.name);
    if (options.hops) data.append('trusted_hops', options.hops);
    if (options.authserv) data.append('trusted_authserv', options.authserv);
    // Unchecked boxes are not submitted and the API defaults to true, so send both states.
    data.append('enrich', String(!offline && el.enrich.checked));
    data.append('scan_macros', String(el.macros.checked));
    return data;
  }

  // ------------------------------------------------------------ busy / ticker
  function setBusy(on) {
    busy = on;
    input.disabled = on;
    el.clear.disabled = on;
    el.loading.hidden = !on;
    el.dropzone.classList.toggle('opacity-60', on);
    el.dropzone.classList.toggle('pointer-events-none', on);
    form.setAttribute('aria-busy', String(on));
    updateButton();
  }

  function startTicker() {
    const started = Date.now();
    const tick = () => {
      const seconds = Math.floor((Date.now() - started) / 1000);
      const hint = !offline && seconds >= SLOW_HINT_AFTER_S ? ' (threat-intelligence lookups can take up to a minute)' : '';
      el.loadingText.textContent = `Analyzing\u2026 ${seconds}s${hint}`;
    };
    tick();
    return setInterval(tick, 1000);
  }

  // -------------------------------------------------------------- error text
  function describeError(status, body, response) {
    const code = body && typeof body.error === 'string' ? body.error : '';
    let message = body && typeof body.message === 'string' ? body.message : '';
    const problems =
      body && body.details && Array.isArray(body.details.errors)
        ? body.details.errors.filter((p) => p && typeof p === 'object')
        : [];
    if (problems.length) {
      message += ` ${problems.map((p) => `${p.field}: ${p.problem}`).join('; ')}`;
    }

    let title = 'The analysis failed';
    if (status === 413) title = 'File too large';
    else if (status === 415) title = 'Unsupported file';
    else if (status === 429) {
      title = 'Too many requests';
      const wait = Number.parseInt(response.headers.get('Retry-After') || '', 10);
      if (Number.isFinite(wait) && wait > 0) message += ` Try again in about ${wait} seconds.`;
    } else if (status === 504) title = 'Analysis timed out';
    else if (code === 'parse_error' || code === 'malformed_message') title = 'The message could not be parsed';
    else if (status === 400 || status === 422) title = 'Invalid request';
    else if (status >= 500) title = 'Server error';

    return { title, message: message.trim() || `The server answered with HTTP ${status}.` };
  }

  function validBundle(data) {
    return Boolean(
      data &&
        data.summary &&
        data.report &&
        typeof data.report === 'object' &&
        typeof data.report.report_id === 'string',
    );
  }

  // ------------------------------------------------------------------ submit
  function showResults(data) {
    const renderer = render();
    if (!renderer) {
      showError('The dashboard script is missing', 'render.js did not load, so the report cannot be displayed. Check the browser console.');
      return;
    }
    try {
      renderer.show(data);
    } catch (error) {
      console.error('Phishing Triage: rendering failed', error);
      showError('The report could not be displayed', 'The analysis finished, but the dashboard failed to draw it. Try again, or use the command-line tool or API.');
      return;
    }
    reportId = data.report.report_id;
    el.results.hidden = false;
    el.results.setAttribute('tabindex', '-1');
    el.results.focus({ preventScroll: true });
    el.results.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
  }

  function discardResults() {
    reportId = null;
    el.results.hidden = true;
    const renderer = window.PhishRender;
    if (renderer && typeof renderer.clear === 'function') {
      try {
        renderer.clear();
      } catch (error) {
        console.error('Phishing Triage: clearing results failed', error);
      }
    }
  }

  async function onSubmit(event) {
    event.preventDefault();
    if (busy) return;
    if (!selectedFile) {
      showError('No file selected', `Choose or drop a ${extensions.join(' or ')} file first.`);
      return;
    }
    const problem = validate(selectedFile);
    if (problem) {
      showError('This file cannot be analyzed', problem);
      return;
    }
    let options;
    try {
      options = readOptions();
    } catch (error) {
      showError('Invalid option', error.message);
      return;
    }

    hideError();
    discardResults();
    let timedOut = false;
    controller = new AbortController();
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, REQUEST_TIMEOUT_MS);
    setBusy(true);
    const ticker = startTicker();

    try {
      const response = await fetch(ANALYZE_URL, {
        method: 'POST',
        body: buildForm(options),
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
        signal: controller.signal,
      });
      const body = parseJson(await response.text());
      if (!response.ok) {
        const info = describeError(response.status, body, response);
        showError(info.title, info.message);
        return;
      }
      if (!validBundle(body)) {
        showError('Unexpected response', 'The server answered, but the reply was not a valid report.');
        return;
      }
      showResults(body);
    } catch (error) {
      if (timedOut) {
        showError('Analysis timed out', 'No answer arrived in time. Try again with threat-intelligence lookups switched off.');
      } else if (!(error && error.name === 'AbortError')) {
        showError('Could not reach the server', 'Check your connection and that the service is running, then try again.');
      }
    } finally {
      clearTimeout(timeout);
      clearInterval(ticker);
      controller = null;
      setBusy(false);
    }
  }

  form.addEventListener('submit', onSubmit);

  // ------------------------------------------------- new analysis and delete
  function resetAll() {
    discardResults();
    hideError();
    clearSelection();
    window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
    input.focus({ preventScroll: true });
  }

  el.newBtn.addEventListener('click', resetAll);

  el.deleteBtn.addEventListener('click', async () => {
    if (!reportId || busy) return;
    if (!window.confirm('Delete this report from server memory now? It cannot be reopened afterwards.')) return;
    el.deleteBtn.disabled = true;
    try {
      const response = await fetch(REPORT_URL + encodeURIComponent(reportId), {
        method: 'DELETE',
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
      });
      if (response.status === 204 || response.status === 404) {
        resetAll();
        toast(response.status === 204 ? 'Report deleted' : 'The report had already expired');
        return;
      }
      const info = describeError(response.status, parseJson(await response.text()), response);
      showError('The report could not be deleted', info.message);
    } catch (_) {
      showError('Could not reach the server', 'The report was not deleted. It will expire on its own.');
    } finally {
      el.deleteBtn.disabled = false;
    }
  });

  window.addEventListener('pagehide', () => {
    if (controller) controller.abort();
  });

  // Firefox restores a previously chosen file after back/forward navigation.
  if (input.files && input.files.length > 0) handleFiles(input.files);
  updateButton();
})();