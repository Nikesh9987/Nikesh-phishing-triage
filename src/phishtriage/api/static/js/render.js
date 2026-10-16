/*
 * Report renderer.
 *
 *   window.PhishRender.show(data)   data = /api/analyze JSON ({summary, report, retention_seconds})
 *   window.PhishRender.clear()      empty every result section
 *
 * Safety rules:
 *   - Text is only ever assigned with textContent, never as HTML.
 *   - Control and direction-override characters are shown as \uXXXX.
 *   - Rows are cloned from the <template> elements in index.html.
 *   - Colours come from data-* attributes styled in app.css.
 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const results = $('results');
  if (!results) return;

  const MAX_IOC_ROWS = 1000;
  const MAX_RECIPIENTS = 5;
  const VERDICTS = {
    malicious: 'MALICIOUS',
    suspicious: 'SUSPICIOUS',
    low_risk: 'LOW RISK',
    clean: 'CLEAN (NO INDICATORS)',
  };
  const SEVERITY_WEIGHT = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const CONTROL_CHARS = /[\p{Cc}\p{Cf}]/gu;

  let state = { iocs: [], hashes: [] };

  // ------------------------------------------------------------------ helpers
  function safe(value, limit = 1000) {
    const text = String(value ?? '').replace(
      CONTROL_CHARS,
      (c) => `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`,
    );
    return text.length > limit ? `${text.slice(0, limit)}\u2026` : text;
  }

  function fmtBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  }

  function fmtDelay(seconds) {
    if (seconds === null || seconds === undefined) return '';
    const sign = seconds < 0 ? '-' : '+';
    const total = Math.floor(Math.abs(seconds));
    if (total < 60) return `${sign}${total}s`;
    if (total < 3600) return `${sign}${Math.floor(total / 60)}m ${total % 60}s`;
    if (total < 86400) return `${sign}${Math.floor(total / 3600)}h ${Math.floor((total % 3600) / 60)}m`;
    return `${sign}${Math.floor(total / 86400)}d ${Math.floor((total % 86400) / 3600)}h`;
  }

  function fmtDate(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return safe(value, 60);
    return `${date.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
  }

  function fmtAddress(addr) {
    if (!addr) return '';
    const name = addr.display_name || '';
    const mail = addr.address || '';
    return name && mail ? `${name} <${mail}>` : name || mail;
  }

  function fmtAddressList(list) {
    const items = Array.isArray(list) ? list.map(fmtAddress).filter(Boolean) : [];
    if (!items.length) return '(none)';
    const extra = items.length - MAX_RECIPIENTS;
    const shown = items.slice(0, MAX_RECIPIENTS).join(', ');
    return extra > 0 ? `${shown} (+${extra} more)` : shown;
  }

  function slot(root, name) {
    const node = root.querySelector(`[data-bind="${name}"]`);
    if (!node) throw new Error(`Template slot "${name}" is missing`);
    return node;
  }

  function setBind(name, value) {
    results.querySelectorAll(`[data-bind="${name}"]`).forEach((node) => {
      node.textContent = safe(value);
    });
  }

  function cloneTemplate(id) {
    const tpl = document.getElementById(id);
    if (!(tpl instanceof HTMLTemplateElement) || !tpl.content.firstElementChild) {
      throw new Error(`Template #${id} is missing`);
    }
    return tpl.content.firstElementChild.cloneNode(true);
  }

  function makeLi(text, className = '') {
    const li = document.createElement('li');
    if (className) li.className = className;
    li.textContent = safe(text, 600);
    return li;
  }

  function setSeverity(node, severity) {
    const known = Object.prototype.hasOwnProperty.call(SEVERITY_WEIGHT, severity) ? severity : 'info';
    node.dataset.severity = known;
    node.textContent = known.toUpperCase();
  }

  function setCopy(button, value) {
    if (value) {
      button.setAttribute('data-copy', value);
      button.hidden = false;
    } else {
      button.removeAttribute('data-copy');
      button.hidden = true;
    }
  }

  function intelSummary(list) {
    const items = Array.isArray(list) ? list : [];
    const flagged = items.filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious');
    if (flagged.length) {
      const text = flagged
        .map((r) => `${r.provider}: ${r.verdict}${r.score === null || r.score === undefined ? '' : ` (${r.score})`}`)
        .join('; ');
      return { text, state: flagged.some((r) => r.verdict === 'malicious') ? 'malicious' : 'suspicious' };
    }
    if (!items.length) return { text: '-', state: 'none' };
    if (items.some((r) => r.verdict === 'clean')) return { text: 'no detections', state: 'clean' };
    if (items.some((r) => r.verdict === 'unknown')) return { text: 'no data', state: 'unknown' };
    return { text: 'lookup failed', state: 'error' };
  }

  // ------------------------------------------------------------------ verdict
  function renderVerdict(report, summary, retention) {
    const card = $('verdict-card');
    const verdict = Object.prototype.hasOwnProperty.call(VERDICTS, report.verdict) ? report.verdict : 'clean';
    card.dataset.verdict = verdict;
    $('verdict-badge').textContent = VERDICTS[verdict];
    $('risk-score').textContent = String(report.risk_score);
    $('risk-meter').setAttribute('aria-valuenow', String(report.risk_score));
    $('risk-meter-fill').style.width = `${Math.max(0, Math.min(100, report.risk_score))}%`;
    $('verdict-note').hidden = !(verdict === 'clean' || verdict === 'low_risk');

    const msg = report.message;
    setBind('subject', msg.subject || '(none)');
    setBind('from', fmtAddress(msg.from_address) || '(none)');
    setBind('reply_to', fmtAddressList(msg.reply_to));
    setBind('return_path', msg.return_path || '(none)');
    setBind('to', fmtAddressList(msg.to));
    setBind('date', fmtDate(msg.date) || '(none)');
    setBind('message_id', msg.message_id || '(none)');
    setBind('file', `${report.filename || '(unnamed)'} (${fmtBytes(report.file_size)}, ${msg.source_format})`);
    setBind('file_sha256', report.file_sha256);
    setBind('from_domain', summary.from_domain || '(unknown)');

    const id = encodeURIComponent(report.report_id);
    $('download-report-link').href = `/api/report/${id}?download=true`;
    $('export-iocs-txt').href = `/api/export/iocs/${id}?format=text&download=true`;
    $('export-iocs-csv').href = `/api/export/iocs/${id}?format=csv&download=true`;

    $('report-id').textContent = report.report_id;
    $('retention-minutes').textContent = String(Math.max(1, Math.round((retention || 3600) / 60)));
    const used = (report.intel_providers_used || []).join(', ');
    $('intel-used').textContent = used || (report.offline ? 'offline' : 'none');
  }

  // ---------------------------------------------------------------- authentication
  function renderAuthCard(key, status, aligned, domain, detail) {
    const card = results.querySelector(`[data-auth="${key}"]`);
    if (!card) return;
    const role = (name) => card.querySelector(`[data-role="${name}"]`);
    const badge = role('badge');
    badge.dataset.status = status;
    badge.textContent = String(status).toUpperCase();
    const alignedEl = role('aligned');
    alignedEl.dataset.aligned = aligned === true ? 'true' : aligned === false ? 'false' : 'unknown';
    alignedEl.textContent = aligned === true ? 'aligned' : aligned === false ? 'NOT aligned' : '-';
    role('domain').textContent = safe(domain || '-', 120);
    role('detail').textContent = safe(detail || '', 400);
  }

  function renderAuth(report, summary) {
    const auth = report.authentication;
    const dkimDetail = auth.dkim.length
      ? auth.dkim
          .map(
            (r) =>
              `${r.selector ? `${r.selector}@` : ''}${r.domain || '?'}: ${r.status}${r.aligned === false ? ' (not aligned)' : ''}`,
          )
          .join('; ')
      : 'No DKIM signature found.';
    renderAuthCard('spf', summary.spf.status, summary.spf.aligned, summary.spf.domain, auth.spf.detail);
    renderAuthCard('dkim', summary.dkim.status, summary.dkim.aligned, summary.dkim.domain, dkimDetail);
    renderAuthCard('dmarc', summary.dmarc.status, summary.dmarc.aligned, summary.dmarc.domain, auth.dmarc.detail);

    const policyEl = $('dmarc-policy');
    const policy = auth.dmarc_policy;
    if (policy) {
      policyEl.textContent = safe(
        `Published DMARC policy (${policy.domain}): p=${policy.policy || 'unspecified'}, ` +
          `sp=${policy.subdomain_policy || 'inherit'}, pct=${policy.percentage}, ` +
          `aspf=${policy.spf_alignment}, adkim=${policy.dkim_alignment}`,
        400,
      );
      policyEl.hidden = false;
    } else {
      policyEl.textContent = '';
      policyEl.hidden = true;
    }
  }

  // ---------------------------------------------------------------------- findings
  function renderFindings(report) {
    const list = $('findings-list');
    const findings = report.findings || [];
    $('findings-count').textContent = `(${findings.length})`;
    $('findings-empty').hidden = findings.length > 0;
    list.replaceChildren(
      ...findings.map((finding) => {
        const item = cloneTemplate('tpl-finding');
        setSeverity(slot(item, 'severity'), finding.severity);
        slot(item, 'title').textContent = safe(finding.title, 300);
        slot(item, 'code').textContent = safe(finding.code, 100);
        const detail = slot(item, 'detail');
        detail.textContent = safe(finding.detail || '', 600);
        detail.hidden = !finding.detail;
        const evidence = slot(item, 'evidence');
        const lines = finding.evidence || [];
        evidence.replaceChildren(...lines.map((line) => makeLi(line)));
        evidence.hidden = lines.length === 0;
        return item;
      }),
    );
  }

  // --------------------------------------------------------------------- delivery path
  function renderPath(report) {
    const trace = report.received;
    const hops = trace.hops || [];
    const origin = trace.originating_mta;
    $('hops-count').textContent = `(${hops.length})`;
    $('hops-empty').hidden = hops.length > 0;

    const summary = $('origin-summary');
    if (hops.length) {
      const parts = [];
      if (origin) {
        const host = origin.hostname || origin.rdns || 'unknown host';
        parts.push(`Originating MTA: ${origin.ip} (${host}). ${origin.reason}`);
      } else {
        parts.push('No public originating IP could be identified.');
      }
      if (trace.total_delay_seconds !== null && trace.total_delay_seconds !== undefined) {
        parts.push(`Total transit time: ${fmtDelay(trace.total_delay_seconds).replace(/^\+/, '')}.`);
      }
      summary.textContent = safe(parts.join(' '), 900);
      summary.hidden = false;
    } else {
      summary.textContent = '';
      summary.hidden = true;
    }

    $('hops-list').replaceChildren(
      ...hops.map((hop) => {
        const item = cloneTemplate('tpl-hop');
        const isOrigin = Boolean(origin) && hop.index === origin.hop_index;
        item.dataset.origin = isOrigin ? 'true' : 'false';
        slot(item, 'index').textContent = `#${hop.index + 1}`;
        slot(item, 'from_host').textContent = safe(hop.from_host || '?', 300);
        slot(item, 'by_host').textContent = safe(hop.by_host || '?', 300);
        slot(item, 'origin_tag').hidden = !isOrigin;
        slot(item, 'delay').textContent = fmtDelay(hop.delay_seconds);
        slot(item, 'timestamp').textContent = fmtDate(hop.timestamp) || 'no usable timestamp';
        slot(item, 'protocol').textContent = hop.protocol ? `\u00b7 ${safe(hop.protocol, 80)}` : '';

        const ips = slot(item, 'ips');
        const ipLines = (hop.ips || []).map((ip) => {
          let line = `${ip.address} [${ip.scope}]`;
          if (ip.rdns) line += ` \u00b7 rDNS ${ip.rdns}`;
          else if (ip.rdns_error) line += ` \u00b7 rDNS: ${ip.rdns_error}`;
          return makeLi(line);
        });
        ips.replaceChildren(...ipLines);
        ips.hidden = ipLines.length === 0;

        const anomalies = slot(item, 'anomalies');
        const notes = (hop.anomalies || []).map((a) => makeLi(a));
        anomalies.replaceChildren(...notes);
        anomalies.hidden = notes.length === 0;
        return item;
      }),
    );
  }

  // ---------------------------------------------------------------------- indicators
  function iocRow(ioc) {
    const row = cloneTemplate('tpl-ioc-row');
    const defanged = safe(ioc.defanged, 4000);
    slot(row, 'type').textContent = ioc.type;
    slot(row, 'defanged').textContent = defanged;
    slot(row, 'count').textContent = String(ioc.count);
    slot(row, 'sources').textContent = (ioc.sources || []).join(', ');
    const intel = intelSummary(ioc.intel);
    const intelCell = slot(row, 'intel');
    intelCell.textContent = safe(intel.text, 300);
    intelCell.dataset.intel = intel.state;
    setCopy(slot(row, 'copy'), defanged);
    return row;
  }

  function renderIocs() {
    const filter = $('ioc-filter');
    const type = filter ? filter.value : '';
    const rows = state.iocs.filter((ioc) => !type || ioc.type === type);
    const shown = rows.slice(0, MAX_IOC_ROWS);

    $('iocs-body').replaceChildren(...shown.map(iocRow));
    $('iocs-count').textContent =
      rows.length > shown.length ? `(${rows.length}, showing the first ${shown.length})` : `(${rows.length})`;
    const empty = $('iocs-empty');
    empty.textContent = state.iocs.length ? 'No indicators of this type.' : 'No indicators extracted.';
    empty.hidden = rows.length > 0;
    $('iocs-table').hidden = rows.length === 0;

    const lines = rows.map((ioc) => safe(ioc.defanged, 4000));
    if (!type) lines.push(...state.hashes);
    $('copy-all-iocs').setAttribute('data-copy', [...new Set(lines.filter(Boolean))].join('\n'));
  }

  // ---------------------------------------------------------------------- attachments
  function attachmentSuspicion(att) {
    let worst = '';
    let weight = 1;
    for (const flag of att.flags || []) {
      const w = SEVERITY_WEIGHT[flag.severity] ?? 0;
      if (w >= 2 && w > weight) {
        weight = w;
        worst = flag.severity;
      }
    }
    if (!worst && (att.intel || []).some((r) => r.verdict === 'malicious')) worst = 'high';
    return worst;
  }

  function attachmentCard(att) {
    const card = cloneTemplate('tpl-attachment');
    slot(card, 'filename').textContent = safe(att.filename, 300);
    slot(card, 'detected').textContent = safe(att.detected_extension || '?', 20);
    slot(card, 'size').textContent = fmtBytes(att.size) + (att.skipped ? ' \u00b7 not inspected (too large)' : '');

    const suspicion = attachmentSuspicion(att);
    const badge = slot(card, 'suspicion');
    if (suspicion) {
      setSeverity(badge, suspicion);
      badge.textContent = 'SUSPICIOUS';
      badge.hidden = false;
    }

    const mime = [att.detected_mime || 'unknown type'];
    if (att.declared_content_type) mime.push(`declared: ${att.declared_content_type}`);
    slot(card, 'mime').textContent = safe(mime.join(' \u00b7 '), 300);

    const flags = slot(card, 'flags');
    const flagItems = (att.flags || []).map((flag) => {
      const li = document.createElement('li');
      li.className = 'flex flex-wrap items-start gap-2 text-xs';
      const sev = document.createElement('span');
      sev.className = 'sev-badge';
      setSeverity(sev, flag.severity);
      const code = document.createElement('span');
      code.className = 'font-mono text-slate-400';
      code.textContent = safe(flag.code, 80);
      const text = document.createElement('span');
      text.className = 'min-w-0 break-words text-slate-400';
      text.textContent = safe(flag.description, 600);
      li.append(sev, code, text);
      return li;
    });
    flags.replaceChildren(...flagItems);
    flags.hidden = flagItems.length === 0;

    const intel = intelSummary(att.intel);
    const intelEl = slot(card, 'intel');
    intelEl.textContent = intel.state === 'none' ? '' : `Threat intel: ${intel.text}`;
    intelEl.dataset.intel = intel.state;
    intelEl.hidden = intel.state === 'none';

    for (const [bind, button, value] of [
      ['sha256', 'copy_sha256', att.sha256],
      ['sha1', 'copy_sha1', att.sha1],
      ['md5', 'copy_md5', att.md5],
    ]) {
      slot(card, bind).textContent = value || '-';
      setCopy(slot(card, button), value);
    }
    return card;
  }

  function renderAttachments(report) {
    const list = report.attachments || [];
    $('attachments-count').textContent = `(${list.length})`;
    $('attachments-empty').hidden = list.length > 0;
    $('attachments-list').replaceChildren(...list.map(attachmentCard));
  }

  // ---------------------------------------------------------------------------- notes
  function renderNotes(report) {
    const sources = [
      ['report', report.warnings],
      ['received', report.received.warnings],
      ['authentication', report.authentication.warnings],
    ];
    const seen = new Set();
    const items = [];
    for (const [source, warnings] of sources) {
      for (const warning of warnings || []) {
        const line = `[${source}] ${safe(warning, 600)}`;
        if (!seen.has(line)) {
          seen.add(line);
          items.push(makeLi(line));
        }
      }
    }
    $('notes-card').hidden = items.length === 0;
    $('notes-count').textContent = items.length ? `(${items.length})` : '';
    $('notes-list').replaceChildren(...items);
  }

  // ------------------------------------------------------------------------ public API
  function clear() {
    state = { iocs: [], hashes: [] };
    results.querySelectorAll('[data-bind]').forEach((node) => {
      node.textContent = '';
    });
    ['findings-list', 'hops-list', 'iocs-body', 'attachments-list', 'notes-list'].forEach((id) =>
      $(id).replaceChildren(),
    );
    ['findings-count', 'hops-count', 'iocs-count', 'attachments-count', 'notes-count', 'report-id'].forEach(
      (id) => {
        $(id).textContent = '';
      },
    );
    ['origin-summary', 'dmarc-policy', 'notes-card', 'verdict-note'].forEach((id) => {
      $(id).hidden = true;
    });
    ['findings-empty', 'hops-empty', 'iocs-empty', 'attachments-empty'].forEach((id) => {
      $(id).hidden = true;
    });
    $('iocs-table').hidden = false;
    $('ioc-filter').value = '';
    $('copy-all-iocs').removeAttribute('data-copy');
    $('download-report-link').href = '#';
    $('export-iocs-txt').href = '#';
    $('export-iocs-csv').href = '#';
    $('verdict-card').dataset.verdict = 'clean';
    $('verdict-badge').textContent = '';
    $('risk-score').textContent = '0';
    $('risk-meter').setAttribute('aria-valuenow', '0');
    $('risk-meter-fill').style.width = '0%';
    for (const key of ['spf', 'dkim', 'dmarc']) renderAuthCard(key, 'unknown', null, '', '');
  }

  function show(data) {
    const { summary, report } = data;
    clear();
    state = {
      iocs: report.iocs || [],
      hashes: (report.attachments || []).map((a) => a.sha256).filter(Boolean),
    };
    renderVerdict(report, summary, data.retention_seconds);
    renderAuth(report, summary);
    renderFindings(report);
    renderPath(report);
    renderIocs();
    renderAttachments(report);
    renderNotes(report);
  }

  const filter = $('ioc-filter');
  if (filter) filter.addEventListener('change', renderIocs);

  window.PhishRender = Object.freeze({ show, clear });
})();