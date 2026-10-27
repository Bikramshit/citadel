/*
 * Citadel dashboard.
 *
 * Every value that comes from the server (event fields, run metadata, the
 * generated tables) is rendered as text through textContent or as an
 * attribute value. Nothing is parsed as markup and no code is built at
 * runtime. Attacker text from logs reaches events, so control and
 * bidirectional-override characters are shown escaped, and long strings are
 * clipped with the full text in a title attribute.
 *
 * The page shows only what the runtime recorded and what the harness
 * measured. When data is missing, the panel says so.
 */
(function () {
  'use strict';

  // ------------------------------------------------------------------
  // Constants
  // ------------------------------------------------------------------

  const CONFIGS = ['C0', 'C1-instr', 'C1-data', 'C2'];
  const POLL_MS = 2000;
  const LIVE_MAX_EVENTS = 20000;
  const READ_TOOLS = new Set(['logs', 'inventory']);
  const VERDICTS = new Set(['allow', 'escalate', 'deny']);
  const EVIDENCE_VERDICTS = new Set(['absent', 'insufficient', 'corroborated', 'conflict']);
  const ATTEMPT_STATES = new Set(['attempted', 'succeeded', 'failed', 'uncertain']);
  const VERDICT_MARK = { allow: '\u2713', escalate: '!', deny: '\u2715', unknown: '?' };
  const UNCERTAIN_TEXT = 'executed; runtime outcome unconfirmed';
  const RUN_KINDS = new Set(['run_start', 'run_end', 'run_abort', 'plan_rejected', 'handoff_reject']);
  const NO_RUNS = 'No recorded runs: /api/runs returned no run directories. Record runs into runs/ ' +
    '(citadel harness, or make m1), then reload this page; or switch to Live and start a run.';

  const $ = (id) => document.getElementById(id);
  // The SVG namespace is read from the static <svg> element in index.html.
  const SVG_NS = $('attack-svg').namespaceURI;

  // ------------------------------------------------------------------
  // Text safety and DOM helpers
  // ------------------------------------------------------------------

  // Control, zero-width, and bidirectional formatting characters, plus the
  // Unicode tag block: shown as visible escapes instead of being rendered.
  const UNSAFE_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u00ad\u061C\u115f\u1160\u180e\u200b-\u200F\u2028-\u202E\u2060-\u206f\ufeff\ufff9-\ufffb\u{e0000}-\u{e007f}]/gu;
  const WS_CHARS = /[\t\n\r]+/g;

  function str(v) {
    return v === null || v === undefined ? '' : String(v);
  }

  function visible(v) {
    return str(v)
      .replace(WS_CHARS, ' ')
      .replace(UNSAFE_CHARS, (c) => '\\u{' + c.codePointAt(0).toString(16) + '}');
  }

  function clipText(v, max) {
    const full = visible(v);
    if (!max) return { text: full, full, clipped: false };
    const cps = Array.from(full);
    if (cps.length <= max) return { text: full, full, clipped: false };
    return { text: cps.slice(0, Math.max(1, max - 1)).join('') + '\u2026', full, clipped: true };
  }

  function arr(v) {
    return Array.isArray(v) ? v : [];
  }

  function isObj(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  function setProps(n, props) {
    if (!props) return;
    for (const k of Object.keys(props)) {
      const v = props[k];
      if (v === null || v === undefined || v === false) continue;
      switch (k) {
        case 'class':
          n.setAttribute('class', v);
          break;
        case 'text':
          n.textContent = visible(v);
          break;
        case 'title':
          n.setAttribute('title', visible(v));
          break;
        case 'on':
          for (const ev of Object.keys(v)) n.addEventListener(ev, v[ev]);
          break;
        case 'hidden':
        case 'disabled':
          n[k] = true;
          break;
        default:
          n.setAttribute(k, v === true ? '' : String(v));
      }
    }
  }

  function addKids(n, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k === null || k === undefined || k === false || k === '') continue;
      n.appendChild(typeof k === 'object' && k.nodeType ? k : document.createTextNode(visible(k)));
    }
  }

  function h(tag, props, ...kids) {
    const n = document.createElement(tag);
    setProps(n, props);
    addKids(n, kids);
    return n;
  }

  function sv(tag, props, ...kids) {
    const n = document.createElementNS(SVG_NS, tag);
    setProps(n, props);
    addKids(n, kids);
    return n;
  }

  // clipped renders a string clipped to max characters, full text in title.
  function clipped(v, max, cls) {
    const c = clipText(v, max);
    return h('span', { class: cls ? 'clip ' + cls : 'clip', title: c.full }, c.text);
  }

  function muted(text, title) {
    return h('span', { class: 'muted', title: title || null }, text);
  }

  function emptyState(text) {
    return h('p', { class: 'empty' }, text);
  }

  function errorState(text) {
    return h('p', { class: 'error', role: 'alert' }, text);
  }

  function errMsg(err) {
    return err && err.message ? err.message : str(err);
  }

  function status(msg, isError) {
    const el = $('status');
    el.textContent = visible(msg);
    el.classList.toggle('is-error', !!isError);
  }

  function uniq(xs) {
    return [...new Set(xs)];
  }

  function num(v, digits) {
    if (v === null || v === undefined || v === '') return '\u2014';
    const n = Number(v);
    if (!Number.isFinite(n)) return '\u2014';
    return digits === undefined ? String(n) : n.toFixed(digits);
  }

  function yesNo(b) {
    return b === true ? 'yes' : b === false ? 'no' : '\u2014';
  }

  // ------------------------------------------------------------------
  // Event helpers
  // ------------------------------------------------------------------

  function opName(op) {
    return isObj(op) && (op.tool || op.action) ? str(op.tool) + '.' + str(op.action) : '';
  }

  function sameOp(a, b) {
    return isObj(a) && isObj(b) && a.tool === b.tool && a.action === b.action;
  }

  function isHandoffOp(op) {
    return isObj(op) && op.tool === 'handoff';
  }

  function isStateChanging(op) {
    return isObj(op) && !READ_TOOLS.has(op.tool) && op.tool !== 'handoff';
  }

  // The last element of decisions is the final verdict.
  function finalOf(e) {
    const d = arr(e && e.decisions);
    return d.length ? d[d.length - 1] : null;
  }

  // Every applicable rule. plan_rejected events list violations only.
  function rulesOf(e) {
    const d = arr(e && e.decisions);
    return e.kind === 'plan_rejected' ? d : d.slice(0, -1);
  }

  function verdictOf(d) {
    return isObj(d) && VERDICTS.has(d.verdict) ? d.verdict : 'unknown';
  }

  function diffKey(tool, action, target) {
    return str(tool) + '.' + str(action) + ' ' + str(target);
  }

  // Trusted sources: task_param:*, user_note, planner_literal:*, runtime,
  // tool:inventory.read. Everything else is untrusted.
  function sourceTrusted(src) {
    const v = str(src);
    return v === 'user_note' || v === 'runtime' || v === 'tool:inventory.read' ||
      v === 'task_param' || v.startsWith('task_param:') ||
      v === 'planner_literal' || v.startsWith('planner_literal:');
  }

  function isBaseSource(src) {
    const v = str(src);
    return v !== '' && !v.startsWith('peer:') && !v.startsWith('claimed:');
  }

  function logDerived(sources) {
    return arr(sources).some((x) => x === 'tool:logs.read' || x === 'claimed:tool:logs.read');
  }

  // analyze matches attempt events to the decisions that admitted them: same
  // agent, same operation, same target (an empty attempt target, as for
  // logs.read, matches on the operation), and the most recent admitted
  // decision not yet matched. Only decisions whose final verdict is allow can
  // own an attempt; a denied duplicate never inherits another call's outcome.
  // Later attempt events with the same key update the state.
  function analyze(events) {
    const outcome = new Map();
    const byKey = new Map();
    const open = [];
    const orphans = [];
    for (const e of arr(events)) {
      if (!isObj(e)) continue;
      if (e.kind === 'decision' && isObj(e.op) && !isHandoffOp(e.op) && verdictOf(finalOf(e)) === 'allow') {
        open.push(e);
      } else if (e.kind === 'attempt' && isObj(e.attempt)) {
        const a = e.attempt;
        const key = str(a.key);
        let d = key ? byKey.get(key) : undefined;
        if (!d) {
          const op = isObj(a.op) ? a.op : e.op;
          const target = str(a.target) || str(e.target);
          for (let i = open.length - 1; i >= 0; i--) {
            const c = open[i];
            if (c.agent === e.agent && sameOp(c.op, op) && (target === '' || str(c.target) === target)) {
              d = c;
              open.splice(i, 1);
              break;
            }
          }
          if (d && key) byKey.set(key, d);
        }
        if (d) outcome.set(d, a);
        else orphans.push(e);
      }
    }
    return { outcome, orphans };
  }

  // handoffOutcomes maps "to/task" to the handoff's recorded state.
  function handoffOutcomes(events) {
    const m = new Map();
    const rejects = [];
    for (const e of arr(events)) {
      if (!isObj(e) || !isObj(e.handoff)) continue;
      const hi = e.handoff;
      const k = str(hi.to) + '/' + str(hi.task);
      if (e.kind === 'handoff_accept') m.set(k, { state: 'accepted', detail: str(e.detail) });
      else if (e.kind === 'handoff_send' && !m.has(k)) m.set(k, { state: 'sent', detail: str(hi.status) });
      else if (e.kind === 'handoff_reject') rejects.push(e);
    }
    return { get: (k) => m.get(k) || (rejects.length ? { state: 'rejected', detail: rejects.map((r) => str(r.code) + ' ' + str(r.detail)).join('; ') } : null) };
  }

  // ------------------------------------------------------------------
  // Chips and badges
  // ------------------------------------------------------------------

  function sourceChip(src) {
    const t = sourceTrusted(src);
    const c = clipText(src, 40);
    return h('span', { class: 'chip ' + (t ? 'trusted' : 'untrusted'), title: c.full + (t ? ' (trusted source)' : ' (untrusted source)') },
      c.text, h('span', { class: 'visually-hidden' }, t ? ' (trusted)' : ' (untrusted)'));
  }

  function sourceChips(list) {
    const l = arr(list);
    if (!l.length) return muted('none recorded');
    return h('div', { class: 'chips' }, l.map(sourceChip));
  }

  function trustBadge(trusted, what) {
    return h('span', { class: 'trust ' + (trusted ? 'trusted' : 'untrusted') }, (what ? what + ' ' : '') + (trusted ? 'trusted' : 'untrusted'));
  }

  function ruleChip(d) {
    const v = verdictOf(d);
    const rule = str(isObj(d) ? d.rule : '') || '?';
    const tip = rule + (isObj(d) && d.group ? ' (group ' + str(d.group) + ')' : '') + ': ' + v + (isObj(d) && d.reason ? ' \u2014 ' + str(d.reason) : '');
    return h('span', { class: 'chip v-' + v, title: tip }, VERDICT_MARK[v] + ' ' + clipText(rule, 12).text,
      h('span', { class: 'visually-hidden' }, ' ' + v));
  }

  function verdictBadge(d, label) {
    const v = verdictOf(d);
    const sub = isObj(d) ? str(d.rule) + (d.reason ? ' \u00b7 ' + str(d.reason) : '') : '';
    return h('div', null,
      h('span', { class: 'badge v-' + v }, VERDICT_MARK[v] + ' ' + (label || v)),
      sub ? clipped(sub, 70, 'badge-sub') : null);
  }

  function evidenceBlock(c, op) {
    if (!isObj(c)) return muted('none recorded');
    const v = EVIDENCE_VERDICTS.has(c.verdict) ? c.verdict : 'unknown';
    const lines = [num(c.observations) + ' observations, ' + num(c.flows) + ' established flows'];
    if ((isObj(op) && op.tool === 'accounts') || Number(c.success_logins) > 0) lines.push(num(c.success_logins) + ' trusted successful logins');
    const sensors = arr(c.sensors);
    lines.push('sensors: ' + (sensors.length ? sensors.join(', ') : 'none'));
    lines.push('thresholds: k=' + num(c.k) + ', min_flows=' + num(c.min_flows));
    if (c.conflict) lines.push('conflict: ' + str(c.conflict));
    return h('div', { class: 'evidence' },
      h('span', { class: 'chip ev ev-' + v }, str(c.verdict) || 'unknown'),
      lines.map((l) => clipped(l, 70, 'ev-line')));
  }

  function attemptLabel(state) {
    if (state === 'uncertain') return UNCERTAIN_TEXT;
    if (state === 'attempted') return 'attempted; not settled';
    return state;
  }

  function outcomeCell(e, a, hs) {
    if (e.kind === 'plan_rejected') return muted('no call');
    if (isHandoffOp(e.op)) {
      const st = hs.get(str(e.target));
      return st ? h('span', { class: 'outcome', title: st.detail }, 'handoff ' + st.state) : muted('no handoff event');
    }
    if (!a) {
      return verdictOf(finalOf(e)) === 'allow'
        ? muted('no attempt recorded', 'No attempt event matched this admitted call.')
        : muted('no attempt', 'No attempt event: the call was not admitted.');
    }
    const state = ATTEMPT_STATES.has(a.state) ? a.state : 'unknown';
    const extra = [];
    if (a.reconciled) extra.push('reconciled by lookup');
    if (a.detail) extra.push(str(a.detail));
    return h('div', null,
      h('span', { class: 'outcome o-' + state, title: 'attempt state: ' + str(a.state) + (a.key ? ' \u00b7 idempotency key ' + str(a.key) : '') }, attemptLabel(state)),
      extra.length ? clipped(extra.join('; '), 60, 'outcome-detail') : null);
  }

  // ------------------------------------------------------------------
  // Server API
  // ------------------------------------------------------------------

  async function errorCode(r) {
    try {
      const j = await r.json();
      return isObj(j) && j.error ? ' ' + str(j.error) : '';
    } catch (_) {
      return '';
    }
  }

  async function getJSON(url) {
    const r = await fetch(url, { headers: { Accept: 'application/json' }, cache: 'no-store', credentials: 'same-origin' });
    if (!r.ok) throw new Error('GET ' + url + ': HTTP ' + r.status + (await errorCode(r)));
    return r.json();
  }

  async function postJSON(url, body, token) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Citadel-Token': token || '' },
      body: JSON.stringify(body),
      cache: 'no-store',
      credentials: 'same-origin',
    });
    let j = null;
    try {
      j = await r.json();
    } catch (_) {
      j = null;
    }
    return { ok: r.ok, status: r.status, body: j };
  }

  // A run ID such as "20261027T101500Z/C2/B1/trial-1", escaped per segment.
  function runURL(id) {
    return '/api/runs/' + str(id).split('/').map(encodeURIComponent).join('/');
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  const S = {
    mode: 'replay',
    dirs: null,
    dirsError: null,
    fixtures: [],
    fixturesError: null,
    approvals: { principal: '', token: '', pending: [], error: null, loaded: false, inflight: false, busy: new Set(), log: [], sig: '' },
    replay: { dir: '', config: '', fixture: '', trial: '', summary: null, events: null, loading: false, error: null, seq: 0 },
    live: { es: null, conn: 'idle', items: [], runIds: [], info: new Map(), selected: '', fixture: '', config: '', starting: false, dropped: 0, bad: 0 },
    results: { dir: '' },
    compare: { dir: '', fixture: '', trial: '', cache: new Map(), seq: 0 },
  };

  function dirObj(name) {
    return (S.dirs || []).find((d) => str(d.dir) === name) || null;
  }

  function runsOf(dir) {
    const d = dirObj(dir);
    return d ? d.runs : [];
  }

  function fixtureRank(id) {
    let m;
    if (id === 'M1') return [0, 0];
    if ((m = /^B(\d+)$/.exec(id))) return [1, Number(m[1])];
    if (/^A-/.test(id)) return [2, 0];
    return [3, 0];
  }

  function sortFixtureIds(ids) {
    return ids.slice().sort((a, b) => {
      const ra = fixtureRank(a);
      const rb = fixtureRank(b);
      return ra[0] - rb[0] || ra[1] - rb[1] || a.localeCompare(b);
    });
  }

  function orderConfigs(cs) {
    const known = CONFIGS.filter((c) => cs.includes(c));
    return known.concat(cs.filter((c) => !CONFIGS.includes(c)).sort());
  }

  function fixtureInfo(id) {
    return S.fixtures.find((f) => str(f.id) === id) || null;
  }

  function fixtureLabelFromRuns(id, runs) {
    const r = runs.find((x) => str(x.fixture) === id);
    if (!r) return id;
    const bits = [str(r.kind), str(r.goal), str(r.style)].filter(Boolean);
    return bits.length ? id + ' \u00b7 ' + bits.join(' ') : id;
  }

  function setOptions(sel, opts, want) {
    sel.replaceChildren(...opts.map((o) => h('option', { value: o.value, title: o.title || null }, o.label)));
    const values = opts.map((o) => o.value);
    const v = values.includes(want) ? want : values.length ? values[0] : '';
    sel.value = v;
    sel.disabled = opts.length === 0;
    return v;
  }

  function dirOptions() {
    return (S.dirs || []).map((d) => ({ value: str(d.dir), label: str(d.dir) }));
  }

  // ------------------------------------------------------------------
  // Current view: the events the event panels show
  // ------------------------------------------------------------------

  function liveRunId() {
    return S.live.selected || S.live.runIds[S.live.runIds.length - 1] || '';
  }

  function liveItems(run) {
    return S.live.items.filter((it) => it.run === run);
  }

  function currentView() {
    if (S.mode === 'live') {
      const run = liveRunId();
      if (!run) {
        const msg = S.live.conn === 'open'
          ? 'Connected to /events. No events received yet; start a run above.'
          : 'Not receiving events from /events (' + S.live.conn + '). The stream reconnects automatically.';
        return { message: msg, kind: 'empty', live: true };
      }
      const items = liveItems(run);
      return { events: items.map((it) => it.e), inferred: items.filter((it) => it.inferred).length, live: true, run };
    }
    if (S.dirsError) return { message: 'Could not load /api/runs: ' + S.dirsError, kind: 'error' };
    if (!S.dirs) return { message: 'Loading recorded runs\u2026', kind: 'loading' };
    if (!S.dirs.length) return { message: NO_RUNS, kind: 'empty' };
    const r = S.replay;
    if (!r.summary) return { message: 'This run directory lists no runs.', kind: 'empty' };
    if (r.error) return { message: 'Could not load the events of ' + str(r.summary.id) + ': ' + r.error, kind: 'error' };
    if (r.loading || !r.events) return { message: 'Loading events of ' + str(r.summary.id) + '\u2026', kind: 'loading' };
    return { events: r.events, summary: r.summary, run: str(r.summary.id) };
  }

  function viewMessage(v) {
    return v.kind === 'error' ? errorState(v.message) : emptyState(v.message);
  }

  // ------------------------------------------------------------------
  // Run bar
  // ------------------------------------------------------------------

  function fact(k, v, title) {
    return h('li', null, h('span', { class: 'k' }, k), h('span', { class: 'v', title: title || null }, v));
  }

  function renderRunBar() {
    const bar = $('run-bar');
    bar.replaceChildren();
    const v = currentView();
    bar.append(h('h2', null, S.mode === 'live' ? 'Live run' : 'Recorded run'));
    if (v.message) {
      bar.append(v.kind === 'error' ? errorState(v.message) : h('p', { class: 'note' }, v.message));
      return;
    }
    const facts = h('ul', { class: 'facts' });
    if (S.mode === 'replay') {
      const sm = v.summary;
      facts.append(
        h('li', null, h('span', { class: 'k' }, 'Run'), clipped(sm.id, 56, 'v mono'),
          h('a', { href: runURL(sm.id), target: '_blank', rel: 'noopener noreferrer' }, 'raw events')),
        fact('Fixture', str(sm.fixture) || '\u2014'),
        fact('Kind', [str(sm.kind), str(sm.goal), str(sm.style)].filter(Boolean).join(' ') || '\u2014'),
        fact('Config', str(sm.config) || '\u2014'),
        fact('Trial', num(sm.trial)),
        fact('Implementation', str(sm.impl) || 'not recorded'));
      bar.append(facts);
      const m = h('ul', { class: 'facts' });
      if (sm.kind === 'attack') m.append(fact('Attack success', yesNo(sm.attack_success)));
      m.append(
        fact('Unauthorized effects', num(sm.unauthorized)),
        fact('Completed', yesNo(sm.completed)),
        fact('Escalations', num(sm.escalations)),
        fact('Uncertain attempts', num(sm.uncertain)),
        fact('Failed run', yesNo(sm.failed)),
        fact('Invariant checker', sm.valid === true ? 'passed' : sm.valid === false ? 'violations recorded' : '\u2014'),
        fact('Latency', num(sm.latency_ms, 2) + ' ms'));
      bar.append(h('p', { class: 'note' }, 'Measured by the harness from the environment diff and the event log:'), m);
      const diff = arr(sm.diff);
      bar.append(h('p', { class: 'note' }, 'Final environment diff: ',
        diff.length ? diff.map((c, i) => [i ? ', ' : '', h('code', null, clipText(diffKey(c.tool, c.action, c.target), 60).text)]) : 'no changes'));
    } else {
      const info = S.live.info.get(v.run) || {};
      const cfg = info.config || (v.events.find((e) => e.config) || {}).config;
      facts.append(
        h('li', null, h('span', { class: 'k' }, 'Run'), clipped(v.run, 56, 'v mono')),
        fact('Config', str(cfg) || '\u2014'),
        info.fixture ? fact('Fixture', info.fixture) : null,
        fact('Events received', String(v.events.length)));
      bar.append(facts);
      if (v.inferred) {
        bar.append(h('p', { class: 'note' }, v.inferred + ' event(s) arrived without a run id (for example handoff rejections and ' +
          'C0 environment changes); they are grouped with the run that emitted the previous event.'));
      }
      if (S.live.dropped) bar.append(h('p', { class: 'note' }, 'The oldest received events were discarded to keep memory bounded; replay the run file for the full log.'));
    }
    const runEvents = v.events.filter((e) => RUN_KINDS.has(e.kind));
    if (runEvents.length) {
      bar.append(h('ul', { class: 'run-events', 'aria-label': 'Run lifecycle events' }, runEvents.map((e) =>
        h('li', null,
          h('span', { class: 'kind' }, str(e.kind)),
          h('span', { class: 'who' }, str(e.agent) || '\u2014'),
          e.code ? h('code', null, clipText(e.code, 40).text) : null,
          clipped(str(e.detail), 200)))));
    }
  }

  // ------------------------------------------------------------------
  // Panel 1: Decisions
  // ------------------------------------------------------------------

  function isBaseline(evs) {
    return evs.some((e) => e.config === 'C0') && !evs.some((e) => e.kind === 'decision');
  }

  function decisionRow(e, attempt, hs) {
    const f = finalOf(e);
    const isPlan = e.kind === 'plan_rejected';
    const isHandoff = isHandoffOp(e.op);
    return h('tr', null,
      h('td', { class: 'seq num', title: str(e.at) }, num(e.seq)),
      h('td', null, clipped(e.agent, 16)),
      h('td', null, isPlan ? h('span', { class: 'call' }, 'plan') : clipped(opName(e.op) || '\u2014', 32, 'call')),
      h('td', null, isPlan ? muted('\u2014') : h('div', null,
        clipped(e.target || '\u2014', 44, 'target'),
        isHandoff ? null : h('div', null, trustBadge(e.trusted === true, 'label')))),
      h('td', null, isPlan ? muted('\u2014') : sourceChips(e.sources)),
      h('td', null, isPlan ? muted('\u2014') : trustBadge(e.pc_trusted === true)),
      h('td', null, h('div', { class: 'chips rules' }, rulesOf(e).map(ruleChip))),
      h('td', null, isPlan
        ? verdictBadge({ verdict: 'deny', rule: str(e.code), reason: str(e.detail) }, 'plan rejected')
        : f ? verdictBadge(f) : muted('no final verdict recorded')),
      h('td', null, evidenceBlock(e.evidence, e.op)),
      h('td', null, outcomeCell(e, attempt, hs)));
  }

  function callsTable(calls) {
    const tbody = h('tbody', null, calls.slice().reverse().map((e) => h('tr', null,
      h('td', { class: 'seq num', title: str(e.at) }, num(e.seq)),
      h('td', null, clipped(e.agent, 16)),
      h('td', null, clipped(opName(e.op) || '\u2014', 32, 'call')),
      h('td', null, clipped(e.target || '\u2014', 44, 'target')),
      h('td', null, muted('none')),
      h('td', null, e.code || e.detail
        ? h('div', null, h('span', { class: 'outcome o-failed' }, 'tool error'), clipped(str(e.code) + ' ' + str(e.detail), 80, 'outcome-detail'))
        : muted('no error recorded')))));
    return h('div', { class: 'table-scroll tall' }, h('table', { class: 'data' },
      h('caption', { class: 'visually-hidden' }, 'Tool calls of the C0 baseline, newest first'),
      h('thead', null, h('tr', null, ['#', 'Agent', 'Call', 'Target', 'Runtime check', 'Tool result'].map((t) => h('th', { scope: 'col' }, t)))),
      tbody));
  }

  function renderDecisions() {
    const body = $('decisions-body');
    const prev = body.querySelector('.table-scroll');
    const scroll = prev ? [prev.scrollTop, prev.scrollLeft] : [0, 0];
    body.replaceChildren();
    const v = currentView();
    if (v.message) {
      body.append(viewMessage(v));
      return;
    }
    const evs = v.events;
    const rows = evs.filter((e) => e.kind === 'decision' || e.kind === 'plan_rejected');
    if (!rows.length) {
      const calls = evs.filter((e) => e.kind === 'call');
      if (calls.length && isBaseline(evs)) {
        body.append(h('p', { class: 'note' }, 'C0 baseline: no runtime policy runs, so there are no decisions or attempt events. ' +
          'The tool calls it made are listed as recorded.'), callsTable(calls));
      } else {
        body.append(emptyState(v.live ? 'No decision events for this run yet.' : 'This run recorded no decision events.'));
      }
      restoreScroll(body, scroll);
      return;
    }
    const { outcome, orphans } = analyze(evs);
    const hs = handoffOutcomes(evs);
    const head = ['#', 'Agent', 'Call', 'Target', 'Target sources', 'PC', 'Rules (every applicable)', 'Final verdict', 'Evidence', 'Attempt outcome'];
    body.append(h('div', { class: 'table-scroll tall' }, h('table', { class: 'data' },
      h('caption', { class: 'visually-hidden' }, 'Policy decisions, newest first'),
      h('thead', null, h('tr', null, head.map((t, i) => h('th', { scope: 'col', class: i === 0 ? 'num' : null }, t)))),
      h('tbody', null, rows.slice().reverse().map((e) => decisionRow(e, outcome.get(e), hs))))));
    const n = rows.length;
    body.append(h('p', { class: 'note' }, n + ' decision' + (n === 1 ? '' : 's') + '. Rule chips: \u2713 allow, ! escalate, \u2715 deny; hover for each rule\u2019s reason.' +
      (orphans.length ? ' ' + orphans.length + ' attempt event(s) matched no admitted decision.' : '')));
    restoreScroll(body, scroll);
  }

  function restoreScroll(body, scroll) {
    const next = body.querySelector('.table-scroll');
    if (next) {
      next.scrollTop = scroll[0];
      next.scrollLeft = scroll[1];
    }
  }

  // ------------------------------------------------------------------
  // Panel 2: Results (a small, text-only markdown renderer)
  // ------------------------------------------------------------------

  function inline(parent, text) {
    const re = /`([^`]+)`|\*\*(.+?)\*\*/g;
    let last = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) parent.appendChild(document.createTextNode(visible(text.slice(last, m.index))));
      if (m[1] !== undefined) parent.appendChild(h('code', null, m[1]));
      else parent.appendChild(h('strong', null, m[2]));
      last = re.lastIndex;
    }
    if (last < text.length) parent.appendChild(document.createTextNode(visible(text.slice(last))));
    return parent;
  }

  function splitRow(line) {
    let s = line.trim();
    if (s.startsWith('|')) s = s.slice(1);
    if (s.endsWith('|') && !s.endsWith('\\|')) s = s.slice(0, -1);
    const cells = [];
    let cur = '';
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '\\' && s[i + 1] === '|') {
        cur += '|';
        i++;
      } else if (c === '|') {
        cells.push(cur.trim());
        cur = '';
      } else {
        cur += c;
      }
    }
    cells.push(cur.trim());
    return cells;
  }

  function isSeparator(line) {
    if (!line || !line.includes('-')) return false;
    const cells = splitRow(line);
    return cells.length > 0 && cells.every((c) => /^:?-+:?$/.test(c));
  }

  function alignOf(cell) {
    const l = cell.startsWith(':');
    const r = cell.endsWith(':');
    return l && r ? 'center' : r ? 'right' : 'left';
  }

  function mdTable(head, aligns, rows) {
    const cls = (i) => (aligns[i] === 'right' ? 'num' : null);
    return h('div', { class: 'table-scroll' }, h('table', { class: 'data' },
      h('thead', null, h('tr', null, head.map((c, i) => inline(h('th', { scope: 'col', class: cls(i) }), c)))),
      h('tbody', null, rows.map((r) => h('tr', null, head.map((_, i) => inline(h('td', { class: cls(i) }), r[i] || '')))))));
  }

  function renderMarkdown(md) {
    const root = h('div', { class: 'md' });
    const lines = str(md).replace(/\r\n?/g, '\n').split('\n');
    let para = null;
    let list = null;
    let hardBreak = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const t = line.trim();
      if (!t) {
        para = null;
        list = null;
        continue;
      }
      const hm = /^(#{1,6})\s+(.*?)\s*#*$/.exec(t);
      if (hm) {
        para = null;
        list = null;
        root.append(inline(h('h' + Math.min(6, hm[1].length + 2)), hm[2]));
        continue;
      }
      if (t.startsWith('|') && isSeparator(lines[i + 1])) {
        para = null;
        list = null;
        const head = splitRow(t);
        const aligns = splitRow(lines[i + 1]).map(alignOf);
        const rows = [];
        i += 2;
        while (i < lines.length && lines[i].trim().startsWith('|')) {
          rows.push(splitRow(lines[i]));
          i++;
        }
        i--;
        root.append(mdTable(head, aligns, rows));
        continue;
      }
      const lm = /^[-*+]\s+(.*)$/.exec(t);
      if (lm) {
        para = null;
        if (!list) {
          list = h('ul');
          root.append(list);
        }
        list.append(inline(h('li'), lm[1]));
        continue;
      }
      list = null;
      if (!para) {
        para = h('p');
        root.append(para);
      } else if (!hardBreak) {
        para.appendChild(document.createTextNode(' '));
      }
      inline(para, t.replace(/\\$/, ''));
      hardBreak = / {2,}$/.test(line) || t.endsWith('\\');
      if (hardBreak) para.append(h('br'));
    }
    return root;
  }

  function implLabel(impl) {
    if (impl === 'scripted') return h('span', { class: 'impl-label impl-scripted' }, 'Deterministic (scripted stand-ins)');
    if (impl === 'model') return h('span', { class: 'impl-label impl-model' }, 'Model runs');
    return h('span', { class: 'impl-label' }, impl ? 'Implementation: ' + impl : 'Implementation not recorded in meta.json');
  }

  function renderResults() {
    const body = $('results-body');
    body.replaceChildren();
    if (S.dirsError) {
      body.append(errorState('Could not load /api/runs: ' + S.dirsError));
      return;
    }
    if (!S.dirs) {
      body.append(emptyState('Loading recorded runs\u2026'));
      return;
    }
    if (!S.dirs.length) {
      body.append(emptyState(NO_RUNS));
      return;
    }
    const d = dirObj(S.results.dir);
    if (!d) {
      body.append(emptyState('Select a run directory.'));
      return;
    }
    const meta = isObj(d.meta) ? d.meta : {};
    const models = arr(meta.models).filter(isObj).map((m) => str(m.role) + '=' + str(m.model) + (m.provider ? ' (' + str(m.provider) + ')' : ''));
    body.append(implLabel(str(meta.impl)), h('ul', { class: 'facts' },
      fact('Started', str(meta.started) || '\u2014'),
      fact('Finished', str(meta.finished) || '\u2014'),
      h('li', null, h('span', { class: 'k' }, 'Code commit'), clipped(str(meta.git_commit) || '\u2014', 12, 'v mono')),
      h('li', null, h('span', { class: 'k' }, 'Thresholds commit'), clipped(str(meta.thresholds_commit) || 'none recorded', 14, 'v mono')),
      fact('Trials per fixture', num(meta.trials)),
      fact('Configs', arr(meta.configs).map(str).join(', ') || '\u2014'),
      fact('Runs listed', String(d.runs.length)),
      h('li', null, h('span', { class: 'k' }, 'Models'), clipped(models.length ? models.join('; ') : 'none recorded', 90, 'v'))));
    const md = str(d.tables_md);
    if (!md.trim()) {
      body.append(emptyState('This run directory has no generated tables (tables.md is missing or empty).'));
      return;
    }
    body.append(renderMarkdown(md));
  }

  // ------------------------------------------------------------------
  // Panel 3: Attack path
  // ------------------------------------------------------------------

  const G = { colW: 200, gap: 56, pad: 14, headH: 52, nodeGap: 10, groupH: 18 };
  const COLUMNS = [
    { title: 'Authorization context', sub: 'run_start: effective capabilities', none: 'no run_start recorded' },
    { title: 'Sources', sub: 'analyst parameters, log records', none: 'no labeled sources' },
    { title: 'Investigator values', sub: 'value events', none: 'no value events' },
    { title: 'Handoff', sub: 'handoff events', none: 'no handoff recorded' },
    { title: 'Responder calls', sub: 'decision events', none: 'no calls recorded' },
  ];
  const SOURCE_GROUPS = ['Analyst parameters', 'Runtime and inventory', 'Log records', 'Other sources'];

  function sourceInfo(src) {
    const v = str(src);
    if (v === 'task_param:c1_intake') return { group: 0, label: 'C1-instr intake, labeled as a parameter' };
    if (v.startsWith('task_param')) return { group: 0, label: 'analyst parameter' };
    if (v === 'user_note') return { group: 0, label: 'analyst note' };
    if (v.startsWith('planner_literal')) return { group: 0, label: 'planner literal' };
    if (v === 'runtime') return { group: 1, label: 'runtime' };
    if (v === 'tool:inventory.read') return { group: 1, label: 'inventory (system of record)' };
    if (v === 'tool:logs.read') return { group: 2, label: 'log records' };
    if (v.startsWith('qllm:')) return { group: 2, label: 'processor output' };
    return { group: 3, label: 'source' };
  }

  function buildPath(events) {
    const evs = arr(events).filter(isObj);
    const index = new Map(evs.map((e, i) => [e, i]));
    const { outcome } = analyze(evs);
    const cols = [[], [], [], [], []];
    const edges = [];
    const byId = new Map();
    const add = (col, n) => {
      n.col = col;
      n.lines = n.lines || [];
      cols[col].push(n);
      byId.set(n.id, n);
      return n;
    };

    // 1. Authorization context, from run_start.
    for (const e of evs) {
      if (e.kind !== 'run_start') continue;
      const id = 'ctx:' + str(e.agent);
      if (byId.has(id)) continue;
      add(0, { id, cls: 'trusted', title: str(e.agent) || 'agent', lines: [str(e.detail) || 'no capabilities recorded'],
        tip: str(e.agent) + ' effective capabilities, from run_start: ' + (str(e.detail) || 'none recorded') });
    }

    // 2. Sources, from labels on values, calls, and decisions.
    const used = new Map();
    for (const e of evs) {
      if (e.kind !== 'value' && e.kind !== 'decision' && e.kind !== 'call') continue;
      for (const x of arr(e.sources)) {
        if (!isBaseSource(x)) continue;
        if (!used.has(x)) used.set(x, new Set());
        used.get(x).add(str(e.agent));
      }
    }
    const srcs = [...used.keys()].map(str).sort((a, b) => sourceInfo(a).group - sourceInfo(b).group || a.localeCompare(b));
    for (const x of srcs) {
      const info = sourceInfo(x);
      const t = sourceTrusted(x);
      add(1, { id: 'src:' + x, cls: t ? 'trusted' : 'untrusted', title: x, lines: [info.label], group: info.group,
        tip: x + ': ' + info.label + (t ? ' (trusted source)' : ' (untrusted source)') });
    }
    for (const [x, agents] of used) {
      if (!str(x).startsWith('task_param') || x === 'task_param:c1_intake') continue;
      for (const a of agents) if (byId.has('ctx:' + a)) edges.push({ from: 'ctx:' + a, to: 'src:' + x, cls: 'e-trusted' });
    }

    // 3. Investigator values.
    const vals = evs.filter((e) => e.kind === 'value' && e.agent === 'investigator');
    for (const v of vals) {
      const id = 'val:' + str(v.value_id);
      if (byId.has(id)) continue;
      const t = v.trusted === true;
      add(2, { id, cls: t ? 'trusted' : 'untrusted', title: str(v.value_id) || 'value', lines: [str(v.value_type) + (t ? ' \u00b7 trusted' : ' \u00b7 untrusted')],
        tip: str(v.value_id) + ' : ' + str(v.value_type) + '\nsources: ' + arr(v.sources).map(str).join(', ') + (arr(v.deps).length ? '\ndeps: ' + arr(v.deps).map(str).join(', ') : '') });
      for (const x of arr(v.sources)) if (byId.has('src:' + x)) edges.push({ from: 'src:' + x, to: id, cls: sourceTrusted(x) ? 'e-trusted' : 'e-untrusted' });
      for (const d of arr(v.deps)) if (byId.has('val:' + d)) edges.push({ from: 'val:' + d, to: id, cls: t ? 'e-trusted' : 'e-untrusted', arc: true });
    }

    // 4. Handoffs, merged by envelope id.
    const hand = new Map();
    for (const e of evs) {
      if (!isObj(e.handoff) || (e.kind !== 'handoff_send' && e.kind !== 'handoff_accept' && e.kind !== 'handoff_reject')) continue;
      const hi = e.handoff;
      const key = str(hi.id) || e.kind + '#' + index.get(e);
      let n = hand.get(key);
      if (!n) {
        n = { key, envelope: str(hi.id), from: '', to: '', task: '', data: [], bytes: null, status: '', states: [], codes: [], first: index.get(e) };
        hand.set(key, n);
      }
      n.from = n.from || str(hi.from);
      n.to = n.to || str(hi.to);
      n.task = n.task || str(hi.task);
      if (!n.data.length) n.data = arr(hi.data).map(str);
      if (hi.bytes !== undefined && hi.bytes !== null) n.bytes = hi.bytes;
      if (hi.status) n.status = str(hi.status);
      n.states.push(e.kind === 'handoff_send' ? 'sent' : e.kind === 'handoff_accept' ? 'accepted' : 'rejected');
      if (e.code) n.codes.push(str(e.code));
    }
    const hdec = evs.filter((e) => e.kind === 'decision' && isHandoffOp(e.op));
    for (const n of hand.values()) {
      const state = n.states.includes('rejected') ? 'rejected' : n.states.includes('accepted') ? 'accepted' : n.states[n.states.length - 1];
      const dec = hdec.find((d) => str(d.target) === n.to + '/' + n.task);
      const dsrc = dec ? arr(dec.sources).map(str) : [];
      const plain = n.status === 'plain text';
      const cls = plain || !dec ? 'neutral' : dsrc.length && dsrc.every(sourceTrusted) ? 'trusted' : 'untrusted';
      const id = 'hof:' + n.key;
      add(3, { id, cls, denied: state === 'rejected', envelope: n.envelope, from: n.from,
        title: (n.from || '?') + ' \u2192 ' + (n.to || '?'),
        lines: [(plain ? 'plain-text report (no typed handoff)' : state) + (n.codes.length ? ' ' + n.codes.join(', ') : ''),
          n.data.length ? n.data.join(', ') : n.task || '\u2014'],
        flag: state === 'rejected' ? 'REJECTED' : '', flagCls: 'deny',
        tip: 'handoff ' + (n.envelope || '(no id)') + '\n' + (n.from || '?') + ' \u2192 ' + (n.to || '?') + ', task ' + (n.task || '\u2014') +
          '\ndata: ' + (n.data.join(', ') || '\u2014') + '\nbytes: ' + num(n.bytes) + '\nevents: ' + n.states.join(', ') +
          (n.codes.length ? '\ncodes: ' + n.codes.join(', ') : '') + (dsrc.length ? '\ndata sources: ' + dsrc.join(', ') : '') });
      if (dec) {
        // Inferred: the Investigator's latest values whose sources all appear
        // among the handoff data's sources, before the envelope was sent.
        const hs = new Set(dsrc);
        const cands = vals.filter((v) => v.agent === (n.from || 'investigator') && index.get(v) < n.first &&
          arr(v.sources).length && arr(v.sources).every((x) => hs.has(str(x))));
        const depOf = new Set();
        for (const v of cands) for (const d of arr(v.deps)) depOf.add(str(d));
        for (const v of cands) {
          if (depOf.has(str(v.value_id))) continue;
          edges.push({ from: 'val:' + str(v.value_id), to: id, cls: 'e-inferred ' + (v.trusted === true ? 'e-trusted' : 'e-untrusted') });
        }
      }
    }

    // 5. Responder calls, from decision events (C0: from call events).
    const trustedTargets = new Set(evs.filter((e) => (e.kind === 'decision' || e.kind === 'call') && e.trusted === true && str(e.target)).map((e) => str(e.target)));
    let calls = evs.filter((e) => e.kind === 'decision' && isObj(e.op) && !isHandoffOp(e.op) && (e.agent === 'responder' || isStateChanging(e.op)));
    let baseline = false;
    if (!calls.length) {
      calls = evs.filter((e) => e.kind === 'call' && e.config === 'C0' && e.agent === 'responder' && isObj(e.op));
      baseline = calls.length > 0;
    }
    const summary = { denied: [], injected: [], intake: [], handoffs: [...hand.values()], baseline };
    calls.forEach((c, i) => {
      const id = 'call:' + i;
      const f = finalOf(c);
      const v = baseline ? 'none' : verdictOf(f);
      const denied = v === 'deny';
      const injected = denied && c.trusted !== true && logDerived(c.sources) && !trustedTargets.has(str(c.target));
      const a = outcome.get(c);
      const lines = [opName(c.op) + (c.agent !== 'responder' ? ' \u00b7 ' + str(c.agent) : '')];
      if (baseline) {
        lines.push('no runtime check (C0)');
        if (c.code || c.detail) lines.push('tool error');
      } else {
        lines.push(v + (isObj(f) && f.rule ? ' \u00b7 ' + str(f.rule) : '') + (c.trusted === true ? ' \u00b7 label trusted' : ' \u00b7 label untrusted'));
        if (a) lines.push(attemptLabel(ATTEMPT_STATES.has(a.state) ? a.state : 'unknown'));
      }
      const tip = opName(c.op) + ' ' + str(c.target) + '\nagent: ' + str(c.agent) +
        (baseline ? '\nno runtime check (C0)' : '\nfinal: ' + v + (isObj(f) ? ' by ' + str(f.rule) + ': ' + str(f.reason) : '')) +
        '\ntarget sources: ' + (arr(c.sources).map(str).join(', ') || 'none recorded') +
        (a ? '\nattempt: ' + attemptLabel(str(a.state)) : '') +
        (injected ? '\ninjected: log-derived target, never in a trusted input, denied' : '');
      add(4, { id, cls: baseline ? 'neutral' : c.trusted === true ? 'trusted' : 'untrusted', denied, injected,
        title: str(c.target) || '\u2014', lines, tip,
        flag: injected ? 'INJECTED' : denied ? 'DENIED' : v === 'allow' ? 'ALLOWED' : v === 'escalate' ? 'ESCALATED' : '',
        flagCls: injected ? 'injected' : v === 'none' ? 'none' : v });
      for (const n of hand.values()) {
        if (n.envelope && arr(c.sources).includes('peer:' + n.from + '/' + n.envelope)) {
          edges.push({ from: 'hof:' + n.key, to: id, cls: injected ? 'e-injected' : 'e-untrusted' });
        }
      }
      for (const x of arr(c.sources)) {
        if (byId.has('src:' + x)) edges.push({ from: 'src:' + x, to: id, cls: injected ? 'e-injected' : sourceTrusted(x) ? 'e-trusted' : 'e-untrusted' });
      }
      if (denied) summary.denied.push({ c, f, injected });
      if (injected) summary.injected.push(c);
      if (arr(c.sources).includes('task_param:c1_intake')) summary.intake.push(c);
    });

    cols.forEach((nodes, i) => {
      if (!nodes.length) add(i, { id: 'none:' + i, cls: 'placeholder', title: 'none recorded', lines: [i === 0 && baseline ? 'C0: no authorization context' : COLUMNS[i].none] });
    });
    return { cols, edges, byId, summary };
  }

  function nodeHeight(n) {
    return 18 + 15 * n.lines.length + 8;
  }

  function layoutPath(model) {
    const colX = (i) => G.pad + i * (G.colW + G.gap);
    const heights = model.cols.map((nodes, i) => {
      let y = 0;
      let group;
      for (const n of nodes) {
        if (i === 1 && n.group !== undefined && n.group !== group) {
          group = n.group;
          n.groupLabel = SOURCE_GROUPS[group];
          y += G.groupH;
        }
        n.h = nodeHeight(n);
        n.rel = y;
        y += n.h + G.nodeGap;
      }
      return Math.max(0, y - G.nodeGap);
    });
    const tallest = Math.max(...heights, 60);
    model.cols.forEach((nodes, i) => {
      const off = G.headH + Math.round((tallest - heights[i]) / 2);
      for (const n of nodes) {
        n.x = colX(i);
        n.y = off + n.rel;
      }
    });
    model.width = G.pad * 2 + 5 * G.colW + 4 * G.gap;
    model.height = G.headH + tallest + G.pad;
  }

  function edgePath(a, b, arc) {
    if (arc) {
      const x = a.x + G.colW;
      const y1 = a.y + a.h / 2;
      const y2 = b.y + b.h / 2;
      const bulge = 28;
      return 'M ' + x + ' ' + y1 + ' C ' + (x + bulge) + ' ' + y1 + ', ' + (x + bulge) + ' ' + y2 + ', ' + (x + 2) + ' ' + y2;
    }
    const x1 = a.x + G.colW;
    const y1 = a.y + a.h / 2;
    const x2 = b.x - 2;
    const y2 = b.y + b.h / 2;
    const dx = Math.max(30, (x2 - x1) / 2);
    return 'M ' + x1 + ' ' + y1 + ' C ' + (x1 + dx) + ' ' + y1 + ', ' + (x2 - dx) + ' ' + y2 + ', ' + x2 + ' ' + y2;
  }

  function arrowFor(cls) {
    if (cls.includes('e-injected')) return 'arrow-injected';
    if (cls.includes('e-trusted')) return 'arrow-trusted';
    if (cls.includes('e-untrusted')) return 'arrow-untrusted';
    return 'arrow-neutral';
  }

  function drawNode(n) {
    const g = sv('g', { class: 'node ' + n.cls + (n.denied ? ' denied' : '') + (n.injected ? ' injected' : ''), transform: 'translate(' + n.x + ',' + n.y + ')' });
    g.append(sv('title', null, n.tip || n.title));
    if (n.injected) g.append(sv('rect', { class: 'halo', x: -5, y: -5, width: G.colW + 10, height: n.h + 10, rx: 10 }));
    g.append(sv('rect', { class: 'box', width: G.colW, height: n.h, rx: 6 }));
    const flagW = n.flag ? 8 + n.flag.length * 6.6 : 0;
    g.append(sv('text', { class: 'n-title', x: 8, y: 16 }, clipText(n.title, Math.floor((G.colW - 16 - flagW) / 7)).text));
    if (n.flag) g.append(sv('text', { class: 'n-flag f-' + n.flagCls, x: G.colW - 7, y: 15, 'text-anchor': 'end' }, n.flag));
    n.lines.forEach((line, i) => {
      g.append(sv('text', { class: 'n-sub', x: 8, y: 32 + i * 15 }, clipText(line, Math.floor((G.colW - 16) / 6.7)).text));
    });
    return g;
  }

  function renderAttackPath() {
    const svg = $('attack-svg');
    const empty = $('path-empty');
    const scroller = $('path-scroll');
    const sum = $('path-summary');
    sum.replaceChildren();
    const v = currentView();
    if (v.message) {
      empty.textContent = visible(v.message);
      empty.hidden = false;
      scroller.hidden = true;
      return;
    }
    if (!v.events.length) {
      empty.textContent = 'No events for this run yet.';
      empty.hidden = false;
      scroller.hidden = true;
      return;
    }
    empty.hidden = true;
    scroller.hidden = false;
    const model = buildPath(v.events);
    layoutPath(model);
    const s = model.summary;
    const counts = model.cols.map((c) => c.filter((n) => n.cls !== 'placeholder').length);
    const descText = 'Attack path of run ' + v.run + ': ' + counts[0] + ' authorization contexts, ' + counts[1] + ' sources, ' + counts[2] +
      ' Investigator values, ' + counts[3] + ' handoffs, ' + counts[4] + ' calls; ' + s.denied.length + ' denied, ' + s.injected.length + ' injected.';

    svg.replaceChildren();
    svg.setAttribute('width', String(model.width));
    svg.setAttribute('height', String(model.height));
    svg.setAttribute('viewBox', '0 0 ' + model.width + ' ' + model.height);
    svg.append(sv('title', { id: 'attack-svg-title' }, 'Attack path'), sv('desc', { id: 'attack-svg-desc' }, descText));
    const defs = sv('defs');
    for (const c of ['trusted', 'untrusted', 'neutral', 'injected']) {
      defs.append(sv('marker', { id: 'arrow-' + c, viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '8', markerHeight: '8', markerUnits: 'userSpaceOnUse', orient: 'auto' },
        sv('path', { d: 'M0,0 L10,5 L0,10 z', class: 'arrow-' + c })));
    }
    svg.append(defs);
    COLUMNS.forEach((col, i) => {
      const x = G.pad + i * (G.colW + G.gap);
      svg.append(sv('text', { class: 'col-head', x, y: 20 }, col.title), sv('text', { class: 'col-sub', x, y: 36 }, col.sub));
      if (i > 0) svg.append(sv('line', { class: 'col-rule', x1: x - G.gap / 2, y1: 8, x2: x - G.gap / 2, y2: model.height - 8 }));
    });
    const eg = sv('g', { class: 'edges' });
    for (const e of model.edges) {
      const a = model.byId.get(e.from);
      const b = model.byId.get(e.to);
      if (!a || !b) continue;
      eg.append(sv('path', { class: 'edge ' + e.cls, d: edgePath(a, b, e.arc), 'marker-end': 'url(#' + arrowFor(e.cls) + ')' }));
    }
    svg.append(eg);
    const ng = sv('g', { class: 'nodes' });
    for (const nodes of model.cols) {
      for (const n of nodes) {
        if (n.groupLabel) ng.append(sv('text', { class: 'group-label', x: n.x, y: n.y - 6 }, n.groupLabel));
        ng.append(drawNode(n));
      }
    }
    svg.append(ng);

    // Text version of the same facts, for screen readers and copying.
    const items = [];
    for (const n of s.handoffs) {
      const st = n.states.includes('rejected') ? 'rejected' : n.states.includes('accepted') ? 'accepted' : n.states[n.states.length - 1];
      items.push(h('li', null, 'Handoff ', h('code', null, clipText(n.envelope || '(no id)', 30).text), ' ', (n.from || '?') + ' \u2192 ' + (n.to || '?') + ': ',
        n.status === 'plain text' ? 'plain-text report' : st, n.codes.length ? ' (' + n.codes.join(', ') + ')' : ''));
    }
    sum.append(h('h3', null, 'Recorded facts'), h('ul', null,
      items,
      s.baseline ? h('li', null, 'C0 baseline: calls ran with no runtime check; there are no decisions to outline.') : null,
      h('li', null, 'Denied calls: ' + s.denied.length + (s.denied.length ? '.' : ' (none).')),
      s.denied.map(({ c, f, injected }) => h('li', null, h('code', null, clipText(str(c.target), 40).text), ' ', opName(c.op), ' \u2014 ',
        isObj(f) ? str(f.rule) + ': ' : '', clipped(isObj(f) ? str(f.reason) : '', 120), injected ? h('strong', null, ' \u2014 injected') : null)),
      s.intake.length ? h('li', null, s.intake.length + ' call(s) whose target carries task_param:c1_intake, the label the C1-instr intake gives its output.') : null));
  }

  // ------------------------------------------------------------------
  // Panel 4: Compare
  // ------------------------------------------------------------------

  function syncCompareSelects() {
    const c = S.compare;
    c.dir = setOptions($('compare-dir'), dirOptions(), c.dir || S.replay.dir);
    const runs = runsOf(c.dir);
    const has = (cfg, f) => runs.some((x) => x.config === cfg && str(x.fixture) === f);
    const fxs = sortFixtureIds(uniq(runs.map((x) => str(x.fixture)))).filter((f) => has('C1-instr', f) && has('C2', f));
    let want = c.fixture;
    if (!fxs.includes(want)) {
      want = fxs.includes(S.replay.fixture) ? S.replay.fixture : fxs.find((f) => runs.some((x) => str(x.fixture) === f && x.kind === 'attack')) || fxs[0];
    }
    c.fixture = setOptions($('compare-fixture'), fxs.map((f) => ({ value: f, label: fixtureLabelFromRuns(f, runs) })), want);
    const trialsOf = (cfg) => runs.filter((x) => x.config === cfg && str(x.fixture) === c.fixture).map((x) => String(x.trial));
    const t2 = new Set(trialsOf('C2'));
    const common = uniq(trialsOf('C1-instr')).filter((t) => t2.has(t)).sort((a, b) => Number(a) - Number(b));
    c.trial = setOptions($('compare-trial'), common.map((t) => ({ value: t, label: 'trial ' + t })), c.trial);
    return { runs, fxs };
  }

  async function loadEventsCached(id) {
    const cache = S.compare.cache;
    if (cache.has(id)) return cache.get(id);
    const p = getJSON(runURL(id)).then((evs) => {
      if (!Array.isArray(evs) && evs !== null) throw new Error('expected a JSON array of events');
      return arr(evs).filter(isObj);
    });
    cache.set(id, p);
    p.catch(() => cache.delete(id));
    return p;
  }

  async function renderCompare() {
    const body = $('compare-body');
    const token = ++S.compare.seq;
    body.replaceChildren();
    if (S.dirsError) {
      body.append(errorState('Could not load /api/runs: ' + S.dirsError));
      return;
    }
    if (!S.dirs) {
      body.append(emptyState('Loading recorded runs\u2026'));
      return;
    }
    if (!S.dirs.length) {
      body.append(emptyState(NO_RUNS));
      return;
    }
    const c = S.compare;
    const runs = runsOf(c.dir);
    if (!c.fixture) {
      body.append(emptyState('This run directory has no fixture recorded under both C1-instr and C2.'));
      return;
    }
    const pick = (cfg) => runs.find((x) => x.config === cfg && str(x.fixture) === c.fixture && String(x.trial) === c.trial) || null;
    const left = pick('C1-instr');
    const right = pick('C2');
    if (!left || !right) {
      body.append(emptyState('No trial of ' + c.fixture + ' was recorded under both C1-instr and C2 in this directory.'));
      return;
    }
    const fx = fixtureInfo(c.fixture);
    const head = h('div', { class: 'compare-fixture' },
      h('p', null, h('strong', null, c.fixture), ' \u00b7 ', [str(left.kind), str(left.goal), str(left.style)].filter(Boolean).join(' ') || '\u2014', ' \u00b7 trial ' + c.trial),
      fx && fx.description ? h('p', { class: 'desc' }, clipText(fx.description, 600).text) : null);
    body.append(head, emptyState('Loading both runs\u2019 events\u2026'));
    let evL;
    let evR;
    try {
      [evL, evR] = await Promise.all([loadEventsCached(str(left.id)), loadEventsCached(str(right.id))]);
    } catch (err) {
      if (token !== S.compare.seq) return;
      body.replaceChildren(head, errorState('Could not load the runs\u2019 events: ' + errMsg(err)));
      return;
    }
    if (token !== S.compare.seq) return;
    const keysOf = (sm) => new Set(arr(sm.diff).map((d) => diffKey(d.tool, d.action, d.target)));
    const kL = keysOf(left);
    const kR = keysOf(right);
    body.replaceChildren(head, h('div', { class: 'compare-grid' },
      compareSide(left, evL, kL, kR, 'C2'),
      compareSide(right, evR, kR, kL, 'C1-instr')));
  }

  function compareSide(sm, evs, mine, other, otherName) {
    const facts = h('ul', { class: 'facts' });
    if (sm.kind === 'attack') facts.append(fact('Attack success', yesNo(sm.attack_success)));
    facts.append(
      fact('Unauthorized effects', num(sm.unauthorized)),
      fact('Completed', yesNo(sm.completed)),
      fact('Escalations', num(sm.escalations)),
      fact('Uncertain', num(sm.uncertain)),
      fact('Failed', yesNo(sm.failed)),
      fact('Invariants', sm.valid === true ? 'passed' : sm.valid === false ? 'violated' : '\u2014'));
    const changes = new Map();
    for (const e of evs) {
      if (e.kind === 'env_change' && isObj(e.change)) changes.set(diffKey(e.change.tool, e.change.action, e.change.target), str(e.change.outcome));
    }
    const diff = arr(sm.diff);
    const diffList = diff.length
      ? h('ul', { class: 'diff-list' }, diff.map((d) => {
        const k = diffKey(d.tool, d.action, d.target);
        const o = changes.get(k);
        return h('li', null, clipText(k, 60).text, o ? h('span', { class: 'diff-outcome' }, ' \u2014 ' + o) : null,
          other.has(k) ? null : h('span', { class: 'diff-outcome' }, ' (not in ' + otherName + '\u2019s diff)'));
      }))
      : h('p', { class: 'note' }, 'No environment changes.');
    const { outcome } = analyze(evs);
    const rows = evs.filter((e) => e.kind === 'decision' && isStateChanging(e.op));
    let table;
    if (!rows.length) {
      table = emptyState('No decisions on state-changing calls in this run.');
    } else {
      table = h('div', { class: 'table-scroll' }, h('table', { class: 'data' },
        h('caption', { class: 'visually-hidden' }, 'Decisions on state-changing calls under ' + str(sm.config) + ', in order'),
        h('thead', null, h('tr', null, ['Target and call', 'Target sources', 'Rules', 'Final', 'Outcome', 'In diff'].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', null, rows.map((e) => {
          const k = diffKey(e.op.tool, e.op.action, e.target);
          const differs = mine.has(k) !== other.has(k);
          const f = finalOf(e);
          return h('tr', { class: differs ? 'row-diff' : null, title: differs ? 'The two final diffs differ on this call.' : null },
            h('td', null, clipped(e.target || '\u2014', 30, 'target'), clipped(opName(e.op), 28, 'call-sub'),
              h('div', null, trustBadge(e.trusted === true, 'label'))),
            h('td', null, sourceChips(e.sources)),
            h('td', null, h('div', { class: 'chips rules' }, rulesOf(e).map(ruleChip))),
            h('td', null, f ? verdictBadge(f) : muted('none recorded')),
            h('td', null, outcomeCell(e, outcome.get(e), handoffOutcomes(evs))),
            h('td', null, mine.has(k) ? 'yes' : 'no', differs ? h('span', { class: 'visually-hidden' }, ' (differs from ' + otherName + ')') : null));
        }))));
    }
    return h('section', { class: 'compare-side', 'aria-label': visible(sm.config) + ' run' },
      h('h3', null, str(sm.config)),
      h('p', { class: 'note' }, clipped(sm.id, 70, 'mono'), ' ', h('a', { href: runURL(sm.id), target: '_blank', rel: 'noopener noreferrer' }, 'raw events')),
      facts,
      h('h4', null, 'Final diff'), diffList,
      h('h4', null, 'Decisions on state-changing calls'), table);
  }

  // ------------------------------------------------------------------
  // Panel 5: Approvals
  // ------------------------------------------------------------------

  function expiryText(iso) {
    const t = Date.parse(str(iso));
    if (!Number.isFinite(t)) return str(iso) || 'not recorded';
    const left = Math.round((t - Date.now()) / 1000);
    const when = new Date(t).toLocaleTimeString();
    if (left <= 0) return when + ' (expired)';
    const m = Math.floor(left / 60);
    const s = left % 60;
    return when + ' (in ' + (m ? m + 'm ' : '') + s + 's)';
  }

  function updateCountdowns() {
    for (const el of document.querySelectorAll('[data-expires]')) el.textContent = visible(expiryText(el.getAttribute('data-expires')));
  }

  function argsTable(args, sources) {
    const a = isObj(args) ? args : {};
    const s = isObj(sources) ? sources : {};
    const names = uniq(Object.keys(a).concat(Object.keys(s))).sort();
    if (!names.length) return h('p', { class: 'note' }, 'No arguments recorded.');
    return h('div', { class: 'table-scroll args-table' }, h('table', { class: 'data' },
      h('caption', { class: 'visually-hidden' }, 'Arguments of the bound call and their sources'),
      h('thead', null, h('tr', null, ['Argument', 'Canonical value', 'Sources'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', null, names.map((n) => h('tr', null,
        h('td', null, clipped(n, 24, 'mono')),
        h('td', null, clipped(str(a[n]), 60, 'target')),
        h('td', null, sourceChips(s[n])))))));
  }

  function boundCall(op, args) {
    const a = isObj(args) ? args : {};
    return opName(op) + '(' + Object.keys(a).sort().map((k) => k + '=' + str(a[k])).join(', ') + ')';
  }

  function pendingCard(req) {
    const A = S.approvals;
    const key = str(req.Key);
    const d = isObj(req.Decision) ? req.Decision : {};
    const call = opName(req.Op) + ' ' + str(req.Target);
    const busy = A.busy.has(key);
    const canAnswer = !!A.principal && !!A.token && /^[0-9a-f]{64}$/.test(key) && !busy;
    const why = !A.principal ? 'No principal from /api/approvals' : !A.token ? 'No token from /api/approvals' : busy ? 'Sending\u2026' : null;
    return h('article', { class: 'approval-card', 'aria-label': 'Approval request: ' + visible(call) },
      h('h3', null, clipped(boundCall(req.Op, req.Args), 100)),
      h('p', { class: 'approval-meta' }, 'run ', clipped(req.RunID, 40, 'mono'), ' \u00b7 agent ', str(req.Agent) || '\u2014',
        ' \u00b7 key ', clipped(key, 16, 'mono'), ' \u00b7 expires ', h('span', { 'data-expires': str(req.ExpiresAt) }, expiryText(req.ExpiresAt))),
      h('div', { class: 'approval-rule' }, 'Escalated by ', ruleChip(d), ' ', clipped(str(d.reason), 160)),
      argsTable(req.Args, req.Sources),
      h('div', null, h('strong', null, 'Evidence'), evidenceBlock(req.Evidence, req.Op)),
      h('div', { class: 'approval-actions' },
        h('button', { type: 'button', class: 'btn btn-approve', disabled: !canAnswer, title: why, on: { click: () => answerApproval(req, true) } }, 'Approve'),
        h('button', { type: 'button', class: 'btn btn-deny', disabled: !canAnswer, title: why, on: { click: () => answerApproval(req, false) } }, 'Deny'),
        h('span', { class: 'muted' }, A.principal ? 'answering as ' + A.principal : 'no principal'),
        busy ? h('span', { class: 'muted' }, 'sending\u2026') : null));
  }

  function renderApprovalsPending(force) {
    const A = S.approvals;
    const sig = JSON.stringify([A.principal, !!A.token, A.error, A.loaded, A.pending.map((p) => str(isObj(p) ? p.Key : '')), [...A.busy], A.log.length]);
    if (!force && sig === A.sig) {
      updateCountdowns();
      return;
    }
    A.sig = sig;
    const box = $('approvals-pending');
    box.replaceChildren(h('h3', { class: 'subhead' }, 'Pending requests' + (A.principal ? ' for ' + visible(A.principal) : '')));
    if (A.error) box.append(errorState('Could not load /api/approvals: ' + A.error));
    else if (!A.loaded) box.append(emptyState('Loading\u2026'));
    else if (!A.pending.length) box.append(emptyState('No pending approval requests.'));
    else box.append(h('div', { class: 'approval-list' }, A.pending.filter(isObj).map(pendingCard)));
    if (A.log.length) {
      box.append(h('h3', { class: 'subhead' }, 'Answers sent from this page'), h('ul', { class: 'log-list' }, A.log.map((l) =>
        h('li', { class: 'approval-result ' + (l.ok ? 'ok' : 'bad') }, l.at + ' \u00b7 ' + (l.yes ? 'approve' : 'deny') + ' ', h('code', null, clipText(l.call, 60).text), ': ' + l.message))));
    }
    const badge = $('pending-badge');
    const n = A.pending.length;
    badge.hidden = n === 0;
    badge.textContent = n + ' pending approval' + (n === 1 ? '' : 's');
    updateCountdowns();
  }

  function renderApprovalsRecorded() {
    const box = $('approvals-recorded');
    box.replaceChildren(h('h3', { class: 'subhead' }, S.mode === 'live' ? 'Approval events in this live run' : 'Approval events in this recorded run'));
    const v = currentView();
    if (v.message) {
      box.append(h('p', { class: 'note' }, v.message));
      return;
    }
    const reqs = v.events.filter((e) => e.kind === 'approval_request' && isObj(e.approval));
    const answers = new Map();
    for (const e of v.events) if (e.kind === 'approval' && isObj(e.approval)) answers.set(str(e.approval.key), e.approval);
    if (!reqs.length) {
      box.append(emptyState('This run recorded no approval requests.'));
      return;
    }
    if (S.mode === 'replay') {
      box.append(h('p', { class: 'note' }, 'In harness runs the fixture\u2019s ground-truth approver answers as the context\u2019s principal. ' +
        'Each card shows the answer recorded in the event log.'));
    }
    box.append(h('div', { class: 'approval-list' }, reqs.map((e) => {
      const ap = e.approval;
      const ans = answers.get(str(ap.key));
      const state = ans ? str(ans.state) : '';
      const stateCls = ['granted', 'rejected', 'expired'].includes(state) ? ' a-' + state : '';
      return h('article', { class: 'approval-card recorded', 'aria-label': 'Recorded approval request: ' + visible(opName(e.op) + ' ' + str(e.target)) },
        h('h3', null, clipped(boundCall(e.op, ap.args), 100)),
        h('p', { class: 'approval-meta' }, 'seq ', num(e.seq), ' \u00b7 agent ', str(e.agent) || '\u2014', ' \u00b7 key ', clipped(ap.key, 16, 'mono'),
          ' \u00b7 expires ', clipped(str(ap.expires_at) || 'not recorded', 40)),
        h('div', { class: 'approval-rule' }, 'Escalated by ', ruleChip({ verdict: 'escalate', rule: ap.rule, reason: ap.reason }), ' ', clipped(str(ap.reason), 160)),
        argsTable(ap.args, ap.sources),
        h('div', null, h('strong', null, 'Evidence'), evidenceBlock(e.evidence, e.op)),
        h('p', { class: 'approval-answer' + stateCls },
          ans ? 'Recorded answer: ' + (state || 'no state') + (ans.approver ? ' by ' + str(ans.approver) : '') : 'No answer recorded in this log.',
          ans && ans.reason && ans.reason !== ap.reason ? h('span', { class: 'muted' }, ' \u2014 ', clipped(str(ans.reason), 120)) : null));
    })));
  }

  async function loadApprovals() {
    const A = S.approvals;
    if (A.inflight) return;
    A.inflight = true;
    try {
      const j = await getJSON('/api/approvals');
      if (!isObj(j)) throw new Error('unexpected response');
      A.principal = str(j.principal);
      A.token = str(j.token);
      A.pending = arr(j.pending).filter(isObj);
      A.error = null;
    } catch (err) {
      A.error = errMsg(err);
    }
    A.loaded = true;
    A.inflight = false;
    renderApprovalsPending(false);
    syncLiveButtons();
  }

  async function answerApproval(req, yes) {
    const A = S.approvals;
    const key = str(req.Key);
    if (!/^[0-9a-f]{64}$/.test(key) || A.busy.has(key)) return;
    A.busy.add(key);
    renderApprovalsPending(true);
    const call = opName(req.Op) + ' ' + str(req.Target);
    let entry;
    try {
      const r = await postJSON('/approve', { key, approver: A.principal, yes }, A.token);
      const code = isObj(r.body) && r.body.error ? ' ' + str(r.body.error) : '';
      entry = r.ok
        ? { ok: true, message: 'accepted by the server' }
        : { ok: false, message: 'refused: HTTP ' + r.status + code };
    } catch (err) {
      entry = { ok: false, message: 'not sent: ' + errMsg(err) };
    }
    A.busy.delete(key);
    entry.call = call;
    entry.yes = yes;
    entry.at = new Date().toLocaleTimeString();
    A.log.unshift(entry);
    if (A.log.length > 10) A.log.length = 10;
    status((yes ? 'Approve ' : 'Deny ') + call + ': ' + entry.message, !entry.ok);
    renderApprovalsPending(true);
    loadApprovals();
  }

  // ------------------------------------------------------------------
  // Replay
  // ------------------------------------------------------------------

  function syncReplaySelects() {
    const r = S.replay;
    r.dir = setOptions($('replay-dir'), dirOptions(), r.dir);
    const runs = runsOf(r.dir);
    const configs = orderConfigs(uniq(runs.map((x) => str(x.config))));
    r.config = setOptions($('replay-config'), configs.map((c) => ({ value: c, label: c })), r.config || 'C2');
    const fxs = sortFixtureIds(uniq(runs.filter((x) => x.config === r.config).map((x) => str(x.fixture))));
    r.fixture = setOptions($('replay-fixture'), fxs.map((f) => ({ value: f, label: fixtureLabelFromRuns(f, runs) })), r.fixture || 'M1');
    const trials = uniq(runs.filter((x) => x.config === r.config && str(x.fixture) === r.fixture).map((x) => String(x.trial)))
      .sort((a, b) => Number(a) - Number(b));
    r.trial = setOptions($('replay-trial'), trials.map((t) => ({ value: t, label: 'trial ' + t })), r.trial);
    return runs.find((x) => x.config === r.config && str(x.fixture) === r.fixture && String(x.trial) === r.trial) || null;
  }

  async function loadReplay(sm) {
    const r = S.replay;
    const token = ++r.seq;
    r.summary = sm;
    r.events = null;
    r.error = null;
    r.loading = !!sm;
    updateHash();
    renderEventPanels();
    if (!sm) return;
    try {
      const evs = await getJSON(runURL(sm.id));
      if (token !== r.seq) return;
      if (!Array.isArray(evs) && evs !== null) throw new Error('expected a JSON array of events');
      r.events = arr(evs).filter(isObj);
    } catch (err) {
      if (token !== r.seq) return;
      r.error = errMsg(err);
    }
    r.loading = false;
    if (S.mode === 'replay') renderEventPanels();
  }

  async function loadRuns(wantRun) {
    S.dirsError = null;
    try {
      const j = await getJSON('/api/runs');
      if (!isObj(j) || !(Array.isArray(j.dirs) || j.dirs === null)) throw new Error('response has no "dirs" array');
      S.dirs = arr(j.dirs).filter(isObj).sort((a, b) => str(b.dir).localeCompare(str(a.dir)));
      for (const d of S.dirs) d.runs = arr(d.runs).filter((x) => isObj(x) && str(x.id));
    } catch (err) {
      S.dirsError = errMsg(err);
      S.dirs = null;
    }
    if (wantRun && S.dirs) {
      for (const d of S.dirs) {
        const sm = d.runs.find((x) => str(x.id) === wantRun);
        if (sm) {
          Object.assign(S.replay, { dir: str(d.dir), config: str(sm.config), fixture: str(sm.fixture), trial: String(sm.trial) });
          break;
        }
      }
    }
    const sm = syncReplaySelects();
    S.results.dir = setOptions($('results-dir'), dirOptions(), S.results.dir || S.replay.dir);
    syncCompareSelects();
    renderResults();
    renderCompare();
    await loadReplay(sm);
  }

  // ------------------------------------------------------------------
  // Live
  // ------------------------------------------------------------------

  function setConn(state) {
    S.live.conn = state;
    const el = $('live-status');
    const text = { idle: 'Not connected', connecting: 'Connecting to /events\u2026', open: 'Receiving /events', reconnecting: 'Reconnecting to /events\u2026', closed: 'Event stream closed' }[state] || state;
    el.textContent = text;
    el.className = 'conn conn-' + state;
  }

  function connectLive() {
    if (S.live.es) return;
    if (typeof EventSource !== 'function') {
      setConn('closed');
      status('This browser has no EventSource; live events are unavailable.', true);
      return;
    }
    const es = new EventSource('/events');
    S.live.es = es;
    setConn('connecting');
    es.addEventListener('open', () => {
      setConn('open');
      if (S.mode === 'live') scheduleLiveRender();
    });
    es.addEventListener('error', () => setConn(es.readyState === EventSource.CLOSED ? 'closed' : 'reconnecting'));
    es.addEventListener('message', (m) => {
      let e;
      try {
        e = JSON.parse(m.data);
      } catch (_) {
        S.live.bad++;
        return;
      }
      if (isObj(e)) onLiveEvent(e);
    });
  }

  let lastLiveRun = '';

  function onLiveEvent(e) {
    const L = S.live;
    const run = str(e.run);
    let assigned = run;
    let inferred = false;
    if (run) {
      lastLiveRun = run;
    } else if (lastLiveRun) {
      assigned = lastLiveRun;
      inferred = true;
    }
    if (!assigned) return;
    L.items.push({ e, run: assigned, inferred });
    if (L.items.length > LIVE_MAX_EVENTS) {
      L.items.splice(0, L.items.length - LIVE_MAX_EVENTS);
      L.dropped++;
    }
    const info = L.info.get(assigned) || {};
    if (!info.config && e.config) info.config = str(e.config);
    L.info.set(assigned, info);
    if (!L.runIds.includes(assigned)) {
      L.runIds.push(assigned);
      syncLiveRunSelect();
    }
    if (S.mode === 'live') scheduleLiveRender();
  }

  let rafPending = false;

  function scheduleLiveRender() {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(() => {
      rafPending = false;
      if (S.mode === 'live') renderEventPanels();
    });
  }

  function liveRunLabel(id) {
    const info = S.live.info.get(id) || {};
    const bits = [info.fixture, info.config].filter(Boolean);
    return bits.length ? id + ' (' + bits.join(', ') + ')' : id;
  }

  function syncLiveRunSelect() {
    const opts = [{ value: '', label: 'Newest run' }].concat(S.live.runIds.slice().reverse().map((r) => ({ value: r, label: liveRunLabel(r) })));
    S.live.selected = setOptions($('live-run'), opts, S.live.selected);
  }

  function syncLiveButtons() {
    const btn = $('live-start');
    const noToken = !S.approvals.token;
    const noFx = !S.fixtures.length;
    btn.disabled = S.live.starting || noToken || noFx;
    btn.title = noToken ? 'No token: /api/approvals did not return one' : noFx ? 'No fixtures from /api/fixtures' : '';
  }

  function syncLiveControls() {
    const ids = sortFixtureIds(S.fixtures.map((f) => str(f.id)));
    S.live.fixture = setOptions($('live-fixture'), ids.map((id) => {
      const f = fixtureInfo(id) || {};
      const bits = [str(f.kind), str(f.goal), str(f.style)].filter(Boolean);
      return { value: id, label: bits.length ? id + ' \u00b7 ' + bits.join(' ') : id, title: visible(f.description) || null };
    }), S.live.fixture || 'M1');
    S.live.config = setOptions($('live-config'), CONFIGS.map((c) => ({ value: c, label: c })), S.live.config || 'C2');
    syncLiveRunSelect();
    syncLiveButtons();
  }

  async function loadFixtures() {
    try {
      const j = await getJSON('/api/fixtures');
      if (!isObj(j) || !(Array.isArray(j.fixtures) || j.fixtures === null)) throw new Error('response has no "fixtures" array');
      S.fixtures = arr(j.fixtures).filter((f) => isObj(f) && str(f.id));
      S.fixturesError = null;
    } catch (err) {
      S.fixtures = [];
      S.fixturesError = errMsg(err);
    }
    syncLiveControls();
    if (S.fixturesError && S.mode === 'live') status('Could not load /api/fixtures: ' + S.fixturesError, true);
    if (S.dirs) renderCompare();
  }

  async function startRun() {
    const fixture = $('live-fixture').value;
    const config = $('live-config').value;
    if (!fixture || !config || S.live.starting) return;
    S.live.starting = true;
    syncLiveButtons();
    status('Starting ' + fixture + ' under ' + config + '\u2026');
    try {
      const r = await postJSON('/run', { fixture, config }, S.approvals.token);
      if (!r.ok) {
        status('Run refused: HTTP ' + r.status + (isObj(r.body) && r.body.error ? ' ' + str(r.body.error) : ''), true);
      } else {
        const id = str(isObj(r.body) ? r.body.run_id : '');
        if (id) {
          S.live.info.set(id, Object.assign(S.live.info.get(id) || {}, { fixture, config }));
          if (!S.live.runIds.includes(id)) S.live.runIds.push(id);
          S.live.selected = id;
          syncLiveRunSelect();
        }
        status(id ? 'Started run ' + id + ' (' + fixture + ', ' + config + '); its events stream into the panels below.'
          : 'The server accepted the run but returned no run_id; showing the newest run.');
      }
    } catch (err) {
      status('Could not start the run: ' + errMsg(err), true);
    }
    S.live.starting = false;
    syncLiveButtons();
    renderEventPanels();
  }

  // ------------------------------------------------------------------
  // Mode, hash, and wiring
  // ------------------------------------------------------------------

  function updateHash() {
    let want = '';
    if (S.mode === 'live') want = '#live';
    else if (S.replay.summary) want = '#run=' + encodeURIComponent(str(S.replay.summary.id));
    if (location.hash !== want) history.replaceState(null, '', want || location.pathname + location.search);
  }

  function readHash() {
    const hs = location.hash;
    if (hs === '#live') return { mode: 'live' };
    if (hs.startsWith('#run=')) {
      try {
        return { mode: 'replay', run: decodeURIComponent(hs.slice(5)) };
      } catch (_) {
        return {};
      }
    }
    return {};
  }

  function setMode(m) {
    S.mode = m;
    $('mode-replay').setAttribute('aria-pressed', String(m === 'replay'));
    $('mode-live').setAttribute('aria-pressed', String(m === 'live'));
    $('replay-controls').hidden = m !== 'replay';
    $('live-controls').hidden = m !== 'live';
    if (m === 'live') {
      connectLive();
      syncLiveControls();
    }
    updateHash();
    renderEventPanels();
  }

  function renderEventPanels() {
    renderRunBar();
    renderDecisions();
    renderAttackPath();
    renderApprovalsRecorded();
  }

  function bind() {
    $('mode-replay').addEventListener('click', () => setMode('replay'));
    $('mode-live').addEventListener('click', () => setMode('live'));
    const onReplay = (field) => (ev) => {
      S.replay[field] = ev.target.value;
      if (field === 'dir') {
        S.results.dir = setOptions($('results-dir'), dirOptions(), S.replay.dir);
        S.compare.dir = S.replay.dir;
        S.compare.fixture = '';
        syncCompareSelects();
        renderResults();
        renderCompare();
      }
      loadReplay(syncReplaySelects());
    };
    $('replay-dir').addEventListener('change', onReplay('dir'));
    $('replay-config').addEventListener('change', onReplay('config'));
    $('replay-fixture').addEventListener('change', onReplay('fixture'));
    $('replay-trial').addEventListener('change', onReplay('trial'));
    $('results-dir').addEventListener('change', (ev) => {
      S.results.dir = ev.target.value;
      renderResults();
    });
    $('compare-dir').addEventListener('change', (ev) => {
      S.compare.dir = ev.target.value;
      syncCompareSelects();
      renderCompare();
    });
    $('compare-fixture').addEventListener('change', (ev) => {
      S.compare.fixture = ev.target.value;
      syncCompareSelects();
      renderCompare();
    });
    $('compare-trial').addEventListener('change', (ev) => {
      S.compare.trial = ev.target.value;
      renderCompare();
    });
    $('live-run').addEventListener('change', (ev) => {
      S.live.selected = ev.target.value;
      renderEventPanels();
    });
    $('live-fixture').addEventListener('change', (ev) => {
      S.live.fixture = ev.target.value;
    });
    $('live-config').addEventListener('change', (ev) => {
      S.live.config = ev.target.value;
    });
    $('live-start').addEventListener('click', startRun);
    $('live-clear').addEventListener('click', () => {
      S.live.items = [];
      S.live.runIds = [];
      S.live.info = new Map();
      S.live.selected = '';
      S.live.dropped = 0;
      lastLiveRun = '';
      syncLiveRunSelect();
      renderEventPanels();
      status('Cleared the received events. Recorded runs are unchanged.');
    });
    $('replay-reload').addEventListener('click', () => {
      S.compare.cache.clear();
      status('Reloading /api/runs\u2026');
      loadRuns(S.replay.summary ? str(S.replay.summary.id) : '').then(() => status(S.dirsError ? 'Could not reload /api/runs.' : 'Reloaded the run list.', !!S.dirsError));
    });
    $('pending-badge').addEventListener('click', () => {
      const panel = $('panel-approvals');
      panel.scrollIntoView({ block: 'start' });
      const first = panel.querySelector('.btn-approve:not([disabled])') || $('h-approvals');
      if (first === $('h-approvals')) first.setAttribute('tabindex', '-1');
      first.focus();
    });
    setInterval(() => {
      if (document.visibilityState === 'visible') loadApprovals();
    }, POLL_MS);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') loadApprovals();
    });
  }

  function init() {
    bind();
    const want = readHash();
    renderEventPanels();
    renderResults();
    renderCompare();
    renderApprovalsPending(true);
    loadApprovals();
    loadFixtures();
    loadRuns(want.run || '');
    if (want.mode === 'live') setMode('live');
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
