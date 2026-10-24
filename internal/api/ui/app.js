'use strict';
(() => {
  const sections = [
    ['Overview', 'status'], ['Alerts', 'alerts?limit=100'], ['Modules', 'modules'],
    ['Enforcement', 'enforce/status'], ['Policies', 'enforce/policies'], ['Action history', 'enforce/history?limit=100'],
    ['Approvals', 'enforce/approvals/pending'], ['Approval history', 'enforce/approvals/history?limit=100'],
    ['Approval settings', 'enforce/config'], ['Correlations', 'correlator'], ['Threats', 'threats'],
    ['Collectors / metrics', 'metrics'], ['Rust engine', 'rust'], ['Archive', 'archive/status'],
    ['Escalation', 'escalation/status'], ['Webhooks', 'enforce/webhooks/stats'],
    ['Dead letters', 'enforce/webhooks/dead-letters'], ['Token vault', 'token-vault/status'], ['Configuration', 'config'], ['Logs', 'logs?limit=100'],
  ];
  const $ = id => document.getElementById(id);
  let key = '', scope = 'read', connected = false, active = sections[0], snapshot = null, generation = 0, requestSerial = 0;
  function message(value) { $('message').textContent = value; }
  async function api(endpoint, method = 'GET', body) {
    const response = await fetch('/api/v1/' + endpoint, { method, credentials: 'omit', cache: 'no-store',
      headers: { ...(key ? { Authorization: 'Bearer ' + key } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(10000) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Engine returned ' + response.status);
    return result;
  }
  function element(tag, text) { const node = document.createElement(tag); if (text !== undefined) node.textContent = String(text); return node; }
  function action(label, endpoint, body) {
    const button = element('button', label);
    button.type = 'button'; button.disabled = scope !== 'write';
    button.addEventListener('click', async () => {
      if (!connected || scope !== 'write' || !window.confirm(label + '? This changes the running engine.')) return;
      button.disabled = true;
      try { const result = await api(endpoint, 'POST', body); message(result.message || label + ' completed'); await refresh(); }
      catch (error) { message(error.message); }
      finally { button.disabled = scope !== 'write'; }
    });
    return button;
  }
  function render() {
    const content = $('content'), controls = $('controls');
    content.replaceChildren(); controls.replaceChildren(); $('raw').textContent = JSON.stringify(snapshot, null, 2);
    if (!snapshot) return;
    if (active[1] === 'enforce/status') {
      controls.append(action('Enable dry run', 'enforce/dry-run/on'), action('Disable dry run / go live', 'enforce/dry-run/off'));
    }
    if (active[1] === 'config') controls.append(action('Reload configuration from disk', 'config/reload'));
    if (active[1] === 'enforce/config') {
      const form = element('form'), label = element('label', 'Approval severity threshold');
      const select = element('select');
      for (const value of ['', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']) { const option = element('option', value || 'Disabled'); option.value = value; select.append(option); }
      select.value = snapshot.approval_gate?.auto_approve_above || ''; select.disabled = scope !== 'write';
      label.append(select); form.append(label);
      const save = element('button', 'Apply approval threshold'); save.disabled = scope !== 'write'; form.append(save);
      form.addEventListener('submit', async event => {
        event.preventDefault();
        if (scope !== 'write') return;
        try { await api('enforce/config', 'POST', { auto_approve_above: select.value }); message('Approval threshold updated'); await refresh(); }
        catch (error) { message(error.message); }
      });
      controls.append(form);
    }
    let rows = Array.isArray(snapshot) ? snapshot : Object.values(snapshot).find(Array.isArray);
    if (active[1] === 'enforce/policies' && snapshot.policies) rows = Object.entries(snapshot.policies).map(([module, policy]) => ({ module, ...policy }));
    if (!rows || active[1] === 'status') {
      const cards = element('div'); cards.className = 'cards';
      for (const [name, value] of Object.entries(snapshot)) if (value === null || typeof value !== 'object') {
        const card = element('div'); card.className = 'metric'; card.append(element('span', name.replaceAll('_', ' ')), element('strong', value ?? '—')); cards.append(card);
      }
      content.append(cards); if (!rows) return;
    }
    const filter = $('filter').value.toLowerCase();
    rows = rows.filter(row => JSON.stringify(row).toLowerCase().includes(filter));
    if (!rows.length) { content.append(element('p', 'No matching records in the current snapshot.')); return; }
    if (typeof rows[0] !== 'object' || rows[0] === null) { for (const row of rows) content.append(element('p', row)); return; }
    const preferred = ['id', 'name', 'timestamp', 'severity', 'module', 'action', 'target', 'status', 'enabled', 'description', 'message'];
    const fields = preferred.filter(field => rows.some(row => Object.hasOwn(row, field)));
    if (!fields.length) fields.push(...Object.keys(rows[0]).slice(0, 6));
    const table = element('table'), head = element('tr');
    for (const field of fields) head.append(element('th', field));
    head.append(element('th', 'Details / actions')); table.append(head);
    for (const row of rows) {
      const tr = element('tr');
      for (const field of fields) tr.append(element('td', typeof row[field] === 'object' ? JSON.stringify(row[field]) : row[field] ?? '—'));
      const cell = element('td'), details = element('details'); details.append(element('summary', 'View'), element('pre', JSON.stringify(row, null, 2))); cell.append(details);
      if (active[1] === 'enforce/approvals/pending' && typeof row.id === 'string') cell.append(action('Approve', 'enforce/approve/' + encodeURIComponent(row.id)), action('Reject', 'enforce/reject/' + encodeURIComponent(row.id)));
      if (active[1] === 'enforce/policies' && typeof row.module === 'string') cell.append(action(row.enabled ? 'Disable policy' : 'Enable policy', 'enforce/policies/' + encodeURIComponent(row.module) + '/' + (row.enabled ? 'disable' : 'enable')));
      tr.append(cell); table.append(tr);
    }
    content.append(table);
  }
  async function refresh() {
    if (!connected) return;
    const serial = ++requestSerial, requestGeneration = generation, endpoint = active[1];
    try {
      const result = await api(endpoint);
      if (requestGeneration !== generation || serial !== requestSerial || !connected || endpoint !== active[1]) return;
      snapshot = result; render(); message('Updated ' + new Date().toLocaleTimeString() + ' · ' + scope + ' access');
    } catch (error) { if (requestGeneration === generation && serial === requestSerial) message(error.message); }
  }
  for (const section of sections) {
    const button = element('button', section[0]); button.type = 'button';
    button.addEventListener('click', () => {
      active = section; $('title').textContent = section[0];
      for (const other of $('navigation').children) other.removeAttribute('aria-current');
      button.setAttribute('aria-current', 'page'); snapshot = null; render(); refresh();
    });
    if (section === active) button.setAttribute('aria-current', 'page');
    $('navigation').append(button);
  }
  $('connect').addEventListener('submit', async event => {
    event.preventDefault(); const attempt = ++generation; key = $('key').value.trim(); $('key').value = ''; connected = false;
    snapshot = null; render(); scope = 'read'; $('scope').textContent = 'Connecting';
    try { const access = await api('ui-access'); if (attempt !== generation) return; scope = access.scope; connected = true; $('scope').textContent = scope + ' access'; await refresh(); }
    catch (error) { if (attempt !== generation) return; key = ''; $('scope').textContent = 'Disconnected'; message(error.message); }
  });
  $('disconnect').addEventListener('click', () => { generation++; key = ''; $('key').value = ''; connected = false; scope = 'read'; snapshot = null; render(); $('scope').textContent = 'Disconnected'; message('Disconnected. Credential and data cleared.'); });
  $('reload').addEventListener('click', refresh);
  $('filter').addEventListener('input', render);
  let timer;
  function resetTimer() { clearInterval(timer); const seconds = Number($('refresh').value); if (seconds > 0) timer = setInterval(refresh, seconds * 1000); }
  $('refresh').addEventListener('change', resetTimer); resetTimer();
})();
