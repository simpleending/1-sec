const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
class Element {
  constructor() { this.value = ''; this.children = []; this.listeners = {}; this.textContent = ''; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute() {}
  removeAttribute() {}
  addEventListener(name, fn) { this.listeners[name] = fn; }
}
function fixture(fetch) {
  const elements = new Map();
  const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), {
    document: { getElementById: get, createElement: () => new Element() },
    fetch, AbortSignal, setInterval: () => 1, clearInterval: () => {}, window: { confirm: () => true },
  });
  return { get, connect: () => get('connect').listeners.submit({ preventDefault() {} }), disconnect: () => get('disconnect').listeners.click() };
}
const response = value => ({ ok: true, json: async () => value });

test('disconnect cancels an in-flight connection without restoring engine data', async () => {
  let release;
  const access = new Promise(resolve => { release = resolve; });
  let dataRequests = 0;
  const app = fixture(async url => {
    if (url === '/api/v1/ui-access') return access;
    dataRequests++; return response({ status: 'private engine snapshot' });
  });
  const connecting = app.connect();
  app.disconnect();
  release(response({ scope: 'read' }));
  await connecting;
  assert.equal(app.get('scope').textContent, 'Disconnected');
  assert.equal(app.get('raw').textContent, 'null');
  assert.equal(dataRequests, 0);
});

test('a failed older connection cannot clear a newer credential or session', async () => {
  let reject;
  const older = new Promise((_resolve, rejectOld) => { reject = rejectOld; });
  const headers = [];
  let attempts = 0;
  const app = fixture(async (url, options) => {
    headers.push(options.headers.Authorization);
    if (url === '/api/v1/ui-access' && ++attempts === 1) return older;
    return response(url === '/api/v1/ui-access' ? { scope: 'read' } : { status: 'new snapshot' });
  });
  app.get('key').value = 'first-fixture';
  const first = app.connect();
  app.get('key').value = 'second-fixture';
  await app.connect();
  reject(new Error('Old connection failed'));
  await first;
  await app.get('reload').listeners.click();
  assert.equal(app.get('scope').textContent, 'read access');
  assert.ok(headers.includes('Bearer second-fixture'));
  assert.equal(headers.at(-1), 'Bearer second-fixture');
  assert.match(app.get('raw').textContent, /new snapshot/);
});

test('read-only connections inspect data and cannot use local enforcement controls', async () => {
  const app = fixture(async url => response(url === '/api/v1/ui-access' ? { scope: 'read' } : { enabled: true }));
  await app.connect();
  assert.equal(app.get('key').value, '');
  assert.equal(app.get('scope').textContent, 'read access');
  const enforcement = app.get('navigation').children.find(button => button.textContent === 'Enforcement');
  await enforcement.listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(app.get('controls').children.length, 2);
  assert.ok(app.get('controls').children.every(button => button.disabled));
  app.disconnect();
  assert.equal(app.get('raw').textContent, 'null');
});

test('named responder can approve while policy and live-mode controls stay disabled', async () => {
  const app = fixture(async url => response(url === '/api/v1/ui-access'
    ? { scope: 'operator', operator: { id: 'alice', role: 'responder' }, permissions: ['read', 'approvals.decide'] }
    : url.includes('approvals/pending') ? { pending: [{ id: 'approval-1' }] } : { enabled: true }));
  await app.connect();
  assert.equal(app.get('scope').textContent, 'alice · responder');
  const enforcement = app.get('navigation').children.find(button => button.textContent === 'Enforcement');
  enforcement.listeners.click(); await new Promise(resolve => setImmediate(resolve));
  assert.ok(app.get('controls').children.every(button => button.disabled));
  const approvals = app.get('navigation').children.find(button => button.textContent === 'Approvals');
  approvals.listeners.click(); await new Promise(resolve => setImmediate(resolve));
  const buttons = [];
  function visit(node) { if (node.textContent === 'Approve' || node.textContent === 'Reject') buttons.push(node); for (const child of node.children) visit(child); }
  visit(app.get('content'));
  assert.equal(buttons.length, 2);
  assert.ok(buttons.every(button => !button.disabled));
  app.disconnect();
  assert.equal(app.get('raw').textContent, 'null');
});

test('refresh applies a role downgrade before rendering action controls', async () => {
  let role = 'responder';
  const app = fixture(async url => response(url === '/api/v1/ui-access'
    ? { scope: 'operator', operator: { id: 'alice', role }, permissions: role === 'responder' ? ['read', 'approvals.decide'] : ['read'] }
    : url.includes('approvals/pending') ? { pending: [{ id: 'approval-1' }] } : { enabled: true }));
  await app.connect();
  app.get('navigation').children.find(button => button.textContent === 'Approvals').listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  role = 'viewer'; await app.get('reload').listeners.click();
  assert.equal(app.get('scope').textContent, 'alice · viewer');
  const buttons = [];
  function visit(node) { if (node.textContent === 'Approve' || node.textContent === 'Reject') buttons.push(node); for (const child of node.children) visit(child); }
  visit(app.get('content'));
  assert.equal(buttons.length, 2);
  assert.ok(buttons.every(button => button.disabled));
});

test('authorization failure clears the named credential and private snapshot', async () => {
  let revoked = false, requests = 0;
  const app = fixture(async url => {
    requests++;
    if (revoked) return { ok: false, status: 403, json: async () => ({ error: 'inactive operator' }) };
    return response(url === '/api/v1/ui-access' ? { scope: 'operator', operator: { id: 'alice', role: 'viewer' }, permissions: ['read'] } : { status: 'private snapshot' });
  });
  app.get('key').value = 'named-fixture'; await app.connect();
  assert.match(app.get('raw').textContent, /private snapshot/);
  revoked = true; await app.get('reload').listeners.click();
  assert.equal(app.get('scope').textContent, 'Disconnected');
  assert.equal(app.get('raw').textContent, 'null');
  const before = requests; await app.get('reload').listeners.click();
  assert.equal(requests, before);
});
