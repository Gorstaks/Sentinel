const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Decode the dashboard's verbatim C# string to exercise the authored renderer.
const htmlSource = fs.readFileSync(path.join(__dirname, '../src/Sentinel.Agent/DashboardHtml.cs'), 'utf8')
  .replaceAll('""', '"').replaceAll('{{', '{').replaceAll('}}', '}');
function sourceOf(name) {
  const match = htmlSource.match(new RegExp('function ' + name + '\\([^)]*\\) \\{[\\s\\S]*?\n\\}'));
  assert.ok(match, 'Missing dashboard function ' + name);
  return match[0];
}
function dashboardDocument(elements) {
  return {
    getElementById(id) { return elements[id] ||= { style: {}, value: '', setAttribute(name, value) { this[name] = value; }, focus() {} }; },
    createTextNode(text) { return text; },
    createElement() { return { innerHTML: '', appendChild(text) { this.innerHTML = text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'); } }; }
  };
}
function coverageCode() { return ['esc', 'sensorRows', 'renderCoverage', 'renderSensorInventory', 'toggleSensorDetails'].map(sourceOf).join('\n'); }

function render(type, data) {
  const container = { innerHTML: '' };
  const document = {
    getElementById: () => container,
    createTextNode: text => text,
    createElement: () => ({
      innerHTML: '',
      appendChild(text) {
        this.innerHTML = text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
      }
    })
  };
  const context = vm.createContext({ document });
  vm.runInContext(sourceOf('esc') + '\n' + sourceOf('renderEvents'), context);
  context.renderEvents([{ type, data: JSON.stringify({ type, data }) }], 'events');
  return container.innerHTML;
}

test('dashboard JavaScript remains syntactically valid', () => {
  const scripts = [...htmlSource.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.ok(scripts.length > 0);
  for (const script of scripts) new vm.Script(script[1]);
});
for (const status of ['Refused', 'Attempted', 'Failed', 'PartiallyCompleted']) {
  test(status + ' response never receives a success checkmark', () => {
    const html = render('response', {
      ActionTaken: 'KILL', Reason: 'Fixture', Execution: { Status: status, Effects: [] }
    });
    assert.match(html, new RegExp('Response: ' + status));
    assert.doesNotMatch(html, /\u2713/);
  });
}
test('only verified effects receive a checkmark', () => {
  assert.match(render('response_result', { Status: 'Verified', VerifiesRequestedAction: true, Effects: [] }), /\u2713/);
});
test('a verified effect label without a completed requested-action receipt is insufficient', () => {
  assert.doesNotMatch(render('response_result', { Status: 'Verified', VerifiesRequestedAction: false, Effects: [] }), /\u2713/);
});
test('legacy action labels cannot imply verified success', () => {
  const html = render('response', { ActionTaken: 'KILL', Reason: 'Legacy fixture' });
  assert.match(html, /Unverified legacy record/);
  assert.doesNotMatch(html, /\u2713/);
});
test('outcome details remain escaped when rendered', () => {
  const html = render('response_result', {
    Status: 'Failed', Reason: '<img src=x onerror=alert(1)>',
    Effects: [{ Action: 'ProcessTree', Status: 'Failed', Detail: '<script>bad()</script>' }]
  });
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script/);
  assert.doesNotMatch(html, /<img|<script/);
});

test('unverified firewall policy never gets an active dashboard badge', () => {
  const elements = {};
  const context = vm.createContext({
    document: dashboardDocument(elements),
    apiCall(endpoint, options, callback) {
      callback(endpoint === '/api/status'
        ? { ok: true, version: '3.2.3', serviceRunning: true, firewallPolicyCompliant: false }
        : { ok: false });
    }
  });
  vm.runInContext(coverageCode() + '\n' + sourceOf('loadStatus'), context);
  context.loadStatus();
  assert.equal(elements['status-text'].textContent, 'Firewall policy needs attention');
  assert.equal(elements['ov-status'].textContent, 'Needs attention');
});

test('verified offline firewall policy cannot hide missing collection health', () => {
  const elements = {};
  const context = vm.createContext({
    document: dashboardDocument(elements),
    apiCall(endpoint, options, callback) {
      callback(endpoint === '/api/status'
        ? { ok: true, version: '3.2.3', serviceRunning: true, firewallPolicyCompliant: true }
        : { ok: false });
    }
  });
  vm.runInContext(coverageCode() + '\n' + sourceOf('loadStatus'), context);
  context.loadStatus();
  assert.equal(elements['status-text'].textContent, 'Service running; sensor health unavailable');
  assert.equal(elements['ov-status'].className, 'card-value warning');
});

function dnsContext(eligible = true) {
  const elements = {
    'dns-adapter': { value: '0' }, 'dns-profile': { value: 'Quad9' }, 'dns-transaction': { value: 'snapshot' }, 'dns-recovery-transaction': { value: 'snapshot' }
  };
  const calls = [];
  const context = vm.createContext({
    document: dashboardDocument(elements),
    dnsInspection: {
      Adapters: [{ Id: 'adapter', Name: 'Fixture', Eligible: eligible, Fingerprint: 'preview' }],
      Profiles: [{ Name: 'Quad9', Ipv4: '9.9.9.9', Ipv6: '2620:fe::fe' }],
      Transactions: [{ Id: 'snapshot', PreviousIpv4: '', PreviousIpv6: '' }]
    },
    confirm(message) { calls.push({ confirmation: message }); return true; },
    ensureCsrf(callback) { callback('csrf-fixture'); },
    apiCall(endpoint, options) { calls.push({ endpoint, options }); }
  });
  vm.runInContext(sourceOf('approveDnsRepair'), context);
  return { context, calls, elements };
}

test('DNS repair approval carries the inspected fingerprint and concrete resolver choice', () => {
  const { context, calls } = dnsContext();
  context.approveDnsRepair(false);
  assert.match(calls[0].confirmation, /9\.9\.9\.9/);
  assert.equal(calls[1].endpoint, '/api/dns/repair');
  assert.equal(calls[1].options.headers['X-CSRF-Token'], 'csrf-fixture');
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    AdapterId: 'adapter', Profile: 'Quad9', ExpectedFingerprint: 'preview', TransactionId: ''
  });
});

test('ineligible adapters cannot request DNS repair from the dashboard', () => {
  const { context, calls } = dnsContext(false);
  context.approveDnsRepair(false);
  assert.equal(calls.length, 0);
});

test('DNS restoration identifies the snapshot and displays automatic configuration explicitly', () => {
  const { context, calls } = dnsContext();
  context.approveDnsRepair(true);
  assert.match(calls[0].confirmation, /automatic\/DHCP/);
  assert.equal(calls[1].endpoint, '/api/dns/restore');
  assert.equal(JSON.parse(calls[1].options.body).TransactionId, 'snapshot');
});


test('interrupted DNS recovery previews the original settings and uses its own approved operation', () => {
  const { context, calls } = dnsContext();
  context.approveDnsRepair(false, true);
  assert.match(calls[0].confirmation, /Recover the interrupted operation/);
  assert.match(calls[0].confirmation, /automatic\/DHCP/);
  assert.equal(calls[1].endpoint, '/api/dns/recover');
  assert.equal(calls[1].options.headers['X-CSRF-Token'], 'csrf-fixture');
  assert.equal(JSON.parse(calls[1].options.body).TransactionId, 'snapshot');
});


test('pending DNS operations block new repairs and expose only recoverable snapshots', () => {
  const { context, elements } = dnsContext();
  context.esc = String;
  context.dnsInspection.Transactions = [{ Id: 'pending', AdapterId: 'adapter', Phase: 'Prepared', RecoveryAvailable: true }];
  vm.runInContext(sourceOf('showDnsAdapter'), context);
  context.showDnsAdapter();
  assert.equal(elements['dns-repair'].disabled, true);
  assert.equal(elements['dns-restore'].disabled, true);
  assert.equal(elements['dns-recover'].disabled, false);
  assert.match(elements['dns-detail'].textContent, /Interrupted transaction/);
  assert.doesNotMatch(elements['dns-detail'].textContent, /preview/);
  context.dnsInspection.Transactions[0].RecoveryAvailable = false;
  context.showDnsAdapter();
  assert.equal(elements['dns-recover'].disabled, true);
});

function auditContext() {
  const elements = {};
  const context = vm.createContext({
    document: {
      getElementById(id) { return elements[id] ||= {}; },
      createTextNode(text) { return text; },
      createElement() { return { innerHTML: '', appendChild(text) {
        this.innerHTML = text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
      } }; }
    }, latestSecurityAudit: null
  });
  vm.runInContext(sourceOf('esc') + '\n' + sourceOf('renderSecurityAudit'), context);
  return { context, elements };
}

test('missing audit coverage is unknown and cannot be downloaded as a current report', () => {
  const { context, elements } = auditContext();
  context.renderSecurityAudit(null);
  assert.match(elements['security-audit'].innerHTML, /coverage unknown/);
  assert.equal(elements['audit-download'].disabled, true);
  assert.equal(context.latestSecurityAudit, null);
});

test('configuration read-back is distinguished from observed active runtime protection', () => {
  const { context, elements } = auditContext();
  context.renderSecurityAudit({ Hardening: [
    { Name: 'PPL', State: 'Configured', Detail: 'Runtime enforcement not verified.' },
    { Name: 'Defender', State: 'ObservedActive', Detail: 'Snapshot.' },
    { Name: 'Unknown provider', State: 'InventedSuccess', Detail: '' }
  ] });
  const html = elements['security-audit'].innerHTML;
  assert.match(html, /PPL: Configuration matches baseline/);
  assert.match(html, /Defender: Active at collection time/);
  assert.match(html, /Unknown provider: Unknown/);
  assert.match(html, /Runtime enforcement not verified/);
});

test('audit renders untrusted event fields as escaped text', () => {
  const { context, elements } = auditContext();
  context.renderSecurityAudit({ History: [{ Name: '<img src=x>', State: 'Partial',
    Detail: '<script>bad()</script>', Items: [{ Account: '<iframe>', Subject: '<img>', Kind: '<b>' }] }] });
  const html = elements['security-audit'].innerHTML;
  assert.doesNotMatch(html, /<img|<script|<iframe|<b>/);
  assert.match(html, /&lt;iframe/);
  assert.match(html, /Partial/);
});

test('empty available event history does not claim no activity occurred', () => {
  const { context, elements } = auditContext();
  context.renderSecurityAudit({ History: [{ Name: 'Logons', State: 'Available', Items: [] }] });
  assert.match(elements['security-audit'].innerHTML, /does not establish that no activity occurred/);
  assert.doesNotMatch(elements['security-audit'].innerHTML, /System appears clean/);
});

test('audit caps rendered history while keeping all collected records in download data', () => {
  const { context, elements } = auditContext();
  const report = { History: [{ Name: 'Logons', State: 'Partial', Items:
    Array.from({ length: 60 }, (_, i) => ({ Kind: 'Logon', Subject: 'Account-' + i })) }] };
  context.renderSecurityAudit(report);
  assert.match(elements['security-audit'].innerHTML, /Showing 50 of 60/);
  assert.doesNotMatch(elements['security-audit'].innerHTML, /Account-59/);
  assert.equal(context.latestSecurityAudit.History[0].Items.length, 60);
  assert.equal(elements['audit-download'].disabled, false);
});

test('incomplete scan cannot display a completed status or a clean-system verdict', () => {
  const { context, elements } = auditContext();
  context.scanPolling = null;
  context.apiCall = (url, options, callback) => callback({ ok: true, status: 'completed', result: {
    Completed: false, Error: 'Scan cancelled', Findings: []
  } });
  context.clearInterval = () => {};
  for (const id of ['scan-progress', 'scan-bar']) elements[id] = { style: {} };
  vm.runInContext(sourceOf('checkScanStatus'), context);
  context.checkScanStatus();
  assert.equal(elements['sc-status'].textContent, 'Incomplete');
  assert.equal(elements['sc-status'].className, 'card-value warning');
  assert.doesNotMatch(elements['scan-findings'].innerHTML, /System appears clean/);
  assert.equal(elements['audit-download'].disabled, true);
});

function renderSensorHealth(health) {
  const elements = {};
  const context = vm.createContext({
    document: dashboardDocument(elements),
    apiCall(endpoint, options, callback) {
      callback(endpoint === '/api/status'
        ? { ok: true, version: '3.3.6', serviceRunning: true, firewallPolicyCompliant: true }
        : { ok: true, monitorsRegistered: 136, monitorsRunning: 134, startupTasksCompleted: 2,
          monitorsDisabled: 0, collectionHealthy: 4, collectionUnverified: 130, ...health });
    }
  });
  vm.runInContext(coverageCode() + '\n' + sourceOf('loadStatus'), context);
  context.loadStatus();
  return elements;
}

test('a running worker with a failed collector keeps the main warning visible', () => {
  const elements = renderSensorHealth({
    monitorsUnhealthy: 1,
    monitorDetails: [{ name: 'DnsQueryMonitor', state: 'Running', reason: null,
      collection: { State: 'Failed', Error: '<script>Channel denied</script>' } }]
  });
  assert.equal(elements['ov-status'].textContent, 'Needs attention');
  assert.equal(elements['status-text'].textContent, 'Sensor coverage needs attention');
  assert.match(elements['ov-monitors'].textContent, /134\/136 tasks running/);
  assert.match(elements['ov-coverage-summary'].textContent, /task details returned/);
  assert.match(elements['ov-monitor-details'].innerHTML, /Channel denied/);
  assert.doesNotMatch(elements['ov-monitor-details'].innerHTML, /<script>/);
});

test('unverified collection cannot display fully active protection', () => {
  const elements = renderSensorHealth({ monitorsUnhealthy: 0, monitorDetails: [] });
  assert.equal(elements['ov-status'].textContent, 'Collection unverified');
  assert.match(elements['status-text'].textContent, /partly unverified/);
});

test('late status replies cannot erase a newer collector failure', () => {
  const pending = [];
  const elements = {};
  const context = vm.createContext({
    document: dashboardDocument(elements),
    apiCall(endpoint, options, callback) { pending.push({ endpoint, callback }); }
  });
  vm.runInContext(coverageCode() + '\n' + sourceOf('loadStatus'), context);
  context.loadStatus();
  context.loadStatus();
  assert.deepEqual(pending.map(x => x.endpoint), ['/api/status', '/api/status']);
  const active = { ok: true, version: 'fixture', serviceRunning: true, firewallPolicyCompliant: true };
  pending[1].callback(active);
  pending[2].callback({ ok: true, monitorsRegistered: 136, monitorsRunning: 134,
    monitorsUnhealthy: 1, monitorDetails: [] });
  pending[0].callback(active);
  assert.equal(elements['ov-status'].textContent, 'Needs attention');
});


test('audit distinguishes contextual, configured-inactive and unsupported protection', () => {
  const { context, elements } = auditContext();
  context.renderSecurityAudit({ Hardening: [
    { Name: 'Credential Guard', State: 'ContextDependent', Detail: 'Domain secrets; excludes browser cookies.' },
    { Name: 'Memory Integrity', State: 'ConfiguredNotRunning', Detail: 'Not active.' },
    { Name: 'Provider', State: 'Unsupported', Detail: 'Unavailable.' }
  ] });
  const html = elements['security-audit'].innerHTML;
  assert.match(html, /Credential Guard: Depends on domain credential use/);
  assert.match(html, /Memory Integrity: Configured, not running/);
  assert.match(html, /Provider: Not supported by this Windows provider/);
  assert.match(html, /excludes browser cookies/);
  assert.doesNotMatch(html, /Active at collection time/);
});


test('Overview cannot expand a native unsupported details element into the full roster', () => {
  assert.doesNotMatch(htmlSource.slice(htmlSource.indexOf('<!DOCTYPE html>')), /<details|<summary/);
  const overview = htmlSource.split('id="page-overview"')[1].split('<!-- EVENTS -->')[0];
  assert.doesNotMatch(overview, /ov-monitor-details/);
  assert.match(htmlSource, /id="sensor-details" style="display:none"/);
  assert.doesNotMatch(htmlSource, /display:\s*grid/);
});

function coverageFixture() {
  const elements = {}, context = vm.createContext({ document: dashboardDocument(elements) });
  vm.runInContext(coverageCode(), context);
  const monitors = Array.from({ length: 128 }, (_, i) => ({ name: 'LegacySensor' + i, state: 'Running', collection: { State: 'Unsupported', Scope: 'No progress source.' } }));
  monitors.push({ name: 'FileVerdictScanner', state: 'Running', collection: { State: 'Failed', Error: '<script>scan pending</script>' } });
  monitors.push({ name: 'EtwSessionGuard', state: 'Running', collection: { State: 'Failed', Error: 'Access denied' } });
  monitors.push({ name: 'DnsQueryMonitor', state: 'Running', collection: { State: 'Healthy' } });
  context.renderCoverage({ monitorDetails: monitors, monitorsUnhealthy: 2, etwHealth: { NativeEventsLost: 616072, DispatchDrops: 0 } });
  return { context, elements, monitors };
}

test('large roster produces a small Overview with failures first and unverified coverage disclosed', () => {
  const { elements } = coverageFixture();
  const html = elements['ov-attention'].innerHTML;
  assert.match(html, /File scanning/);
  assert.match(html, /Windows event collection/);
  assert.doesNotMatch(html, /LegacySensor/);
  assert.match(html, /616072 native events/);
  assert.match(elements['ov-coverage-summary'].textContent, /128 collection unverified/);
  assert.doesNotMatch(html, /<script>/);
});

test('sensor inventory filters and searches the complete roster without dropping unknown states', () => {
  const { context, elements } = coverageFixture();
  assert.match(elements['sensor-result-count'].textContent, /131 of 131/);
  assert.match(elements['ov-monitor-details'].innerHTML, /Collection unverified/);
  elements['sensor-search'].value = 'unsupported'; context.renderSensorInventory();
  assert.match(elements['sensor-result-count'].textContent, /128 of 131/);
  elements['sensor-search'].value = '';
  elements['sensor-filter'].value = 'attention'; context.renderSensorInventory();
  assert.match(elements['sensor-result-count'].textContent, /2 of 131/);
  assert.doesNotMatch(elements['ov-monitor-details'].innerHTML, /LegacySensor/);
  elements['sensor-search'].value = 'access denied'; context.renderSensorInventory();
  assert.match(elements['sensor-result-count'].textContent, /1 of 131/);
  elements['sensor-search'].value = 'absent'; context.renderSensorInventory();
  assert.match(elements['ov-monitor-details'].innerHTML, /No sensors match/);
});

test('explicit sensor disclosure works without browser details support', () => {
  const { context, elements } = coverageFixture();
  context.document.getElementById('sensor-details').style.display = 'none';
  context.toggleSensorDetails();
  assert.equal(elements['sensor-details'].style.display, 'block');
  assert.equal(elements['sensor-toggle']['aria-expanded'], 'true');
  context.renderCoverage({ monitorDetails: [], monitorsUnhealthy: 1 });
  assert.equal(elements['sensor-details'].style.display, 'block');
  context.toggleSensorDetails();
  assert.equal(elements['sensor-details'].style.display, 'none');
});


test('a successful service reply cannot show active coverage before health arrives', () => {
  const elements = {}, pending = [];
  const context = vm.createContext({ document: dashboardDocument(elements), apiCall(url, options, callback) { pending.push(callback); } });
  vm.runInContext(coverageCode() + '\n' + sourceOf('loadStatus'), context);
  context.loadStatus();
  pending[0]({ ok: true, version: 'fixture', serviceRunning: true, firewallPolicyCompliant: true });
  assert.equal(elements['ov-status'].textContent, 'Checking coverage');
  assert.notEqual(elements['status-badge'].className, 'status-badge active');
});

test('explicitly checked coverage can become active but unverified coverage stays amber', () => {
  const active = renderSensorHealth({ collectionHealthy: 1, collectionUnverified: 0, monitorsUnhealthy: 0, monitorDetails: [] });
  assert.equal(active['status-badge'].className, 'status-badge active');
  const unknown = renderSensorHealth({ collectionUnverified: 128, monitorsUnhealthy: 0, monitorDetails: [] });
  assert.equal(unknown['status-badge'].className, 'status-badge warning');
});

test('ETW lane losses remain distinct from filtering and coalescing in metrics', () => {
  const elements = {};
  const context = vm.createContext({
    document: dashboardDocument(elements),
    apiCall(url, options, callback) {
      callback({ ok: true, ops: { Etw: {
        DispatchDrops: 41, DispatchLaneDrops: { ProcessImage: 2, File: 39, Registry: 0, Other: 0 },
        EventsFiltered: 800, RegistryHintsCoalesced: 900
      }, ProductVersion: 'fixture' } });
    }
  });
  vm.runInContext(sourceOf('esc') + '\n' + sourceOf('loadOps'), context);
  context.loadOps();
  const html = elements['ops-grid'].innerHTML;
  for (const [label, value] of [ ['ETW dispatch drops', 41], ['ETW process/image lane drops', 2],
    ['ETW file lane drops', 39], ['ETW unused event IDs filtered', 800], ['ETW registry hints coalesced', 900] ]) {
    assert.ok(html.includes(label + '</div><div class="metric-value">' + value));
  }
  assert.ok(html.indexOf('ETW collection') < html.indexOf('<h3>Product</h3>'));
});

test('IPC failure distinguishes running, starting, unknown and explicitly stopped services', () => {
  for (const [state, label, overview] of [
    ['NotResponding', 'Service running; IPC not responding', 'Unavailable'],
    ['Starting', 'Service starting; IPC not ready', 'Starting'],
    ['Unknown', 'Service status unknown; IPC unavailable', 'Unavailable'],
    ['Stopped', 'Service stopped', 'Stopped']
  ]) {
    const elements = {};
    const context = vm.createContext({ document: dashboardDocument(elements),
      apiCall(url, options, callback) { callback(url === '/api/status'
        ? { ok: true, version: 'fixture', serviceRunning: false, ipcReachable: false, serviceState: state }
        : { ok: false }); }
    });
    vm.runInContext(coverageCode() + '\n' + sourceOf('loadStatus'), context);
    context.loadStatus();
    assert.equal(elements['status-text'].textContent, label);
    assert.equal(elements['ov-status'].textContent, overview);
    assert.notEqual(elements['status-badge'].className, 'status-badge active');
  }
});

test('unexpected privacy overlays show high-priority review without claiming compromise or a kill', () => {
  const html = render('detection', { RuleName: 'Clickjacking: Suspicious Overlay Window', ProcessName: 'example', ProcessId: 42,
    Metadata: { PrivacyActivity: 'true', ReviewPriority: 'High', UserInitiated: 'Unknown' } });
  assert.match(html, /High-priority review/);
  assert.match(html, /Tier2 observation; no response authorized/);
  assert.doesNotMatch(html, /\u2713|unauthorized recording|malware confirmed/);
});

test('delete-pending file containment cannot be rendered as verified neutralization', () => {
  const html = render('file_policy', { Status: 'PartiallyCompleted', Target: 'fixture.bin',
    Detail: 'Encrypted recovery copy saved; original file object marked delete-pending.' });
  assert.match(html, /Known-malware file containment: PartiallyCompleted/);
  assert.match(html, /delete-pending/);
  assert.doesNotMatch(html, /\u2713|responseVerified|neutralized/);
});
