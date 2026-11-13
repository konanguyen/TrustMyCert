'use strict';

// TrustMyCert WebUI.
//
// Two bridges:
//   KernelSU / APatch WebUI : window.ksu.exec(command, optionsJson, callback)
//   Magisk action.sh         : local busybox httpd + token-protected CGI
//
// All commands are fixed strings; the only user input is a package name that
// is validated before it is passed to the root CLI.

const MODULE_ID = 'trustmycert';
const TMC = '/data/adb/modules/' + MODULE_ID + '/bin/tmc';
const PACKAGE_RE = /^[A-Za-z0-9_][A-Za-z0-9_.]*$/;
// KernelSU injects no token. The Magisk HTTP fallback passes a one-time token
// in the URL fragment (#...): fragments are never sent to the server, so a
// local port scan cannot discover it.
const TOKEN = (typeof window.TMC_TOKEN === 'string' && window.TMC_TOKEN) ||
  (typeof location !== 'undefined' && location.hash ? location.hash.slice(1) : '');

const hasKsu = typeof ksu !== 'undefined' && ksu && typeof ksu.exec === 'function';

const el = (id) => document.getElementById(id);
const ui = {
  bridge: el('bridge'),
  banner: el('banner'),
  enabled: el('enabled'),
  match_subprocesses: el('match_subprocesses'),
  verbose: el('verbose'),
  bypass: el('bypass'),
  bypassConfirm: el('bypass-confirm'),
  bypassYes: el('bypass-yes'),
  bypassNo: el('bypass-no'),
  count: el('count'),
  addForm: el('add-form'),
  addBtn: el('add-btn'),
  pkg: el('pkg'),
  installed: el('installed'),
  formError: el('form-error'),
  targets: el('targets'),
  empty: el('empty'),
  configLog: el('config-log'),
  moduleLog: el('module-log'),
  autoRefresh: el('auto-refresh'),
  refresh: el('refresh'),
  path: el('path'),
};

let state = {
  enabled: false,
  bypass: false,
  verbose: false,
  match_subprocesses: false,
  targets: [],
};
let busy = false;
let autoTimer = null;

function setAutoRefresh(enabled) {
  if (autoTimer !== null) {
    clearInterval(autoTimer);
    autoTimer = null;
  }
  if (enabled) autoTimer = setInterval(loadModuleLogs, 5000);
}

function setBanner(message, kind) {
  if (!message) {
    ui.banner.hidden = true;
    ui.banner.textContent = '';
    return;
  }
  ui.banner.hidden = false;
  ui.banner.className = 'banner ' + (kind || 'info');
  ui.banner.textContent = message;
}

async function loadModuleLogs() {
  try {
    const text = await run(TMC + ' logs 200');
    ui.moduleLog.textContent = text.trim() || 'No TrustMyCert log entries yet.';
  } catch (error) {
    ui.moduleLog.textContent = 'Cannot read module logs: ' + error.message;
  }
}

function ksuExec(command) {
  return new Promise((resolve, reject) => {
    const name = 'tmc_cb_' + Date.now() + '_' + Math.floor(Math.random() * 1e6);
    window[name] = (errno, stdout, stderr) => {
      delete window[name];
      resolve({ errno: errno, stdout: stdout || '', stderr: stderr || '' });
    };
    try {
      ksu.exec(command, '{}', name);
    } catch (error) {
      delete window[name];
      reject(error);
    }
  });
}

async function httpExec(command) {
  if (!TOKEN) {
    throw new Error('UI token missing. Start the UI from the module Action button.');
  }
  const args = command.indexOf(TMC) === 0 ? command.slice(TMC.length).trim() : command;
  const query = 'token=' + encodeURIComponent(TOKEN);
  const response = await fetch('cgi-bin/api?' + query, {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'text/plain' },
    body: args,
  });
  let body = null;
  try {
    body = await response.json();
  } catch (error) {
    body = null;
  }
  if (!response.ok) {
    const detail = body && body.stderr ? body.stderr.trim() : ('HTTP ' + response.status);
    throw new Error(detail || ('HTTP ' + response.status));
  }
  if (!body) throw new Error('Malformed CGI response');
  return { errno: body.errno, stdout: body.stdout || '', stderr: body.stderr || '' };
}

async function run(command) {
  const result = hasKsu ? await ksuExec(command) : await httpExec(command);
  const clean = (s) => (s || '').trim();
  if (result.errno !== 0) {
    const detail = clean(result.stderr) || clean(result.stdout) || ('exit ' + result.errno);
    throw new Error(detail);
  }
  return result.stdout || '';
}

function parseConfig(text) {
  const cfg = {
    enabled: false,
    bypass: false,
    verbose: false,
    match_subprocesses: false,
    targets: [],
  };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq);
    const value = line.slice(eq + 1);
    if (key === 'target') {
      if (value) cfg.targets.push(value);
    } else if (key in cfg) {
      cfg[key] = value === '1' || value === 'true';
    }
  }
  return cfg;
}

function render() {
  ui.enabled.checked = state.enabled;
  ui.match_subprocesses.checked = state.match_subprocesses;
  ui.verbose.checked = state.verbose;
  // The bypass checkbox is only shown as active after the confirmation flow.
  ui.bypass.checked = state.bypass;
  ui.count.textContent = String(state.targets.length);

  ui.targets.textContent = '';
  for (const pkg of state.targets) {
    const li = document.createElement('li');
    const name = document.createElement('code');
    name.textContent = pkg;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'remove';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () => removeTarget(pkg));
    li.append(name, remove);
    ui.targets.append(li);
  }
  ui.empty.hidden = state.targets.length !== 0;
}

async function refresh() {
  if (busy) return;
  busy = true;
  ui.refresh.disabled = true;
  try {
    const text = await run(TMC + ' list');
    state = parseConfig(text);
    render();
    ui.configLog.textContent = '$ tmc list\n' + text.trim();
    setBanner('');
  } catch (error) {
    setBanner('Cannot read config: ' + error.message, 'error');
    ui.configLog.textContent = 'Cannot read config: ' + error.message;
  } finally {
    busy = false;
    ui.refresh.disabled = false;
  }
  await loadModuleLogs();
}

async function setFlag(key, value) {
  if (busy) return;
  busy = true;
  try {
    await run(TMC + ' set ' + key + ' ' + (value ? '1' : '0'));
    state[key] = value;
    if (key === 'bypass') ui.bypass.checked = value;
    setBanner('');
  } catch (error) {
    setBanner('Failed to update ' + key + ': ' + error.message, 'error');
    const control = el(key);
    if (control) control.checked = !!state[key];
  } finally {
    busy = false;
  }
  await refresh();
}

async function addTarget(pkg) {
  if (busy) return;
  if (!PACKAGE_RE.test(pkg)) {
    showFormError('Invalid package name.');
    return;
  }
  if (pkg === 'system_server') {
    showFormError('system_server is never instrumented.');
    return;
  }
  let added = false;
  busy = true;
  ui.addBtn.disabled = true;
  try {
    await run(TMC + ' add ' + pkg);
    ui.pkg.value = '';
    showFormError('');
    added = true;
  } catch (error) {
    showFormError(error.message);
  } finally {
    busy = false;
    ui.addBtn.disabled = false;
  }
  if (added) await refresh();
}

async function removeTarget(pkg) {
  if (busy) return;
  let removed = false;
  busy = true;
  try {
    await run(TMC + ' remove ' + pkg);
    removed = true;
  } catch (error) {
    setBanner('Failed to remove ' + pkg + ': ' + error.message, 'error');
  } finally {
    busy = false;
  }
  if (removed) await refresh();
}

function showFormError(message) {
  ui.formError.textContent = message;
  ui.formError.hidden = !message;
}

async function loadInstalled() {
  try {
    const out = await run(TMC + ' apps');
    const names = out.split('\n').map((s) => s.trim()).filter((s) => PACKAGE_RE.test(s));
    ui.installed.textContent = '';
    for (const name of names) {
      const option = document.createElement('option');
      option.value = name;
      ui.installed.append(option);
    }
  } catch (error) {
    // Package listing is a convenience; ignore failures (e.g. restricted shell).
  }
}

function wireEvents() {
  ui.enabled.addEventListener('change', () => setFlag('enabled', ui.enabled.checked));
  ui.match_subprocesses.addEventListener('change', () =>
    setFlag('match_subprocesses', ui.match_subprocesses.checked));
  ui.verbose.addEventListener('change', () => setFlag('verbose', ui.verbose.checked));

  ui.bypass.addEventListener('change', () => {
    if (!ui.bypass.checked) {
      setFlag('bypass', false);
      ui.bypassConfirm.hidden = true;
      return;
    }
    // Never enable on a single tap: require explicit confirmation.
    ui.bypass.checked = false;
    ui.bypassConfirm.hidden = false;
  });
  ui.bypassNo.addEventListener('click', () => {
    ui.bypassConfirm.hidden = true;
  });
  ui.bypassYes.addEventListener('click', async () => {
    ui.bypassConfirm.hidden = true;
    await setFlag('bypass', true);
  });

  ui.addForm.addEventListener('submit', (event) => {
    event.preventDefault();
    addTarget(ui.pkg.value.trim());
  });

  ui.refresh.addEventListener('click', refresh);
  ui.autoRefresh.addEventListener('change', () => setAutoRefresh(ui.autoRefresh.checked));
}

async function boot() {
  ui.bridge.textContent = hasKsu ? 'KernelSU WebUI' : 'Local HTTP';
  ui.bridge.className = 'pill ok';
  wireEvents();
  await refresh();
  loadInstalled();
}

boot();
