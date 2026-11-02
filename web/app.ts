const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const value = (id: string) => $<HTMLInputElement>(id).value;
let token = '',
  roleList: string[] = [];
function el(tag: string, text = '', className = '') {
  const n = document.createElement(tag);
  n.textContent = text;
  n.className = className;
  return n;
}
function notice(message: string, error = false) {
  $('notice').textContent = message;
  $('notice').classList.toggle('error', error);
}
function failure(e: unknown) {
  notice(e instanceof Error ? e.message : 'Request failed', true);
}
async function api(path: string, method = 'GET', body?: unknown): Promise<any> {
  const response = await fetch(path, {
    method,
    headers: {
      authorization: 'Bearer ' + token,
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? 'Request failed');
  return data;
}
function badge(text: string) {
  return el('span', text, 'badge state-' + text);
}
function addCell(row: HTMLElement, text: string, cls = '') {
  const n = el('td', text, cls);
  row.append(n);
  return n;
}
function option(select: HTMLElement, id: string, label: string) {
  const node = el('option', label) as HTMLOptionElement;
  node.value = id;
  select.append(node);
}
function download(data: unknown, name: string) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
  );
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function audit(events: any[]) {
  const root = $('audit');
  root.replaceChildren();
  for (const event of events.slice(0, 8)) {
    const row = el('tr');
    addCell(row, new Date(event.at).toLocaleTimeString([], { hour12: false }), 'mono');
    addCell(row, event.actor);
    const c = addCell(row, '');
    c.append(el('b', event.action), el('small', '#' + event.seq + ' · ' + event.hash.slice(0, 10)));
    root.append(row);
  }
  if (!events.length) {
    const row = el('tr');
    const c = addCell(row, 'No recorded activity.');
    c.setAttribute('colspan', '3');
    root.append(row);
  }
}
function button(label: string, action: () => Promise<unknown>, cls = 'ghost') {
  const b = el('button', label, cls) as HTMLButtonElement;
  b.onclick = () => {
    b.disabled = true;
    void action()
      .catch(failure)
      .finally(() => {
        b.disabled = false;
      });
  };
  return b;
}
async function mutate(path: string, body: unknown, message: string) {
  const result = await api(path, 'POST', body);
  notice(message);
  await refresh();
  return result;
}
$('connect').onclick = () => {
  token = value('token');
  $<HTMLInputElement>('device-credential').value = '';
  $('enroll-secret').hidden = true;
  void api('/api/me')
    .then(async (me) => {
      roleList = me.roles;
      $('status').textContent = me.subject + ' · ' + me.roles.join(', ');
      notice('Connected to ' + me.tenant + '. Your role controls the actions available here.');
      await refresh();
    })
    .catch(failure);
};
$('refresh').onclick = () => void refresh().catch(failure);
function approvals(plans: any[], extra?: (p: any, container: HTMLElement) => void) {
  const root = $('plans');
  root.replaceChildren();
  if (!plans.length) {
    root.className = 'empty';
    root.textContent = 'No plans created yet.';
    return;
  }
  root.className = '';
  for (const p of plans) {
    const record = el('article', '', 'record');
    record.dataset.planId = p.id;
    const top = el('header');
    top.append(el('h3', planTitle(p)), badge(p.status));
    record.append(
      top,
      el(
        'p',
        'Requested by ' +
          p.binding.requestedBy +
          ' · ' +
          new Date(p.binding.expiresAt).toLocaleTimeString() +
          ' expiry',
      ),
      el('p', p.digest, 'evidence'),
    );
    const actions = el('div', '', 'row-actions');
    if (roleList.includes('reviewer') && p.status === 'planned') {
      actions.append(
        button(
          'Approve',
          () =>
            mutate(
              '/api/plans/' + p.id + '/review',
              { digest: p.digest, approve: true },
              'Approval granted for this exact plan.',
            ),
          'primary',
        ),
        button('Reject', () =>
          mutate(
            '/api/plans/' + p.id + '/review',
            { digest: p.digest, approve: false },
            'Plan rejected.',
          ),
        ),
      );
    }
    if (roleList.includes('operator') && ['approved', 'blocked'].includes(p.status))
      actions.append(
        button(
          p.status === 'blocked' ? 'Retry known blocked step' : 'Execute',
          () =>
            mutate(
              '/api/plans/' + p.id + '/execute',
              { digest: p.digest, key: p.executionKey ?? 'execute-' + p.id },
              'Execution recorded. Inspect the result and any remaining work.',
            ),
          'primary',
        ),
      );
    actions.append(button('Export evidence', async () => download(p, 'plan-evidence.json')));
    record.append(actions);
    extra?.(p, record);
    root.append(record);
  }
}

let devices: any[] = [];
function planTitle(p: any) {
  return 'Lab firewall repair · ' + p.binding.data.deviceId;
}
function selected() {
  return devices.find((d) => d.id === value('selected-device'));
}
function detail() {
  const d = selected(),
    root = $('findings');
  root.replaceChildren();
  if (!d) return;
  for (const f of d.findings) {
    const row = el('div', '', 'rule');
    row.append(el('span', f.title), badge(f.state));
    root.append(row);
  }
}
async function refresh() {
  const d = await api('/api/overview');
  for (const id of ['transition', 'enroll-button', 'import-observation'])
    $<HTMLButtonElement>(id).disabled = !roleList.includes('operator');
  $<HTMLButtonElement>('plan-remediation').disabled = !roleList.includes('requester');
  $<HTMLButtonElement>('support').disabled = !roleList.some((r) =>
    ['viewer', 'operator'].includes(r),
  );
  devices = d.devices;
  const all = devices.flatMap((x) => x.findings);
  $('device-count').textContent = String(devices.length);
  $('failing-count').textContent = String(all.filter((x) => x.state === 'fail').length);
  $('unknown-count').textContent = String(all.filter((x) => x.state === 'unknown').length);
  $('ticket-count').textContent = String(
    d.tickets.filter((t: any) => t.status !== 'resolved').length,
  );
  const rows = $('devices');
  rows.replaceChildren();
  const select = $('selected-device'),
    previous = value('selected-device');
  select.replaceChildren();
  for (const device of devices) {
    const row = el('tr'),
      c = addCell(row, '');
    c.append(
      el('b', device.label),
      el('small', device.id + ' · ' + device.platform + ' · ' + device.region),
    );
    addCell(row, device.state);
    addCell(
      row,
      device.findings.some((f: any) => f.state === 'fail')
        ? 'Needs attention'
        : device.findings.some((f: any) => f.state === 'unknown')
          ? 'Unknown'
          : 'Passing',
    );
    addCell(row, device.snapshot?.source ?? 'No observation');
    rows.append(row);
    option(select, device.id, device.label);
  }
  if (previous) $<HTMLSelectElement>('selected-device').value = previous;
  detail();
  approvals(d.plans);
  audit(d.audit);
  const tickets = $('tickets');
  tickets.replaceChildren();
  tickets.className = d.tickets.length ? '' : 'empty';
  if (!d.tickets.length) tickets.textContent = 'No support cases.';
  for (const t of d.tickets) {
    const item = el('article', '', 'record');
    item.dataset.ticketId = t.id;
    const head = el('header');
    head.append(el('h3', t.finding + ' · ' + t.deviceId), badge(t.status));
    item.append(head, el('p', 'Opened ' + new Date(t.createdAt).toLocaleString()));
    if (roleList.includes('operator') && t.status !== 'resolved') {
      const actions = el('div', '', 'row-actions');
      if (t.status === 'open')
        actions.append(
          button('Start investigation', () =>
            mutate('/api/tickets/' + t.id, { status: 'in-progress' }, 'Investigation started.'),
          ),
        );
      actions.append(
        button('Resolve with readback', () =>
          mutate(
            '/api/tickets/' + t.id,
            { status: 'resolved' },
            'Support case resolved with passing observation.',
          ),
        ),
      );
      item.append(actions);
    }
    tickets.append(item);
  }
}
$<HTMLSelectElement>('selected-device').onchange = detail;
$('plan-remediation').onclick = () => {
  const d = selected();
  if (d)
    void mutate(
      '/api/plans',
      { deviceId: d.id, action: 'enable-lab-firewall' },
      'Plan created for independent review.',
    ).catch(failure);
};
$('support').onclick = () => {
  const d = selected();
  if (d)
    void api('/api/devices/' + d.id + '/support')
      .then((x) => download(x, 'support-bundle.json'))
      .catch(failure);
};
$('transition').onclick = () => {
  const d = selected();
  if (d)
    void mutate(
      '/api/devices/' + d.id + '/transition',
      { version: d.version, state: value('asset-state'), ownerAlias: value('owner') || null },
      'Asset transition recorded.',
    ).catch(failure);
};
$('import-observation').onclick = () => {
  const file = $<HTMLInputElement>('observation-file').files?.[0];
  if (!file || file.size > 240000) {
    notice('Choose a JSON observation smaller than 240 KB.', true);
    return;
  }
  void file
    .text()
    .then((text) =>
      mutate('/api/observations', JSON.parse(text), 'Observation validated and recorded.'),
    )
    .catch(failure);
};

$('enroll-button').onclick = () =>
  void mutate(
    '/api/devices',
    {
      id: value('enroll-id'),
      label: value('enroll-label'),
      platform: value('enroll-platform'),
      region: 'EU',
      serialAlias: 'serial-' + value('enroll-id'),
      mode: 'managed-observation',
    },
    'Observation device enrolled. Save its private credential now.',
  )
    .then((data) => {
      $<HTMLInputElement>('device-credential').value = data.deviceToken;
      $('enroll-secret').hidden = false;
    })
    .catch(failure);
$('show-credential').onclick = () => {
  const field = $<HTMLInputElement>('device-credential');
  field.type = field.type === 'password' ? 'text' : 'password';
};

$('disconnect').onclick = () => {
  token = '';
  roleList = [];
  location.reload();
};
