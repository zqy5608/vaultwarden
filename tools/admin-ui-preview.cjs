// Render the real templates with fixtures, without a running vault or credentials.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Handlebars = require('handlebars');

const root = path.resolve(__dirname, '..');
const output = path.resolve(process.argv[2] || 'tmp/admin-ui-preview');
const staging = process.argv[3] && path.resolve(process.argv[3]);
const templates = staging ? path.join(staging, 'templates') : path.join(root, 'src/static/templates/admin');
assert.notEqual(output, root, 'Choose a separate output directory');
const hb = Handlebars.create();
hb.registerHelper('eq', (a, b) => a === b);
hb.registerHelper('case', function (value, ...args) {
    const options = args.pop();
    return args.includes(value) ? options.fn(this) : options.inverse(this);
});
hb.registerHelper('to_json', value => new hb.SafeString(JSON.stringify(value).replace(/</g, '\\u003c')));
for (const file of fs.readdirSync(templates).filter(file => file.endsWith('.hbs'))) {
    hb.registerPartial(`admin/${path.basename(file, '.hbs')}`, fs.readFileSync(path.join(templates, file), 'utf8'));
}
const render = hb.compile(fs.readFileSync(path.join(templates, 'base.hbs'), 'utf8'), { strict: true });
const element = (name, type, value, editable = true) => ({
    name, type, value, editable, overridden: false, default: '', doc: { name, description: 'Preview setting' },
});
const user = {
    id: '11111111-2222-4333-8444-555555555555', name: 'Demo user', email: 'user@example.com',
    user_enabled: true, twoFactorEnabled: true, emailVerified: true, _status: 0,
    created_at: '2026-11-05 10:00:00', last_active: '2026-11-06 12:06:00',
    cipher_count: 42, attachment_count: 0, attachment_size: '0 B', sso_identifier: 'demo-user', organizations: [],
};
const org = {
    id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', name: 'Demo workspace', billingEmail: 'team@example.com',
    user_count: 2, cipher_count: 12, attachment_count: 0, attachment_size: '0 B',
    collection_count: 2, group_count: 1, event_count: 8,
};
const token = {
    id: 'demo-token', email: user.email, name: 'Browser assistant', tokenPrefix: 'demo-prefix',
    folders: [], unrestricted: true, createdAt: '2026-11-05', revoked: false,
};
const agents = {
    enabled: true, requireFolderAcl: false,
    tokens: [token, { ...token, id: 'research-token', name: 'Research assistant', unrestricted: false, folders: [{ id: 'work-folder', label: 'Work' }] },
        { ...token, id: 'old-token', name: 'Old workstation', revoked: true }],
    fillAgents: [{ ...token, id: 'c43f-demo-92b1', name: 'MacBook' }, { ...token, id: 'a71e-demo-30dc', name: 'Desktop' }],
    audit: [
        { createdAt: '2026-11-06 12:06', action: 'ticket_create', detail: 'created', origin: 'https://example.com', ip: '127.0.0.1' },
        { createdAt: '2026-11-06 12:05', action: 'redeem', detail: 'redeemed', origin: 'https://example.com', ip: '127.0.0.1' },
        { createdAt: '2026-11-06 11:58', action: 'deny', detail: 'origin_not_allowed', origin: 'https://example.com', ip: '127.0.0.1' },
    ],
};
const diagnostics = {
    current_release: '1.0.0-demo', latest_release: '1.0.0-demo', latest_commit: '2b97177',
    active_web_release: '2026.10.0', latest_web_release: '2026.10.0', web_vault_enabled: true,
    db_type: 'SQLite', db_version: '3.x', host_os: 'linux', host_arch: 'x86_64',
    running_within_container: true, container_base_image: 'debian', config_file_status: 'Loaded',
    overrides: '', invalid_env_vars: '', template_overrides: '', ip_header_exists: true,
    ip_header_match: true, ip_header_name: 'CF-Connecting-IP', ip_header_config: 'CF-Connecting-IP',
    has_http_access: true, uses_proxy: false, enable_websocket: true, dns_resolved: '192.0.2.1',
    tz_env: 'UTC', server_time: '2026-11-06 12:06:00 UTC', server_time_local: '2026-11-06 12:06:00 UTC',
    ntp_time: '2026-11-06 12:06:00 UTC', admin_url: 'https://vault.example.com/admin', invalid_feature_flags: '',
};
const settings = {
    can_backup: true,
    config: [
        { group: 'general', groupdoc: 'General settings', elements: [element('domain', 'text', 'https://vault.example.com'), element('signups_allowed', 'checkbox', false), element('invitations_allowed', 'checkbox', true), element('admin_token', 'password', '$argon2-preview-not-a-credential')] },
        { group: 'agent', groupdoc: 'Agent API', elements: [element('agent_api_enabled', 'checkbox', true), element('agent_require_folder_acl', 'checkbox', false), element('agent_reveal_usernames', 'checkbox', false)] },
        { group: 'smtp', groupdoc: 'SMTP Email Settings', elements: [element('smtp_host', 'text', ''), element('smtp_port', 'number', 587), element('smtp_password', 'password', '')] },
        { group: 'readonly', groupdoc: '', elements: [element('database_url', 'text', 'data/db.sqlite3', false), element('disable_admin_token', 'checkbox', false, false)] },
    ],
};
const fixtures = [
    ['settings', settings], ['users', [user]], ['organizations', [org]], ['diagnostics', diagnostics], ['agents', agents],
    ['login', null], ['login-error', null, 'login'], ['agents-empty', { ...agents, enabled: false, tokens: [], fillAgents: [], audit: [] }, 'agents'],
    ['agents-acl', { ...agents, requireFolderAcl: true }, 'agents'], ['users-empty', [], 'users'], ['organizations-empty', [], 'organizations'],
];
fs.mkdirSync(path.join(output, 'vw_static'), { recursive: true });
for (const folder of ['scripts', 'images']) {
    for (const file of fs.readdirSync(path.join(root, 'src/static', folder))) {
        if (!fs.statSync(path.join(root, 'src/static', folder, file)).isFile()) continue;
        const override = staging && path.join(staging, folder, file);
        fs.copyFileSync(override && fs.existsSync(override) ? override : path.join(root, 'src/static', folder, file), path.join(output, 'vw_static', file));
    }
}
for (const [name, data, template = name] of fixtures) {
    let html = render({ page_content: `admin/${template}`, page_data: data, logged_in: template !== 'login',
        urlpath: '', sso_enabled: true, error: name === 'login-error' ? 'Invalid admin token. Please try again.' : null,
        redirect: template === 'login' ? 'admin/agents' : null });
    const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
    assert.equal(ids.length, new Set(ids).size, `${name}: duplicate IDs`);
    assert.equal((html.match(/<h1[ >]/g) || []).length, 1, `${name}: one page heading`);
    assert.ok(!html.includes('{{'), `${name}: unresolved template expression`);
    for (const id of ['bd-theme', 'bd-theme-text', 'navbarCollapse', 'admin-content']) assert.ok(ids.includes(id), `${name}: missing ${id}`);
    if (template === 'agents') {
        for (const id of ['agent-token-form', 'fill-agent-form', 'agent-folder-list', 'agent-secret-panel']) assert.ok(ids.includes(id));
        assert.ok(html.includes(`data-require-folder-acl="${data.requireFolderAcl}"`));
    }
    // Keep fixtures offline: diagnostics' live HTTP/WebSocket probes are not preview data.
    html = html.replace('<script src="/vw_static/admin_diagnostics.js"></script>', '');
    html = html.replace('<head>', `<head><script>window.__previewErrors=[];window.addEventListener('error',e=>window.__previewErrors.push(e.message));window.__previewRequests=[];window.fetch=async(url,options={})=>{window.__previewRequests.push({url:String(url),...options});throw new Error('No backend in static preview');};</script>`);
    html = html.replaceAll('="/vw_static/', '="./vw_static/');
    fs.writeFileSync(path.join(output, `${name}.html`), html);
}
console.log(`Rendered and checked ${fixtures.length} fixture pages in ${output}`);
