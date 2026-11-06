import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import path from 'node:path';

// Use only against a disposable local instance with a test credential.
export async function checkAdminLogin(page, baseUrl, token) {
    const base = baseUrl.replace(/\/$/, '');
    await page.goto(`${base}/admin/logout`);
    await page.goto(`${base}/admin/agents`);
    await page.fill('#admin-token', `${token}-invalid`);
    await page.click('button[type="submit"]');
    await page.waitForSelector('.alert-danger');
    assert.equal(await page.evaluate(() => document.querySelector('#redirect').value), '/agents');
    await page.fill('#admin-token', token);
    await page.click('button[type="submit"]');
    await page.waitForSelector('#agent-token-form');
    assert.equal(await page.url(), `${base}/admin/agents`);
    assert.equal(await page.evaluate(() => document.querySelector('.admin-primary-nav .active')?.getAttribute('aria-current')), 'page');
    console.log('Passed native invalid-login retry, redirect and active navigation');
}

// Run inside ego-browser nodejs with an existing task space and fixture directory.
export async function checkAdminUi(task, directory, screenshots) {
    const page = task.page('p1');
    const open = name => page.goto(pathToFileURL(path.join(directory, `${name}.html`)).href + '?lang=en');
    const results = [];
    const pages = ['settings', 'users', 'organizations', 'diagnostics', 'agents', 'login', 'agents-empty', 'agents-acl', 'users-empty', 'organizations-empty', 'login-error'];
    for (const width of [390, 1024, 1536]) {
        await page.cdp('Emulation.setDeviceMetricsOverride', { width, height: 1050, deviceScaleFactor: 1, mobile: false });
        for (const name of pages) {
            await open(name);
            const state = await page.evaluate(() => ({
                overflow: document.documentElement.scrollWidth > innerWidth,
                errors: window.__previewErrors,
                brokenImages: [...document.images].filter(image => image.complete && image.naturalWidth === 0).length,
            }));
            assert.equal(state.overflow, false, `${name} at ${width}: page overflow`);
            assert.deepEqual(state.errors, [], `${name} at ${width}: runtime errors`);
            assert.equal(state.brokenImages, 0, `${name}: broken image`);
            if (screenshots && [390, 1536].includes(width) && !name.includes('-')) {
                await page.screenshot({ path: path.join(screenshots, `${name}-${width}.png`), fullPage: true });
            }
        }
        results.push(`${pages.length} pages at ${width}px`);
    }

    await open('agents');
    await page.cdp('Emulation.setDeviceMetricsOverride', { width: 390, height: 1050, deviceScaleFactor: 1, mobile: false });
    await page.click('button[aria-label="Toggle navigation"]');
    await page.waitForFunction(() => document.querySelector('#navbarCollapse').classList.contains('show'));
    assert.equal(await page.evaluate(() => document.querySelector('.navbar-toggler').getAttribute('aria-expanded')), 'true');
    await page.click('#bd-theme');
    await page.click('[data-bs-theme-value="dark"]');
    assert.equal(await page.evaluate(() => document.documentElement.dataset.bsTheme), 'dark');
    await page.click('#bd-theme');
    await page.click('[data-bs-theme-value="light"]');
    assert.equal(await page.evaluate(() => document.documentElement.dataset.bsTheme), 'light');
    await page.click('button[aria-label="Toggle navigation"]');
    await page.waitForFunction(() => !document.querySelector('#navbarCollapse').classList.contains('show'));
    results.push('Mobile navigation and theme switching');

    const mockRequests = async () => page.evaluate(() => {
        window.__previewAlerts = [];
        window.__previewRequests = [];
        window.__previewReloads = 0;
        window.alert = message => window.__previewAlerts.push(message);
        window.confirm = () => false;
        window.reload = () => { window.__previewReloads += 1; };
        window.fetch = async (url, options = {}) => {
            window.__previewRequests.push({ url: String(url), method: options.method, body: options.body });
            return new Response(JSON.stringify(String(url).includes('/folders?')
                ? { folders: [{ id: '11111111-2222-4333-8444-555555555555', label: 'Work' }, { id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', label: 'Personal' }] }
                : { token: 'preview-only-not-a-valid-credential' }), { status: 200 });
        };
    });
    await mockRequests();
    await page.fill('#agent-user-email', 'user@example.com');
    await page.fill('#agent-token-name', 'Browser assistant');
    await page.waitForFunction(() => document.querySelectorAll('#agent-folder-list input').length === 2);
    await page.click('#agent-folder-all');
    await page.click('#agent-token-form button[type="submit"]');
    await page.waitForFunction(() => !document.querySelector('#agent-secret-panel').hidden);
    const created = await page.evaluate(() => JSON.parse(window.__previewRequests.find(request => request.url.endsWith('/agent/tokens')).body));
    assert.equal(created.userEmail, 'user@example.com');
    assert.equal(created.folderIds.length, 2);
    await page.click('#agent-secret-done');
    await page.waitForFunction(() => document.querySelector('#agent-secret-panel')?.hidden);
    results.push('AI token creation, selected folders, one-time credential and Done');

    await open('agents');
    await mockRequests();
    await page.click('#fill-tab');
    await page.waitForSelector('#fill-create.show');
    assert.equal(await page.evaluate(() => document.querySelector('#fill-tab').getAttribute('aria-selected')), 'true');
    await page.fill('#fill-agent-email', 'user@example.com');
    await page.fill('#fill-agent-name', 'MacBook');
    await page.click('#fill-agent-form button[type="submit"]');
    await page.waitForFunction(() => !document.querySelector('#agent-secret-panel').hidden);
    assert.equal(await page.evaluate(() => window.__previewRequests.some(request => request.url.endsWith('/agent/fill-agents'))), true);
    await page.click('css=[data-agent-revoke="token"] >> nth=0');
    assert.equal(await page.evaluate(() => window.__previewRequests.some(request => request.url.endsWith('/revoke'))), false);
    await page.evaluate(() => { window.confirm = () => true; });
    await page.click('css=[data-agent-revoke="token"] >> nth=0');
    await page.waitForFunction(() => window.__previewRequests.some(request => request.url.endsWith('/revoke')));
    results.push('Fill-agent tab/creation and cancel/confirm revocation');

    await open('agents-acl');
    await mockRequests();
    await page.fill('#agent-user-email', 'user@example.com');
    await page.fill('#agent-token-name', 'Scoped assistant');
    await page.waitForFunction(() => document.querySelectorAll('#agent-folder-list input').length === 2);
    await page.click('#agent-token-form button[type="submit"]');
    assert.equal(await page.evaluate(() => window.__previewAlerts.some(message => message.includes('Select at least one folder'))), true);
    assert.equal(await page.evaluate(() => window.__previewRequests.some(request => request.url.endsWith('/agent/tokens'))), false);
    await page.click('#agent-folder-all');
    await page.click('#agent-token-form button[type="submit"]');
    await page.waitForFunction(() => !document.querySelector('#agent-secret-panel').hidden);
    results.push('Required folder ACL blocks empty selection and permits selected folders');

    await open('agents');
    await mockRequests();
    await page.fill('#agent-user-email', 'user@example.com');
    await page.fill('#agent-token-name', 'Session test');
    await page.waitForFunction(() => document.querySelectorAll('#agent-folder-list input').length === 2);
    await page.evaluate(() => { window.fetch = async () => new Response('<html>Login required</html>', { status: 401 }); });
    await page.click('#agent-token-form button[type="submit"]');
    await page.waitForFunction(() => window.__previewAlerts.length > 0);
    assert.equal(await page.evaluate(() => document.querySelector('#agent-secret-panel').hidden), true);
    assert.equal(await page.evaluate(() => window.__previewAlerts[0].includes('401')), true);
    results.push('Expired admin session gives feedback without revealing a credential');

    await open('settings');
    await mockRequests();
    await page.click('#b_general');
    await page.waitForSelector('#g_general.show');
    await page.click('[data-vw-pw-toggle="input_admin_token"]');
    assert.equal(await page.evaluate(() => document.querySelector('#input_admin_token').type), 'text');
    await page.click('[data-vw-pw-toggle="input_admin_token"]');
    assert.equal(await page.evaluate(() => document.querySelector('#input_admin_token').type), 'password');
    await page.click('#config-form button[type="submit"]');
    await page.waitForFunction(() => window.__previewRequests.some(request => request.url.endsWith('/admin/config')));
    results.push('Settings accordion, password masking and existing save endpoint');

    await open('users');
    await page.fill('#users-block .dt-search input', 'does-not-exist');
    await page.waitForFunction(() => document.querySelector('#users-table tbody').textContent.includes('No matching records'));
    await page.fill('#users-block .dt-search input', '');
    await page.waitForFunction(() => document.querySelector('#users-table tbody').textContent.includes('Demo user'));
    results.push('Users table search/empty results');
    console.log({ passed: results });
    return results;
}
