import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export async function checkAdminChinese(task, directory, screenshots) {
    const page = task.page('p1');
    const open = name => page.goto(pathToFileURL(path.join(directory, `${name}.html`)).href + '?lang=zh-CN');
    const names = ['settings', 'users', 'organizations', 'diagnostics', 'agents', 'login', 'agents-empty', 'agents-acl', 'users-empty', 'organizations-empty', 'login-error'];
    for (const width of [320, 390, 1536]) {
        await page.cdp('Emulation.setDeviceMetricsOverride', { width, height: 1050, deviceScaleFactor: 1, mobile: false });
        for (const name of names) {
            await open(name);
            const state = await page.evaluate(() => ({ language: document.documentElement.lang,
                overflow: document.documentElement.scrollWidth > innerWidth, errors: window.__previewErrors }));
            assert.equal(state.language, 'zh-CN');
            assert.equal(state.overflow, false, `${name} at ${width}: page overflow`);
            assert.deepEqual(state.errors, [], `${name} at ${width}: script error`);
            if (screenshots && [390, 1536].includes(width) && ['settings', 'agents', 'users', 'login'].includes(name)) {
                await page.screenshot({ path: path.join(screenshots, `${name}-zh-${width}.png`), fullPage: true });
            }
        }
    }
    await open('agents');
    assert.equal(await page.evaluate(() => document.querySelector('tbody strong').textContent), 'Browser assistant');
    assert.equal(await page.evaluate(() => document.querySelector('tbody td:nth-child(2)').textContent), 'user@example.com');
    await page.evaluate(() => { window.confirm = text => { window.__localePrompt = text; return false; }; });
    await page.fill('#agent-token-name', 'Keep this input');
    await page.selectOption('#admin-language', 'en');
    assert.equal(await page.evaluate(() => document.querySelector('#admin-language').value), 'zh-CN');
    assert.equal(await page.evaluate(() => document.querySelector('#agent-token-name').value), 'Keep this input');
    assert.ok(await page.evaluate(() => window.__localePrompt.includes('未保存')));
    await page.fill('#agent-token-name', '');
    await page.evaluate(() => { document.querySelector('#agent-secret-panel').hidden = false; });
    await page.selectOption('#admin-language', 'en');
    assert.equal(await page.evaluate(() => document.querySelector('#agent-secret-panel').hidden), false);
    assert.equal(await page.evaluate(() => document.querySelector('#admin-language').value), 'zh-CN');
    await page.evaluate(() => { document.querySelector('#agent-secret-panel').hidden = true; });
    await page.selectOption('#admin-language', 'en');
    await page.waitForFunction(() => document.documentElement.lang === 'en');
    assert.ok(await page.evaluate(() => document.querySelector('h1').textContent.includes('Agent API')));
    await page.reload();
    assert.equal(await page.evaluate(() => document.documentElement.lang), 'en');
    await page.selectOption('#admin-language', 'zh-CN');
    await page.waitForFunction(() => document.documentElement.lang === 'zh-CN');

    await page.evaluate(() => {
        window.__alerts = [];
        window.alert = message => window.__alerts.push(message);
        window.fetch = async () => new Response(JSON.stringify({ message: 'User not found' }), { status: 400 });
    });
    await page.fill('#agent-user-email', 'missing@example.com');
    await page.fill('#agent-token-name', 'Test assistant');
    await page.click('#agent-token-form button[type="submit"]');
    await page.waitForFunction(() => window.__alerts.length > 0);
    assert.equal(await page.evaluate(() => window.__alerts[0]), '未找到用户');

    await open('settings');
    assert.equal(await page.evaluate(() => document.querySelector('[data-i18n-config-name="domain"]').textContent), '实例访问地址');
    assert.equal(await page.evaluate(() => document.querySelector('#input_domain').value), 'https://vault.example.com');
    assert.ok(await page.evaluate(() => document.querySelector('[data-i18n-config-description="domain"]').title.includes('DOMAIN')));
    await open('users-empty');
    assert.ok(await page.evaluate(() => document.querySelector('#users-table tbody').textContent.includes('暂无数据')));
    assert.ok(await page.evaluate(() => document.querySelector('.dt-info').textContent.includes('显示 0 条')));
    assert.equal(await page.evaluate(() => document.querySelector('.dt-length option[value="-1"]').textContent), '全部');

    await open('users');
    await page.evaluate(() => {
        window.__dialogs = [];
        window.alert = text => window.__dialogs.push(text);
        window.confirm = text => { window.__dialogs.push(text); return false; };
        const button = document.querySelector('[vw-disable-user]');
        const span = document.createElement('span'); span.textContent = button.textContent;
        button.replaceChildren(span);
    });
    await page.click('button[vw-disable-user] span');
    assert.ok(await page.evaluate(() => window.__dialogs[0].includes('user@example.com') && window.__dialogs[0].includes('禁用')));
    assert.equal(await page.evaluate(() => window.__previewRequests.length), 0);
    await page.evaluate(() => { window.prompt = text => { window.__dialogs.push(text); return 'wrong@example.com'; }; });
    await page.click('button[vw-delete-user]');
    assert.equal(await page.evaluate(() => window.__dialogs.at(-1)), '邮箱不匹配，请重试');
    assert.equal(await page.evaluate(() => window.__previewRequests.length), 0);

    await open('organizations');
    await page.evaluate(() => {
        window.__dialogs = [];
        window.confirm = text => { window.__dialogs.push(text); return true; };
        window.prompt = text => { window.__dialogs.push(text); return 'wrong-uuid'; };
        window.alert = text => window.__dialogs.push(text);
    });
    await page.click('button[vw-delete-organization]');
    assert.ok(await page.evaluate(() => window.__dialogs[0].includes('Demo workspace') && window.__dialogs[0].includes('无法撤销')));
    assert.equal(await page.evaluate(() => window.__dialogs.at(-1)), '组织 UUID 不匹配，请重试');
    assert.equal(await page.evaluate(() => window.__previewRequests.length), 0);

    await open('settings');
    await page.evaluate(() => {
        window.__dialogs = [];
        window.prompt = text => { window.__dialogs.push(text); return '删除'; };
        window.alert = text => window.__dialogs.push(text);
    });
    await page.click('#deleteConf');
    assert.ok(await page.evaluate(() => window.__dialogs[0].includes('DELETE')));
    assert.equal(await page.evaluate(() => window.__previewRequests.length), 0, 'The confirmation keyword must remain DELETE');
    console.log('Passed 33 Chinese layouts, preserved user/config data, both locale directions, reload persistence, unsaved/one-time credential guards, Chinese errors and table controls.');
}
