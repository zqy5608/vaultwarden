const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const catalog = fs.readFileSync(path.join(root, 'src/static/scripts/admin_zh.js'), 'utf8');
const runtime = fs.readFileSync(path.join(root, 'src/static/scripts/admin_i18n.js'), 'utf8');
function load({ saved, search = '', blocked = false, dirty = false, secret = false } = {}) {
    const calls = [];
    const select = { value: '', addEventListener: (_, callback) => { select.change = callback; } };
    class Input {}
    class Textarea {}
    class Select {}
    const field = Object.assign(new Input(), { type: 'text', value: dirty ? 'changed' : '', defaultValue: '' });
    const context = vm.createContext({
        URL, URLSearchParams, HTMLInputElement: Input, HTMLTextAreaElement: Textarea, HTMLSelectElement: Select,
        localStorage: { getItem: () => { if (blocked) throw Error('blocked'); return saved; }, setItem: (...args) => { if (blocked) throw Error('blocked'); calls.push(args); } },
        window: { location: { search, href: 'https://vault.example/admin?other=1', assign: url => calls.push(url) } },
        document: { documentElement: {}, forms: [{ elements: [field] }], querySelectorAll: () => [],
            getElementById: id => id === 'admin-language' ? select : id === 'agent-secret-panel' && secret ? { hidden: false } : null,
            addEventListener: (_, callback) => { select.ready = callback; } },
        confirm: () => false,
    });
    vm.runInContext(catalog + '\n' + runtime + '\nglobalThis.i18n = AdminI18n; globalThis.zh = ADMIN_ZH;', context);
    return { context, select, calls, i18n: context.i18n };
}
const zh = load();
assert.equal(zh.i18n.language, 'zh-CN');
assert.equal(zh.context.document.documentElement.lang, 'zh-CN');
assert.equal(zh.i18n.t('Settings'), '设置');
assert.equal(zh.i18n.t('Unknown upstream message'), 'Unknown upstream message');
assert.equal(zh.i18n.t('To delete user "{email}", please type the email below', { email: 'literal<script>@example.com' }), '如要删除用户“literal<script>@example.com”，请在下方输入该邮箱');
assert.equal(load({ saved: 'en' }).i18n.t('Settings'), 'Settings');
assert.equal(load({ saved: 'zh-CN', search: '?lang=en' }).i18n.language, 'en');
assert.equal(load({ saved: 'invalid', search: '?lang=<script>' }).i18n.language, 'zh-CN');
assert.equal(load({ blocked: true }).i18n.language, 'zh-CN');
assert.equal(zh.i18n.message('Config saved correctly\nUser not found'), '配置已保存\n未找到用户');
assert.equal(zh.i18n.tableLanguage().zeroRecords, '没有匹配的记录');
assert.equal(zh.i18n.tableLanguage().lengthLabels['-1'], '全部');
for (const options of [{ dirty: true }, { secret: true }]) {
    const state = load(options);
    state.select.ready(); state.select.value = 'en'; state.select.change();
    assert.equal(state.select.value, 'zh-CN');
    assert.equal(state.calls.length, 0, 'Cancel must preserve forms and one-time credentials');
}
const state = load(); state.select.ready(); state.select.value = 'en'; state.select.change();
assert.deepEqual(state.calls, [['admin-language', 'en'], 'https://vault.example/admin?other=1']);
const blocked = load({ blocked: true }); blocked.select.ready(); blocked.select.value = 'en'; blocked.select.change();
assert.deepEqual(blocked.calls, ['https://vault.example/admin?other=1&lang=en']);

const decode = text => text.replace(/&quot;/g, '"').replace(/&#x27;|&#39;/g, "'").replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
let markers = 0;
for (const file of fs.readdirSync(path.join(root, 'src/static/templates/admin'))) {
    const html = fs.readFileSync(path.join(root, 'src/static/templates/admin', file), 'utf8');
    for (const match of html.matchAll(/data-i18n(?:-(?:title|placeholder|aria-label))?="([^"]+)"/g)) {
        if (match[1].includes('{{')) continue;
        const source = decode(match[1]).replace(/\s+/g, ' ').trim();
        assert.ok(Object.hasOwn(zh.context.zh.text, source), `${file}: missing translation for ${source}`);
        markers++;
    }
    assert.ok(!/data-i18n="{{(?:name|email|id|tokenPrefix|token)}}"/.test(html), 'Do not translate user data');
}
const config = fs.readFileSync(path.join(root, 'src/config.rs'), 'utf8').split('make_config! {\n    folders')[1].split('\nfn validate_config')[0];
let settings = 0;
for (const match of config.matchAll(/((?:\s*\/\/\/[^\n]*\n)+)\s*(\w+):\s*(?:String|Pass|bool|u\d+|i\d+|usize)/g)) {
    const entry = zh.context.zh.config[match[2]];
    assert.ok(entry?.[0], `Missing setting translation: ${match[2]}`);
    if (match[1].includes('|>')) assert.ok(entry[1], `Missing setting description: ${match[2]}`);
    settings++;
}
console.log(`Passed locale, fallback, interpolation, persistence and data-loss guards; ${markers} UI markers and ${settings} settings covered.`);
