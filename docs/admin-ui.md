# Admin UI: Clear

## Scope and acceptance

Use the approved light concept (the second displayed preview) across Settings, Users, Organizations, Diagnostics, Agent API and login. Keep the existing Rocket/Handlebars/Bootstrap stack, endpoints, authentication, confirmation dialogs, form IDs and credential lifecycle. No new production dependency, data migration or deployment is required.

The selected reference is the light Agent API preview from 2026-11-06: pale sidebar, blue active navigation, gray canvas, white bordered panels, precise tables and a right-hand credential form. Extend this vocabulary to the other pages. The repository's Vaultwarden icon remains the brand asset. Do not invent status metrics.

## Tokens and responsive behavior

`admin.css` owns the implementation tokens: canvas `#f6f8fa`, surface `#ffffff`, text `#17212b`, muted `#596777`, border `#dfe5eb`, accent `#2563eb`, active background `#e8f0ff`, 12px panel radius, 8px control radius, system sans-serif, 14px body and 30px page headings. Retain an explicit dark/auto theme choice, with light as the default for new sessions without a saved preference.

At 992px and above use a 236px sidebar. Below that use a collapsible top navigation; keep keyboard access, visible focus, accessible labels and Bootstrap's expanded state. At 1400px and above Agent API uses inventory plus a credential column; below that put creation before inventory. Tables scroll within their panels, never the entire page. Long identifiers and one-time credentials wrap safely.

## Implementation sequence

1. Build the shell, CSS and six page layouts in a separate staging directory with fixed sample data. Use the existing templates and source assets, not a bitmap as the UI.
2. Render all pages, including empty/revoked states, and check screenshots at desktop and mobile sizes before applying templates to production source.
3. Apply verified templates, preserve backend contracts, then repeat layout checks and test navigation, themes, settings controls, credential tabs, creation/revocation and session-error handling with local mocked responses.
4. Run JavaScript syntax checks, template rendering assertions, available Rust tests and diff checks. Review before commit/push. Deploy an explicitly authorized release from a reviewed main revision, with a backup and the previous image digest available for rollback.

## Chinese and English

Keep the approved light design. The admin UI defaults to Simplified Chinese and offers an English/Simplified Chinese selector on every page, including login. Persist the choice in browser storage. Locale changes reload the page so Bootstrap and DataTables initialize consistently; ask before discarding unsaved form values or a displayed one-time credential. Do not translate vault data, user names, email addresses, identifiers, configuration values or destructive-action confirmation keywords.

Use an explicit translation catalog and opt-in template markers, never scan arbitrary DOM text. Localize static text, accessibility labels, placeholders, setting names/descriptions, table controls and client dialogs. Preserve raw diagnostic support exports in English for upstream support. Unknown server errors fall back to their original text. New upstream settings fall back to English until their catalog entry is added. No new runtime dependency or API contract is needed.

Verify both languages on all fixture pages at desktop and mobile widths; verify persistence, guarded locale switching, user-data integrity, translated errors and unchanged request bodies. Keep translation coverage checks runnable with Node.

## Reproducible preview

`tools/admin-ui-preview.cjs` renders the actual templates against deterministic fixtures and local static assets. It uses Handlebars 4.7.8 only as an isolated preview tool; the application continues to use its existing Rust Handlebars dependency. Install the preview renderer outside the repository and set `NODE_PATH` to that directory's `node_modules`, then run:

```sh
node tools/admin-ui-preview.cjs /absolute/output/directory
```

The generated HTML contains sample data and is not connected to a live server. It is the editable static artifact for screenshot QA. Do not enter real credentials in the preview.

`tools/check-admin-ui.mjs` exports `checkAdminUi(task, fixtureDirectory, screenshotDirectory)`. Run it inside `ego-browser nodejs` with the task's existing TaskSpace and an absolute fixture directory. It checks all 11 fixtures at 390, 1024 and 1536px, then exercises mobile navigation, themes, settings, credential tabs, ACL selection, creation, revocation and expired-session feedback using mocked local responses. Live diagnostic HTTP/WebSocket probes are intentionally excluded from the static fixture.

It also exports `checkAdminLogin(page, baseUrl, testToken)` for a disposable local instance. This checks that an invalid login followed by a valid one returns to `/admin/agents` with active navigation. Login rendering normalizes the redirect prefix so retrying cannot accumulate slashes.

Run `node tools/test-admin-i18n.cjs` for translation coverage and locale/guard checks. `tools/check-admin-chinese.mjs` exports `checkAdminChinese(task, fixtureDirectory, screenshotDirectory)` for Chinese layout and interaction checks, including destructive-confirmation keywords.
