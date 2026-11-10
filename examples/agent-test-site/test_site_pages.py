"""Small, same-origin pages for the owned authentication test service."""

from html import escape

CSS = """
:root{font-family:system-ui,-apple-system,sans-serif;color:#1e293b;background:#f5f7fb;color-scheme:light}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px 16px}
main{width:100%;max-width:480px;background:white;border:1px solid #e2e8f0;border-radius:18px;padding:32px;box-shadow:0 12px 40px #0f172a08}
.eyebrow{font-size:12px;font-weight:700;letter-spacing:.1em;color:#64748b;margin:0 0 16px}
h1{font-size:28px;letter-spacing:-.04em;margin:0 0 10px}p{color:#64748b;line-height:1.6;margin:0 0 24px}
label{display:block;font-size:14px;font-weight:600;margin:18px 0 8px}input,textarea{width:100%;padding:12px;border:1px solid #cbd5e1;border-radius:9px;font:inherit;min-width:0}textarea{min-height:140px;resize:vertical}
button{width:100%;font:inherit;font-weight:600;padding:12px;border-radius:9px;cursor:pointer;border:1px solid #2563eb;background:#2563eb;color:white;margin-top:20px}
button.secondary{background:white;color:#334155;border-color:#cbd5e1;margin-top:12px}button:disabled{opacity:.6;cursor:wait}
input:focus,button:focus-visible,a:focus-visible{outline:3px solid #bfdbfe;outline-offset:2px}a{color:#2563eb;text-decoration:none}
.foot{font-size:14px;text-align:center;margin:24px 0 0}.divider{text-align:center;color:#94a3b8;font-size:12px;margin:24px 0 0}
.notice{font-size:13px;border-top:1px solid #e2e8f0;margin-top:28px;padding-top:18px;margin-bottom:0}
.status{font-size:14px;line-height:1.6;min-height:24px;margin:18px 0 0;color:#475569;overflow-wrap:anywhere}.error{color:#b91c1c}
.account{background:#f8fafc;border:1px solid #e2e8f0;padding:16px;border-radius:10px;margin:24px 0;overflow-wrap:anywhere}
.account small{display:block;color:#64748b;margin-bottom:6px}.badge{display:inline-block;font-size:12px;color:#166534;background:#dcfce7;border-radius:100px;padding:5px 10px;margin-bottom:16px}
@media(max-width:480px){main{padding:24px}body{padding:16px}h1{font-size:25px}}
"""

SCRIPT = """
async function post(path, value = {}) {
  const response = await fetch(path, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(value)
  });
  if (!response.ok) throw new Error('verification_failed');
  return response.json();
}
async function ceremony(button, register) {
  const status = document.querySelector('#status');
  button.disabled = true;
  status.textContent = 'Complete the confirmation in your passkey provider.';
  try {
    const base = register ? '/registration/' : '/authentication/';
    const options = await post(base + 'options');
    const credential = register
      ? await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options)})
      : await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options)});
    const result = await post(base + 'verification', credential.toJSON());
    if (result.verified !== true) throw new Error('verification_failed');
    if (register) status.textContent = 'Passkey registered. Sign out to test passkey sign-in.';
    else location.assign('/profile');
  } catch (error) {
    status.textContent = error.name === 'NotAllowedError'
      ? 'Confirmation was canceled or unavailable.' : 'Sign-in could not be verified.';
  } finally {
    button.disabled = false;
  }
}
document.querySelector('#register-button')?.addEventListener('click', event => ceremony(event.currentTarget, true));
document.querySelector('#login-button')?.addEventListener('click', event => ceremony(event.currentTarget, false));
"""


def render(
    kind: str,
    *,
    username: str = "",
    error: str = "",
    note: str = "",
    verified: bool = False,
) -> str:
    account = escape(username, quote=True)
    register = kind == "register"
    title = "Create a test account" if register else "Welcome back"
    if kind == "profile":
        title = "You're signed in"
        content = f"""<section id="profile"><span class="badge">Session verified</span>
<h1>{title}</h1><p>Your authenticated session is active.</p>
<div class="account"><small>Test account</small><strong>{account}</strong></div>
<p><a id="workspace-link" href="/workspace">Open test workspace</a></p>
<button id="register-button" type="button">Register a passkey</button>
<p id="status" class="status" role="status" aria-live="polite"></p>
<form method="post" action="/logout"><button id="logout" class="secondary" type="submit">Sign out</button></form></section>"""
    elif kind == "workspace":
        title = "Test workspace"
        content = f"""<section id="workspace"><span class="badge">Authenticated workspace</span>
<h1>{title}</h1><p>Save a note to test actions in your signed-in session.</p>
<form method="post" action="/workspace"><label for="note">Test note</label>
<textarea id="note" name="note" maxlength="2048">{escape(note)}</textarea>
<button id="save-note" type="submit">Save note</button></form>
<form method="post" action="/workspace/check"><label for="expected-note">Verify saved note</label>
<input id="expected-note" name="expected" type="text" maxlength="2048" autocomplete="off">
<button id="check-note" class="secondary" type="submit">Verify note</button></form>
{'<p id="note-matches" class="status" role="status">Saved note verified.</p>' if verified else ""}
<p class="foot"><a href="/profile">Back to profile</a></p>
<form method="post" action="/logout"><button id="logout" class="secondary" type="submit">Sign out</button></form></section>"""
    else:
        action = "/register" if register else "/login"
        label = "Create test account" if register else "Sign in"
        description = (
            "Use a unique password for testing only."
            if register
            else "Test password autofill or sign in with a passkey."
        )
        content = f"""<h1>{title}</h1><p>{description}</p>
<form method="post" action="{action}">
<label for="input-email">Username</label><input id="input-email" name="username" type="text" autocomplete="username" pattern="[A-Za-z0-9_-]{{3,64}}" minlength="3" maxlength="64" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="{"new-password" if register else "current-password"}" minlength="12" maxlength="128" required>
<button id="{"register-account-button" if register else "password-submit"}" type="submit">{label}</button></form>"""
        if not register:
            content += """<div class="divider">OR</div><button id="login-button" class="secondary" type="button">Sign in with a passkey</button>
<p id="status" class="status" role="status" aria-live="polite"></p>
<p class="foot">New test account? <a href="/register">Create one</a></p>"""
        else:
            content += (
                '<p class="foot">Already registered? <a href="/login">Sign in</a></p>'
            )
    message = (
        f'<p class="status error" role="alert">{escape(error)}</p>' if error else ""
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="agent-test-user" content="{account}"><title>{title} · Agent Auth Test</title>
<link rel="stylesheet" href="/static/site.css"><script src="/static/site.js" defer></script>
</head><body><main><div class="eyebrow">AGENT AUTH TEST</div>{content}{message}
<p class="notice">Test credentials only. Keep personal passwords and accounts out of this site.</p>
</main></body></html>"""
