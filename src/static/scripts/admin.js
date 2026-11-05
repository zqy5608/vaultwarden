"use strict";
/* exported BASE_URL, _post, _delete */

function getBaseUrl() {
    // If the base URL is `https://vaultwarden.example.com/base/path/admin/`,
    // `window.location.href` should have one of the following forms:
    //
    // - `https://vaultwarden.example.com/base/path/admin`
    // - `https://vaultwarden.example.com/base/path/admin/#/some/route[?queryParam=...]`
    //
    // We want to get to just `https://vaultwarden.example.com/base/path`.
    const pathname = window.location.pathname;
    const adminPos = pathname.indexOf("/admin");
    const newPathname = pathname.substring(0, adminPos != -1 ? adminPos : pathname.length);
    return `${window.location.origin}${newPathname}`;
}
const BASE_URL = getBaseUrl();

function reload() {
    // Reload the page by setting the exact same href
    // Using window.location.reload() could cause a repost.
    window.location = window.location.href;
}

function msg(text, reload_page = true) {
    text && alert(text);
    reload_page && reload();
}

function _fetch(method, url, successMsg, errMsg, body, reload_page = true) {
    let respStatus;
    let respStatusText;
    fetch(url, {
        method: method,
        body: body,
        mode: "same-origin",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" }
    }).then(resp => {
        if (resp.ok) {
            msg(successMsg, reload_page);
            // Abuse the catch handler by setting error to false and continue
            return Promise.reject({ error: false });
        }
        respStatus = resp.status;
        respStatusText = resp.statusText;
        return resp.text();
    }).then(respText => {
        try {
            const respJson = JSON.parse(respText);
            if (respJson.errorModel && respJson.errorModel.message) {
                return respJson.errorModel.message;
            } else {
                return Promise.reject({ body: `${respStatus} - ${respStatusText}\n\nUnknown error`, error: true });
            }
        } catch (e) {
            return Promise.reject({ body: `${respStatus} - ${respStatusText}\n\n[Catch] ${e}`, error: true });
        }
    }).then(apiMsg => {
        msg(`${errMsg}\n${apiMsg}`, reload_page);
    }).catch(e => {
        if (e.error === false) { return true; }
        else { msg(`${errMsg}\n${e.body}`, reload_page); }
    });
}

function _post(url, successMsg, errMsg, body, reload_page = true) {
    return _fetch("POST", url, successMsg, errMsg, body, reload_page);
}

function _delete(url, successMsg, errMsg, body, reload_page = true) {
    return _fetch("DELETE", url, successMsg, errMsg, body, reload_page);
}

function createScopedCredential(url, body) {
    fetch(url, {
        method: "POST",
        body: JSON.stringify(body),
        mode: "same-origin",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" }
    }).then(async (resp) => {
        const text = await resp.text();
        let data = {};
        try {
            data = JSON.parse(text);
        } catch (e) {
            data = {};
        }
        if (!resp.ok) {
            msg(data.message || text || "Request failed", false);
            return;
        }
        const panel = document.getElementById("agent-secret-panel");
        const value = document.getElementById("agent-secret-value");
        if (panel && value) {
            value.textContent = data.token || "";
            panel.hidden = false;
        }
    }).catch(() => {
        msg("Request failed", false);
    });
}

// Bootstrap Theme Selector
const getStoredTheme = () => localStorage.getItem("theme");
const setStoredTheme = theme => localStorage.setItem("theme", theme);

const getPreferredTheme = () => {
    const storedTheme = getStoredTheme();
    if (storedTheme) {
        return storedTheme;
    }

    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
};

const setTheme = theme => {
    if (theme === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        document.documentElement.setAttribute("data-bs-theme", "dark");
    } else {
        document.documentElement.setAttribute("data-bs-theme", theme);
    }
};

setTheme(getPreferredTheme());

const showActiveTheme = (theme, focus = false) => {
    const themeSwitcher = document.querySelector("#bd-theme");

    if (!themeSwitcher) {
        return;
    }

    const themeSwitcherText = document.querySelector("#bd-theme-text");
    const activeThemeIcon = document.querySelector(".theme-icon-active use");
    const btnToActive = document.querySelector(`[data-bs-theme-value="${theme}"]`);
    if (!btnToActive) {
        return;
    }
    const btnIconUse = btnToActive ? btnToActive.querySelector("[data-theme-icon-use]") : null;
    const iconHref = btnIconUse ? btnIconUse.getAttribute("href") || btnIconUse.getAttribute("xlink:href") : null;

    document.querySelectorAll("[data-bs-theme-value]").forEach(element => {
        element.classList.remove("active");
        element.setAttribute("aria-pressed", "false");
    });

    btnToActive.classList.add("active");
    btnToActive.setAttribute("aria-pressed", "true");

    if (iconHref && activeThemeIcon) {
        activeThemeIcon.setAttribute("href", iconHref);
        activeThemeIcon.setAttribute("xlink:href", iconHref);
    }

    const themeSwitcherLabel = `${themeSwitcherText.textContent} (${btnToActive.dataset.bsThemeValue})`;
    themeSwitcher.setAttribute("aria-label", themeSwitcherLabel);

    if (focus) {
        themeSwitcher.focus();
    }
};

window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    const storedTheme = getStoredTheme();
    if (storedTheme !== "light" && storedTheme !== "dark") {
        setTheme(getPreferredTheme());
    }
});


// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    showActiveTheme(getPreferredTheme());

    document.querySelectorAll("[data-bs-theme-value]")
        .forEach(toggle => {
            toggle.addEventListener("click", () => {
                const theme = toggle.getAttribute("data-bs-theme-value");
                setStoredTheme(theme);
                setTheme(theme);
                showActiveTheme(theme, true);
            });
        });

    const agentTokenForm = document.getElementById("agent-token-form");
    const fillAgentForm = document.getElementById("fill-agent-form");
    if (agentTokenForm) {
        agentTokenForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const folderIds = document.getElementById("agent-folder-ids").value
                .split(",")
                .map((value) => value.trim())
                .filter(Boolean);
            createScopedCredential(`${BASE_URL}/admin/agent/tokens`, {
                userEmail: document.getElementById("agent-user-email").value,
                name: document.getElementById("agent-token-name").value,
                folderIds,
            });
        });
    }
    if (fillAgentForm) {
        fillAgentForm.addEventListener("submit", (event) => {
            event.preventDefault();
            createScopedCredential(`${BASE_URL}/admin/agent/fill-agents`, {
                userEmail: document.getElementById("fill-agent-email").value,
                name: document.getElementById("fill-agent-name").value,
            });
        });
    }
    const secretDone = document.getElementById("agent-secret-done");
    if (secretDone) {
        secretDone.addEventListener("click", reload);
    }
    document.querySelectorAll("[data-agent-revoke]").forEach((button) => {
        button.addEventListener("click", () => {
            const kind = button.getAttribute("data-agent-revoke");
            const id = button.getAttribute("data-agent-id");
            if (!id || !confirm("Revoke this credential?")) {
                return;
            }
            const path = kind === "fill" ? "fill-agents" : "tokens";
            _post(`${BASE_URL}/admin/agent/${path}/${id}/revoke`, "Credential revoked", "Revoke failed", "{}");
        });
    });

    // get current URL path and assign "active" class to the correct nav-item
    const pathname = window.location.pathname;
    if (pathname === "") return;
    const navItem = document.querySelectorAll(`.navbar-nav .nav-item a[href="${pathname}"]`);
    if (navItem.length === 1) {
        navItem[0].className = navItem[0].className + " active";
        navItem[0].setAttribute("aria-current", "page");
    }
});
