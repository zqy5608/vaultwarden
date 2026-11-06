"use strict";
/* global AdminI18n */
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
    text && alert(AdminI18n.message(text));
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

let agentFolderRequest = 0;
let agentFoldersLoadedFor = "";
let agentFoldersDisplayedFor = "";
let agentFolderPending = null;
let agentFolderPendingEmail = "";
let agentFolderLoadTimer = 0;
const AGENT_FOLDER_LOAD_DELAY_MS = 300;

function agentEmailLooksUsable(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

// Missing controls must not throw. A stale page used to read .value of a removed node and the click died.
function agentFieldValue(id) {
    const field = document.getElementById(id);
    if (!field || typeof field.value !== "string") {
        return null;
    }
    return field.value;
}

function agentFolderEmailStillCurrent(normalized) {
    const field = document.getElementById("agent-user-email");
    return field !== null && field.value.trim().toLowerCase() === normalized;
}

// Bump the request counter so an in-flight lookup cannot paint folders for a previous email.
function dropStaleAgentFolderRequest(normalized) {
    if (agentFolderPendingEmail && agentFolderPendingEmail !== normalized) {
        agentFolderRequest += 1;
        agentFolderPending = null;
        agentFolderPendingEmail = "";
    }
    if (agentFoldersDisplayedFor === normalized && normalized !== "") {
        agentFoldersLoadedFor = normalized;
        return;
    }
    agentFoldersLoadedFor = "";
}

function scheduleAgentFolderLoad(email, delay) {
    if (agentFolderLoadTimer) {
        clearTimeout(agentFolderLoadTimer);
        agentFolderLoadTimer = 0;
    }
    const normalized = email.trim().toLowerCase();
    dropStaleAgentFolderRequest(normalized);
    if (!agentEmailLooksUsable(email)) {
        setAgentFolderStatus("");
        setAgentFolderMessage("Enter a user email to load folders.");
        return;
    }
    if (agentFoldersLoadedFor === normalized || agentFolderPendingEmail === normalized) {
        return;
    }
    if (agentFoldersDisplayedFor && agentFoldersDisplayedFor !== normalized) {
        setAgentFolderStatus("");
        setAgentFolderMessage("Loading folders…");
    }
    const startLoad = () => {
        agentFolderLoadTimer = 0;
        if (!agentFolderEmailStillCurrent(normalized)) {
            return;
        }
        const emailValue = agentFieldValue("agent-user-email");
        if (emailValue === null) {
            return;
        }
        loadAgentFolders(emailValue);
    };
    if (delay <= 0) {
        startLoad();
        return;
    }
    agentFolderLoadTimer = setTimeout(startLoad, delay);
}

function setAgentFolderStatus(text) {
    const status = document.getElementById("agent-folder-status");
    if (status) {
        status.textContent = AdminI18n.t(text || "");
    }
}

function setAgentFolderMessage(text) {
    const list = document.getElementById("agent-folder-list");
    const actions = document.getElementById("agent-folder-actions");
    if (!list) {
        return;
    }
    if (actions) {
        actions.hidden = true;
    }
    agentFoldersDisplayedFor = "";
    list.replaceChildren();
    const note = document.createElement("span");
    note.className = "text-body-secondary";
    note.textContent = AdminI18n.t(text);
    list.appendChild(note);
}

function agentJsonBody(text) {
    try {
        const data = JSON.parse(text);
        if (data && typeof data === "object") {
            return data;
        }
    } catch (e) {
        return null;
    }
    return null;
}

function agentServerMessage(data) {
    if (!data) {
        return "";
    }
    if (typeof data.message === "string" && data.message.trim()) {
        return data.message.trim();
    }
    if (data.errorModel && typeof data.errorModel.message === "string" && data.errorModel.message.trim()) {
        return data.errorModel.message.trim();
    }
    return "";
}

function agentFailureMessage(resp, data, fallback) {
    const server = agentServerMessage(data);
    if (server) {
        return AdminI18n.t(server);
    }
    const status = resp && resp.status ? String(resp.status) : "";
    const statusText = resp && resp.statusText ? String(resp.statusText) : "";
    const label = [status, statusText].filter(Boolean).join(" ");
    return label ? `${AdminI18n.t(fallback)} (${label})` : AdminI18n.t(fallback);
}

function reportAgentFolderFailure(message) {
    setAgentFolderMessage(message);
    msg(message, false);
}

function agentFolderChoices(folders) {
    const rows = folders.filter((folder) => folder && folder.id).map((folder) => ({
        id: String(folder.id),
        text: String(folder.label || folder.name || folder.id)
    }));
    const counts = new Map();
    rows.forEach((folder) => {
        counts.set(folder.text, (counts.get(folder.text) || 0) + 1);
    });
    return rows.map((folder) => ({
        id: folder.id,
        text: counts.get(folder.text) > 1 ? `${folder.text} (${folder.id.slice(0, 8)})` : folder.text
    }));
}

function loadAgentFolders(email) {
    const list = document.getElementById("agent-folder-list");
    const actions = document.getElementById("agent-folder-actions");
    const normalized = email.trim().toLowerCase();
    if (agentFolderPending && agentFolderPendingEmail === normalized) {
        return agentFolderPending;
    }
    agentFoldersLoadedFor = "";
    agentFoldersDisplayedFor = "";
    if (!list) {
        return Promise.resolve(false);
    }
    if (!normalized) {
        setAgentFolderMessage("Enter a user email to load folders.");
        return Promise.resolve(false);
    }
    const request = ++agentFolderRequest;
    setAgentFolderStatus("");
    setAgentFolderMessage("Loading folders…");
    const url = `${BASE_URL}/admin/agent/users/folders?email=${encodeURIComponent(email.trim())}`;
    const pending = fetch(url, {
        method: "GET",
        mode: "same-origin",
        credentials: "same-origin",
        headers: { "Accept": "application/json" }
    }).then(async (resp) => {
        if (request !== agentFolderRequest) {
            return false;
        }
        const text = await resp.text();
        if (request !== agentFolderRequest || !agentFolderEmailStillCurrent(normalized)) {
            return false;
        }
        const data = agentJsonBody(text);
        if (!resp.ok || !data || !Array.isArray(data.folders)) {
            reportAgentFolderFailure(agentFailureMessage(resp, data, "Could not load folders"));
            return false;
        }
        const folders = agentFolderChoices(data.folders);
        list.replaceChildren();
        if (folders.length === 0) {
            if (actions) {
                actions.hidden = true;
            }
            const note = document.createElement("span");
            note.className = "text-body-secondary";
            const tokenForm = document.getElementById("agent-token-form");
            const requireAcl = tokenForm !== null && tokenForm.dataset.requireFolderAcl === "true";
            note.textContent = AdminI18n.t(requireAcl
                ? "This user has no folders. Create a folder in the vault, or turn off the folder allowlist requirement."
                : "This user has no folders. The token can still see eligible personal logins.");
            list.appendChild(note);
        } else {
            if (actions) {
                actions.hidden = false;
            }
            folders.forEach((folder) => {
                const row = document.createElement("div");
                row.className = "form-check";
                const input = document.createElement("input");
                input.className = "form-check-input";
                input.type = "checkbox";
                input.value = folder.id;
                input.id = `agent-folder-${folder.id}`;
                const label = document.createElement("label");
                label.className = "form-check-label";
                label.htmlFor = input.id;
                label.textContent = folder.text;
                label.title = folder.id;
                row.append(input, label);
                list.appendChild(row);
            });
        }
        agentFoldersLoadedFor = normalized;
        agentFoldersDisplayedFor = normalized;
        return true;
    }).catch(() => {
        if (request !== agentFolderRequest || !agentFolderEmailStillCurrent(normalized)) {
            return false;
        }
        reportAgentFolderFailure("Could not load folders.");
        return false;
    });
    agentFolderPending = pending;
    agentFolderPendingEmail = normalized;
    pending.finally(() => {
        if (agentFolderPending === pending) {
            agentFolderPending = null;
            agentFolderPendingEmail = "";
        }
    });
    return pending;
}

function revealAgentSecret(token) {
    const panel = document.getElementById("agent-secret-panel");
    const value = document.getElementById("agent-secret-value");
    if (!panel || !value) {
        return;
    }
    value.textContent = token;
    panel.hidden = false;
    const show = () => {
        try {
            if (typeof panel.scrollIntoView === "function") {
                panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
            }
        } catch (e) {
            // The credential is already visible when the browser cannot scroll.
        }
    };
    if (typeof requestAnimationFrame === "function") {
        requestAnimationFrame(show);
    } else {
        show();
    }
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
        const data = agentJsonBody(text);
        if (!resp.ok || !data || typeof data.token !== "string") {
            msg(agentFailureMessage(resp, data, "Request failed"), false);
            return;
        }
        revealAgentSecret(data.token);
    }).catch(() => {
        msg("Request failed", false);
    });
}

// Bootstrap Theme Selector
const getStoredTheme = () => {
    try { return localStorage.getItem("theme"); } catch (_) { return null; }
};
const setStoredTheme = theme => {
    try { localStorage.setItem("theme", theme); } catch (_) { /* Keep this page usable without storage. */ }
};

const getPreferredTheme = () => {
    const storedTheme = getStoredTheme();
    if (storedTheme) {
        return storedTheme;
    }

    return "light";
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

    const themeSwitcherLabel = `${themeSwitcherText.textContent} (${AdminI18n.t({ light: "Light", dark: "Dark", auto: "Auto" }[theme])})`;
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
    const agentUserEmail = document.getElementById("agent-user-email");
    if (agentUserEmail) {
        agentUserEmail.addEventListener("input", () => {
            scheduleAgentFolderLoad(agentUserEmail.value, AGENT_FOLDER_LOAD_DELAY_MS);
        });
        agentUserEmail.addEventListener("change", () => {
            scheduleAgentFolderLoad(agentUserEmail.value, 0);
        });
        agentUserEmail.addEventListener("blur", () => {
            scheduleAgentFolderLoad(agentUserEmail.value, 0);
        });
    }
    const folderAll = document.getElementById("agent-folder-all");
    const folderNone = document.getElementById("agent-folder-none");
    if (folderAll) {
        folderAll.addEventListener("click", () => {
            document.querySelectorAll("#agent-folder-list input[type=checkbox]").forEach((input) => {
                input.checked = true;
            });
        });
    }
    if (folderNone) {
        folderNone.addEventListener("click", () => {
            document.querySelectorAll("#agent-folder-list input[type=checkbox]").forEach((input) => {
                input.checked = false;
            });
        });
    }
    if (agentTokenForm) {
        agentTokenForm.addEventListener("submit", (event) => {
            event.preventDefault();
            if (agentFolderLoadTimer) {
                clearTimeout(agentFolderLoadTimer);
                agentFolderLoadTimer = 0;
            }
            const emailValue = agentFieldValue("agent-user-email");
            const nameValue = agentFieldValue("agent-token-name");
            if (emailValue === null || nameValue === null) {
                msg("Could not read this form. Reload the page and try again.", false);
                return;
            }
            const email = emailValue.trim();
            const normalized = email.toLowerCase();
            const requireAcl = agentTokenForm.dataset.requireFolderAcl === "true";
            const selectedFolderIds = () => [...document.querySelectorAll("#agent-folder-list input[type=checkbox]:checked")]
                .map((input) => input.value);
            const createToken = (folderIds) => {
                setAgentFolderStatus("");
                createScopedCredential(`${BASE_URL}/admin/agent/tokens`, {
                    userEmail: email,
                    name: nameValue,
                    folderIds,
                });
            };
            // Folder lookup is optional unless an allowlist is required. A failed lookup must not swallow Create.
            if (!requireAcl) {
                createToken(selectedFolderIds());
                return;
            }
            const createIfAllowed = () => {
                const folderIds = selectedFolderIds();
                if (agentFoldersLoadedFor !== normalized || folderIds.length === 0) {
                    msg("Select at least one folder. A folder allowlist is required.", false);
                    return;
                }
                createToken(folderIds);
            };
            if (agentFoldersLoadedFor === normalized && normalized !== "") {
                createIfAllowed();
                return;
            }
            loadAgentFolders(email).then((ok) => {
                if (!ok || agentFoldersLoadedFor !== normalized) {
                    return;
                }
                createIfAllowed();
            });
        });
    }
    if (fillAgentForm) {
        fillAgentForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const userEmail = agentFieldValue("fill-agent-email");
            const name = agentFieldValue("fill-agent-name");
            if (userEmail === null || name === null) {
                msg("Could not read this form. Reload the page and try again.", false);
                return;
            }
            createScopedCredential(`${BASE_URL}/admin/agent/fill-agents`, {
                userEmail,
                name,
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
            if (!id || !confirm(AdminI18n.t("Revoke this credential?"))) {
                return;
            }
            const path = kind === "fill" ? "fill-agents" : "tokens";
            _post(`${BASE_URL}/admin/agent/${path}/${id}/revoke`, "Credential revoked", "Revoke failed", "{}");
        });
    });

    // get current URL path and assign "active" class to the correct nav-item
    const pathname = window.location.pathname.replace(/\/+$/, "");
    if (pathname === "") return;
    const navItem = document.querySelectorAll(`.navbar-nav .nav-item a[href="${pathname}"]`);
    if (navItem.length === 1) {
        navItem[0].className = navItem[0].className + " active";
        navItem[0].setAttribute("aria-current", "page");
    }
});
