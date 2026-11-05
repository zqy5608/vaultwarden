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

let agentFolderRequest = 0;
let agentFoldersLoadedFor = "";
let agentFoldersDisplayedFor = "";
let agentFolderPending = null;
let agentFolderPendingEmail = "";

function setAgentFolderStatus(text) {
    const status = document.getElementById("agent-folder-status");
    if (status) {
        status.textContent = text || "";
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
    note.textContent = text;
    list.appendChild(note);
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
        let data = {};
        try {
            data = JSON.parse(text);
        } catch (e) {
            data = {};
        }
        if (!resp.ok) {
            setAgentFolderMessage(data.message || "Could not load folders.");
            return false;
        }
        const folders = agentFolderChoices(Array.isArray(data.folders) ? data.folders : []);
        list.replaceChildren();
        if (folders.length === 0) {
            if (actions) {
                actions.hidden = true;
            }
            const note = document.createElement("span");
            note.className = "text-body-secondary";
            const tokenForm = document.getElementById("agent-token-form");
            const requireAcl = tokenForm !== null && tokenForm.dataset.requireFolderAcl === "true";
            note.textContent = requireAcl
                ? "This user has no folders. Create a folder in the vault, or turn off the folder allowlist requirement."
                : "This user has no folders. The token can still see eligible personal logins.";
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
        if (request !== agentFolderRequest) {
            return false;
        }
        setAgentFolderMessage("Could not load folders.");
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
    const agentUserEmail = document.getElementById("agent-user-email");
    if (agentUserEmail) {
        agentUserEmail.addEventListener("input", () => {
            const normalized = agentUserEmail.value.trim().toLowerCase();
            agentFoldersLoadedFor = normalized === agentFoldersDisplayedFor ? agentFoldersDisplayedFor : "";
        });
        agentUserEmail.addEventListener("change", () => {
            loadAgentFolders(agentUserEmail.value);
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
            const email = document.getElementById("agent-user-email").value.trim();
            const normalized = email.toLowerCase();
            const createToken = () => {
                const requireAcl = agentTokenForm.dataset.requireFolderAcl === "true";
                const folderIds = [...document.querySelectorAll("#agent-folder-list input[type=checkbox]:checked")]
                    .map((input) => input.value);
                if (requireAcl && folderIds.length === 0) {
                    msg("Select at least one folder. A folder allowlist is required.", false);
                    return;
                }
                setAgentFolderStatus("");
                createScopedCredential(`${BASE_URL}/admin/agent/tokens`, {
                    userEmail: email,
                    name: document.getElementById("agent-token-name").value,
                    folderIds,
                });
            };
            // Show the folder names before storing an allowlist, including an empty one.
            if (agentFoldersLoadedFor === normalized && normalized !== "") {
                createToken();
                return;
            }
            loadAgentFolders(email).then((ok) => {
                if (ok && agentFoldersLoadedFor === normalized) {
                    setAgentFolderStatus("Folders loaded. Review the selection, then create the token.");
                }
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
