// Publishes website origins for this fork's fill-only Agent API.
// The script runs in the unlocked web vault tab. It sends URI strings the
// user confirms and the tab's existing user access token. It does not read
// password fields and it does not accept an AI token.
(function (factory) {
    "use strict";
    var api = factory();
    if (typeof module !== "undefined" && module.exports) {
        module.exports = api;
    }
    if (typeof document !== "undefined" && document.documentElement) {
        api.boot();
    }
})(function () {
    "use strict";
    var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    function jwtPayload(token) {
        var part = String(token).split(".")[1];
        if (!part) {
            return null;
        }
        try {
            var body = part.replace(/-/g, "+").replace(/_/g, "/");
            if (body.length % 4) {
                body += "====".slice(body.length % 4);
            }
            var binary = atob(body);
            var bytes = new Uint8Array(binary.length);
            var index;
            for (index = 0; index < binary.length; index += 1) {
                bytes[index] = binary.charCodeAt(index);
            }
            var parsed = JSON.parse(new TextDecoder().decode(bytes));
            return parsed && typeof parsed === "object" ? parsed : null;
        } catch (err) {
            return null;
        }
    }

    function looksLikeJwt(text) {
        var parts = String(text).split(".");
        if (parts.length !== 3) {
            return false;
        }
        if (!/^eyJ[A-Za-z0-9_-]+$/.test(parts[0])) {
            return false;
        }
        if (!/^[A-Za-z0-9_-]+$/.test(parts[1]) || !/^[A-Za-z0-9_-]{10,}$/.test(parts[2])) {
            return false;
        }
        return true;
    }

    function isUserAccessToken(payload, nowSec) {
        if (!payload || typeof payload.sub !== "string" || !UUID.test(payload.sub)) {
            return false;
        }
        if (typeof payload.email !== "string" || payload.email.indexOf("@") === -1) {
            return false;
        }
        if (typeof payload.exp === "number" && payload.exp <= nowSec) {
            return false;
        }
        var scope = payload.scope;
        if (Array.isArray(scope)) {
            return scope.indexOf("api") !== -1;
        }
        if (typeof scope === "string") {
            return scope.split(/[\s,]+/).indexOf("api") !== -1;
        }
        return false;
    }

    function collectStrings(value, depth, out) {
        if (depth > 5 || out.length > 20) {
            return;
        }
        if (typeof value === "string") {
            var text = value.trim();
            if (text.charAt(0) === "{" || text.charAt(0) === "[" || text.charAt(0) === '"') {
                try {
                    collectStrings(JSON.parse(text), depth + 1, out);
                    return;
                } catch (err) {
                    // The value is ordinary text.
                }
            }
            if (looksLikeJwt(text)) {
                out.push(text);
            }
            return;
        }
        var index;
        if (Array.isArray(value)) {
            for (index = 0; index < value.length && index < 20; index += 1) {
                collectStrings(value[index], depth + 1, out);
            }
            return;
        }
        if (value && typeof value === "object") {
            var keys = Object.keys(value);
            for (index = 0; index < keys.length && index < 40; index += 1) {
                collectStrings(value[keys[index]], depth + 1, out);
            }
        }
    }

    function selectAccessToken(entries, nowSec) {
        var found = [];
        var index;
        for (index = 0; index < entries.length; index += 1) {
            var entry = entries[index];
            if (!entry || typeof entry.value !== "string" || entry.value.length > 100000) {
                continue;
            }
            var keyName = String(entry.key || "");
            if (!/token|access/i.test(keyName) && entry.value.length > 8000) {
                continue;
            }
            var strings = [];
            collectStrings(entry.value, 0, strings);
            var stringIndex;
            for (stringIndex = 0; stringIndex < strings.length; stringIndex += 1) {
                var payload = jwtPayload(strings[stringIndex]);
                if (!isUserAccessToken(payload, nowSec)) {
                    continue;
                }
                found.push({
                    token: strings[stringIndex],
                    email: payload.email,
                    userId: payload.sub,
                    preferred: /accessToken/i.test(keyName),
                    exp: typeof payload.exp === "number" ? payload.exp : 0,
                });
            }
        }
        if (!found.length) {
            return null;
        }
        found.sort(function (left, right) {
            if (left.preferred !== right.preferred) {
                return left.preferred ? -1 : 1;
            }
            return right.exp - left.exp;
        });
        return found[0];
    }

    function itemIdFromLocation(hash, search) {
        var query = "";
        var hashText = hash || "";
        var hashQuery = hashText.indexOf("?");
        if (hashQuery !== -1) {
            query += hashText.slice(hashQuery + 1);
        }
        if (search) {
            query += "&" + String(search).replace(/^\?/, "");
        }
        var params = new URLSearchParams(query);
        var keys = ["itemId", "cipherId", "itemid", "cipherid"];
        var index;
        for (index = 0; index < keys.length; index += 1) {
            var value = params.get(keys[index]);
            if (value && UUID.test(value)) {
                return value;
            }
        }
        var match = hashText.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
        return match ? match[0] : "";
    }

    function publishableUri(value) {
        var text = String(value || "").trim();
        if (!text || text.length > 2048 || /\s/.test(text) || text.indexOf("\\") !== -1) {
            return "";
        }
        var url;
        try {
            url = new URL(text.indexOf("://") === -1 ? "https://" + text : text);
        } catch (err) {
            return "";
        }
        if (url.protocol !== "http:" && url.protocol !== "https:") {
            return "";
        }
        if (!url.hostname || (url.hostname.indexOf(".") === -1 && url.hostname.indexOf(":") === -1)) {
            return "";
        }
        url.username = "";
        url.password = "";
        url.search = "";
        url.hash = "";
        return url.toString();
    }

    function originsFromNodes(nodes, vaultHost) {
        var list = nodes || [];
        var hasViewAnchor = list.some(function (node) {
            return node && node.tag === "a" && node.inView && node.href;
        });
        var seen = {};
        var origins = [];
        var index;
        for (index = 0; index < list.length; index += 1) {
            var node = list[index];
            if (!node || node.password) {
                continue;
            }
            var raw = "";
            if (node.tag === "input" || node.tag === "textarea") {
                var label = String(node.label || "").toLowerCase();
                if (label.indexOf("password") !== -1) {
                    continue;
                }
                if (label.indexOf("uri") === -1 && label.indexOf("url") === -1 && label.indexOf("website") === -1) {
                    continue;
                }
                raw = node.value || "";
            } else if (node.tag === "a") {
                if (node.chrome) {
                    continue;
                }
                if (hasViewAnchor && !node.inView) {
                    continue;
                }
                raw = node.href || "";
            } else {
                continue;
            }
            var cleaned = publishableUri(raw);
            if (!cleaned) {
                continue;
            }
            var host = "";
            try {
                host = new URL(cleaned).host;
            } catch (err) {
                continue;
            }
            if (node.tag === "a" && vaultHost && host === vaultHost) {
                continue;
            }
            if (seen[cleaned]) {
                continue;
            }
            seen[cleaned] = true;
            origins.push(cleaned);
            if (origins.length === 20) {
                break;
            }
        }
        return origins;
    }

    function normalizeOriginLines(text) {
        var parts = String(text || "").split(/\s+/);
        var seen = {};
        var origins = [];
        var index;
        for (index = 0; index < parts.length; index += 1) {
            var cleaned = publishableUri(parts[index]);
            if (!cleaned || seen[cleaned]) {
                continue;
            }
            seen[cleaned] = true;
            origins.push(cleaned);
            if (origins.length === 20) {
                break;
            }
        }
        return origins;
    }

    function apiBase() {
        var script = document.querySelector("script[data-vw-agent-uri]");
        if (script) {
            var value = script.getAttribute("data-vw-agent-uri") || "";
            if (value === "/") {
                return "";
            }
            return value.replace(/\/$/, "");
        }
        var base = document.querySelector("base[href]");
        if (!base) {
            return "";
        }
        try {
            var url = new URL(base.getAttribute("href"), location.origin);
            if (url.origin !== location.origin) {
                return "";
            }
            return url.pathname.replace(/\/$/, "");
        } catch (err) {
            return "";
        }
    }

    function storageEntries() {
        var out = [];
        function pull(store) {
            var index;
            for (index = 0; index < store.length; index += 1) {
                var key = store.key(index);
                var value = store.getItem(key);
                if (typeof value === "string") {
                    out.push({ key: key, value: value });
                }
            }
        }
        try {
            pull(window.sessionStorage);
        } catch (err) {
            // Storage can be blocked. The button stays hidden.
        }
        try {
            pull(window.localStorage);
        } catch (err) {
            // Same as session storage.
        }
        return out;
    }

    function pageNodes() {
        var root = cipherRoot();
        var nodes = [];
        var inputs = document.querySelectorAll("input, textarea");
        var index;
        for (index = 0; index < inputs.length; index += 1) {
            var input = inputs[index];
            if (input.closest("#vw-agent-uri-root")) {
                continue;
            }
            nodes.push({
                tag: input.tagName.toLowerCase(),
                password: input.type === "password",
                label: [
                    input.getAttribute("formcontrolname"),
                    input.getAttribute("ng-reflect-name"),
                    input.getAttribute("name"),
                    input.getAttribute("aria-label"),
                    input.getAttribute("placeholder"),
                ].join(" "),
                value: input.value,
            });
        }
        var links = document.querySelectorAll("a[href]");
        for (index = 0; index < links.length; index += 1) {
            var link = links[index];
            if (link.closest("#vw-agent-uri-root")) {
                continue;
            }
            nodes.push({
                tag: "a",
                href: link.href,
                chrome: Boolean(link.closest("nav, header, footer")),
                inView: Boolean(root && root !== document.body && root.contains(link)),
            });
        }
        return nodes;
    }

    function cipherRoot() {
        var selectors = [
            "app-vault-cipher-view",
            "app-cipher-view",
            "app-login-credentials",
            "vault-view",
            "app-view",
        ];
        var index;
        for (index = 0; index < selectors.length; index += 1) {
            var found = document.querySelector(selectors[index]);
            if (found) {
                return found;
            }
        }
        return document.body;
    }

    function readSession() {
        return selectAccessToken(storageEntries(), Date.now() / 1000);
    }

    function boot() {
        if (window.__vwAgentUriBooted) {
            return;
        }
        window.__vwAgentUriBooted = true;
        window.setInterval(tick, 2000);
        tick();
    }

    function tick() {
        var session = readSession();
        var existing = document.getElementById("vw-agent-uri-root");
        if (!session) {
            if (existing) {
                existing.remove();
            }
            return;
        }
        if (!existing) {
            mount();
        }
    }

    function mount() {
        var root = document.createElement("div");
        root.id = "vw-agent-uri-root";
        var button = document.createElement("button");
        button.type = "button";
        button.textContent = "Agent sites";
        style(button, {
            position: "fixed",
            right: "16px",
            bottom: "16px",
            zIndex: "2147483000",
            background: "#175ddc",
            color: "#fff",
            border: "0",
            borderRadius: "999px",
            padding: "10px 14px",
            font: "14px sans-serif",
            cursor: "pointer",
            boxShadow: "0 2px 8px rgba(0,0,0,.25)",
        });
        button.addEventListener("click", openPanel);
        root.appendChild(button);
        document.body.appendChild(root);
        document.addEventListener("keydown", function (event) {
            if (event.key === "Escape") {
                closePanel();
            }
        });
    }

    function openPanel() {
        var session = readSession();
        closePanel();
        if (!session) {
            return;
        }
        var root = document.getElementById("vw-agent-uri-root");
        if (!root) {
            return;
        }
        var panel = document.createElement("div");
        panel.id = "vw-agent-uri-panel";
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-label", "Publish sites for Agent fill");
        style(panel, {
            position: "fixed",
            right: "16px",
            bottom: "64px",
            zIndex: "2147483000",
            width: "340px",
            maxHeight: "70vh",
            overflow: "auto",
            background: "#fff",
            color: "#172033",
            border: "1px solid #d0d7e2",
            borderRadius: "12px",
            padding: "14px",
            font: "14px sans-serif",
            boxShadow: "0 8px 24px rgba(0,0,0,.2)",
        });

        panel.appendChild(heading("Publish sites for Agent fill"));
        panel.appendChild(paragraph("Signed in as " + session.email + ". This sends websites only. Passwords stay in the vault."));
        panel.appendChild(paragraph("This replaces the websites already published for the login."));

        var idLabel = paragraph("Login id");
        var idInput = document.createElement("input");
        idInput.type = "text";
        idInput.value = itemIdFromLocation(location.hash, location.search);
        idInput.spellcheck = false;
        idInput.autocomplete = "off";
        style(idInput, fieldStyle());
        panel.appendChild(idLabel);
        panel.appendChild(idInput);

        var uriLabel = paragraph("Websites");
        var uriInput = document.createElement("textarea");
        uriInput.rows = 6;
        uriInput.spellcheck = false;
        uriInput.value = originsFromNodes(pageNodes(), location.host).join("\n");
        style(uriInput, fieldStyle());
        panel.appendChild(uriLabel);
        panel.appendChild(uriInput);

        var subdomains = document.createElement("label");
        style(subdomains, { display: "flex", gap: "8px", alignItems: "center", margin: "8px 0" });
        var subdomainsBox = document.createElement("input");
        subdomainsBox.type = "checkbox";
        subdomains.appendChild(subdomainsBox);
        subdomains.appendChild(document.createTextNode("Allow subdomains of these hosts"));
        panel.appendChild(subdomains);

        var status = paragraph("");
        status.id = "vw-agent-uri-status";
        panel.appendChild(status);

        var actions = document.createElement("div");
        style(actions, { display: "flex", gap: "8px", marginTop: "8px" });
        var publish = actionButton("Publish", "#175ddc", "#fff");
        var clear = actionButton("Clear", "#fff", "#172033");
        clear.style.border = "1px solid #d0d7e2";
        var close = actionButton("Close", "#fff", "#172033");
        close.style.border = "1px solid #d0d7e2";
        publish.addEventListener("click", function () {
            submitIndex("PUT", session, idInput, uriInput, subdomainsBox, status, publish);
        });
        clear.addEventListener("click", function () {
            submitIndex("DELETE", session, idInput, uriInput, subdomainsBox, status, clear);
        });
        close.addEventListener("click", closePanel);
        actions.appendChild(publish);
        actions.appendChild(clear);
        actions.appendChild(close);
        panel.appendChild(actions);
        root.appendChild(panel);
        uriInput.focus();
    }

    function submitIndex(method, session, idInput, uriInput, subdomainsBox, status, button) {
        var fresh = readSession();
        if (!fresh) {
            setStatus(status, "Unlock the vault in this tab, then try again.", true);
            return;
        }
        var itemId = idInput.value.trim();
        if (!UUID.test(itemId)) {
            setStatus(status, "Open a personal login first, or paste its id.", true);
            return;
        }
        var origins = method === "DELETE" ? [] : normalizeOriginLines(uriInput.value);
        if (method !== "DELETE" && !origins.length) {
            setStatus(status, "Enter at least one https website.", true);
            return;
        }
        button.disabled = true;
        setStatus(status, method === "DELETE" ? "Clearing…" : "Publishing…", false);
        var match = subdomainsBox.checked ? 0 : null;
        var body = method === "DELETE" ? null : JSON.stringify({
            uris: origins.map(function (uri) {
                return match === null ? { uri: uri, match: null } : { uri: uri, match: match };
            }),
        });
        fetch(apiBase() + "/api/agent/items/" + itemId + "/uri-index", {
            method: method,
            headers: {
                Authorization: "Bearer " + fresh.token,
                Accept: "application/json",
                "Content-Type": "application/json",
            },
            body: body,
        }).then(function (response) {
            return response.json().catch(function () {
                return {};
            }).then(function (payload) {
                return { ok: response.ok, payload: payload };
            });
        }).then(function (result) {
            button.disabled = false;
            if (!result.ok) {
                var message = result.payload && result.payload.message ? result.payload.message : "The vault rejected the update.";
                setStatus(status, message, true);
                return;
            }
            var stored = result.payload && Array.isArray(result.payload.uris) ? result.payload.uris : origins;
            if (method === "DELETE") {
                setStatus(status, "Cleared published sites for this login.", false);
                return;
            }
            setStatus(status, "Published " + stored.join(", ") + ".", false);
        }).catch(function () {
            button.disabled = false;
            setStatus(status, "Could not reach the vault.", true);
        });
    }

    function closePanel() {
        var panel = document.getElementById("vw-agent-uri-panel");
        if (panel) {
            panel.remove();
        }
    }

    function heading(text) {
        var node = document.createElement("div");
        node.textContent = text;
        style(node, { fontWeight: "700", marginBottom: "8px" });
        return node;
    }

    function paragraph(text) {
        var node = document.createElement("p");
        node.textContent = text;
        style(node, { margin: "0 0 8px", lineHeight: "1.4" });
        return node;
    }

    function actionButton(text, background, color) {
        var button = document.createElement("button");
        button.type = "button";
        button.textContent = text;
        style(button, {
            background: background,
            color: color,
            border: "0",
            borderRadius: "8px",
            padding: "8px 10px",
            font: "14px sans-serif",
            cursor: "pointer",
        });
        return button;
    }

    function setStatus(node, text, isError) {
        node.textContent = text;
        node.style.color = isError ? "#8a1f11" : "#0b6b2f";
    }

    function fieldStyle() {
        return {
            width: "100%",
            boxSizing: "border-box",
            margin: "0 0 8px",
            padding: "8px",
            border: "1px solid #d0d7e2",
            borderRadius: "8px",
            font: "13px sans-serif",
            color: "#172033",
            background: "#fff",
        };
    }

    function style(node, rules) {
        var key;
        for (key in rules) {
            if (Object.prototype.hasOwnProperty.call(rules, key)) {
                node.style[key] = rules[key];
            }
        }
    }

    return {
        selectAccessToken: selectAccessToken,
        itemIdFromLocation: itemIdFromLocation,
        publishableUri: publishableUri,
        originsFromNodes: originsFromNodes,
        normalizeOriginLines: normalizeOriginLines,
        boot: boot,
    };
});
