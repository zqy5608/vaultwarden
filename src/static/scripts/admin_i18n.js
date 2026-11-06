"use strict";
/* global ADMIN_ZH */

const AdminI18n = (() => {
    const supported = value => value === "en" || value === "zh-CN";
    let saved;
    try { saved = localStorage.getItem("admin-language"); } catch (_) { /* Storage may be disabled. */ }
    const requested = new URLSearchParams(window.location.search).get("lang");
    const language = supported(requested) ? requested : supported(saved) ? saved : "zh-CN";
    document.documentElement.lang = language;

    function t(source, values = {}) {
        const key = String(source).replace(/\s+/g, " ").trim();
        const text = language === "zh-CN" && Object.hasOwn(ADMIN_ZH.text, key) ? ADMIN_ZH.text[key] : String(source);
        return text.replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match);
    }

    function message(source) {
        const translated = t(source);
        if (translated !== String(source)) return translated;
        return String(source).split("\n").map(line => t(line)).join("\n");
    }

    function hasUnsavedChanges() {
        if (document.getElementById("agent-secret-panel")?.hidden === false) return true;
        return [...document.forms].some(form => [...form.elements].some(field => {
            if (field instanceof HTMLInputElement) {
                return ["checkbox", "radio"].includes(field.type) ? field.checked !== field.defaultChecked : field.value !== field.defaultValue;
            }
            if (field instanceof HTMLTextAreaElement) return field.value !== field.defaultValue;
            if (field instanceof HTMLSelectElement) {
                return field.value !== ([...field.options].find(option => option.defaultSelected) || field.options[0])?.value;
            }
            return false;
        }));
    }

    function apply() {
        document.querySelectorAll("[data-i18n]").forEach(element => { element.textContent = t(element.dataset.i18n); });
        for (const attribute of ["title", "placeholder", "aria-label"]) {
            document.querySelectorAll(`[data-i18n-${attribute}]`).forEach(element => {
                element.setAttribute(attribute, t(element.getAttribute(`data-i18n-${attribute}`)));
            });
        }
        document.querySelectorAll("[data-i18n-config-name]").forEach(element => {
            element.dataset.adminSourceText = element.textContent;
            const entry = ADMIN_ZH.config[element.dataset.i18nConfigName];
            if (language === "zh-CN" && entry) element.textContent = entry[0];
        });
        document.querySelectorAll("[data-i18n-config-description]").forEach(element => {
            const name = element.dataset.i18nConfigDescription;
            const entry = ADMIN_ZH.config[name];
            if (language === "zh-CN" && entry) element.title = `[${name.toUpperCase()}] ${entry[1]}`;
        });
        document.querySelectorAll("[data-i18n-default]").forEach(element => {
            element.placeholder = `${t("Default:")} ${element.dataset.i18nDefault}`;
        });
        const select = document.getElementById("admin-language");
        if (select) {
            select.value = language;
            select.addEventListener("change", () => {
                const next = select.value;
                if (!supported(next) || next === language) return;
                if (hasUnsavedChanges() && !confirm(t("Changing language reloads this page. Unsaved changes or the displayed one-time credential will be lost. Continue?"))) {
                    select.value = language;
                    return;
                }
                const url = new URL(window.location.href);
                try {
                    localStorage.setItem("admin-language", next);
                    url.searchParams.delete("lang");
                } catch (_) {
                    url.searchParams.set("lang", next);
                }
                window.location.assign(url.href);
            });
        }
    }

    function tableLanguage() {
        return {
            emptyTable: t("No data available in table"), info: t("Showing _START_ to _END_ of _TOTAL_ entries"),
            infoEmpty: t("Showing 0 to 0 of 0 entries"), infoFiltered: t("(filtered from _MAX_ total entries)"),
            lengthMenu: t("_MENU_ entries per page"), search: t("Search:"), zeroRecords: t("No matching records found"),
            lengthLabels: { "-1": t("All") },
            paginate: { first: t("First"), last: t("Last"), next: t("Next"), previous: t("Previous") },
            aria: { orderable: t("Activate to sort"), orderableReverse: t("Activate to reverse sorting"), orderableRemove: t("Activate to remove sorting") },
        };
    }
    document.addEventListener("DOMContentLoaded", apply);
    return { t, message, language, tableLanguage, hasUnsavedChanges };
})();
