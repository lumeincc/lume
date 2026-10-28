// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

"use strict";

(() => {
  const version = "1";
  const consentCookie = "lume_consent";
  const languageCookie = "lume_lang";
  const consentAge = 182 * 24 * 60 * 60;
  const languageAge = 365 * 24 * 60 * 60;
  const languages = ["en", "ru", "kk"];
  const base = new URL(".", document.currentScript.src).pathname;
  const secure = location.protocol === "https:" ? "; Secure" : "";
  const body = document.body;

  const read = (name) => {
    const entry = document.cookie.split("; ").find((part) => part.startsWith(name + "="));
    return entry === undefined ? null : entry.slice(name.length + 1);
  };

  const write = (name, value, age) => {
    document.cookie = `${name}=${value}; Max-Age=${age}; Path=${base}; SameSite=Lax${secure}`;
  };

  const stored = () => {
    const [given, preferences] = (read(consentCookie) || "").split(".");
    if (given !== version || (preferences !== "0" && preferences !== "1")) {
      return null;
    }
    return { preferences: preferences === "1" };
  };

  const apply = (choice) => {
    if (!choice.preferences) {
      if (read(languageCookie) !== null) {
        write(languageCookie, "", 0);
      }
      return;
    }
    if (body.classList.contains("chooser")) {
      const remembered = read(languageCookie);
      if (languages.includes(remembered)) {
        location.replace(base + remembered + "/");
      }
      return;
    }
    const language = document.documentElement.lang;
    if ((body.classList.contains("home") || body.classList.contains("page")) && languages.includes(language)) {
      write(languageCookie, language, languageAge);
    }
  };

  const choice = stored();
  if (choice !== null) {
    apply(choice);
  }

  const banner = document.querySelector(".consent");
  const dialog = document.querySelector(".consent-settings");
  const preferences = document.getElementById("consent-preferences");
  if (banner === null || dialog === null || preferences === null) {
    return;
  }

  const save = (allowed) => {
    write(consentCookie, `${version}.${allowed ? 1 : 0}`, consentAge);
    apply({ preferences: allowed });
    banner.hidden = true;
    if (dialog.open) {
      dialog.close();
    }
  };

  const open = () => {
    const current = stored();
    preferences.checked = current !== null && current.preferences;
    dialog.showModal();
  };

  const actions = {
    accept: () => save(true),
    reject: () => save(false),
    save: () => save(preferences.checked),
    open,
    close: () => dialog.close(),
  };

  document.addEventListener("click", (event) => {
    const control = event.target.closest("[data-consent]");
    if (control === null || !(control.dataset.consent in actions)) {
      return;
    }
    event.preventDefault();
    actions[control.dataset.consent]();
  });

  banner.hidden = choice !== null;
})();
