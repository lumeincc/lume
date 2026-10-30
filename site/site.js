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

(() => {
  const body = document.body;
  if (!body.classList.contains("home") && !body.classList.contains("chooser")) {
    return;
  }
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    return;
  }

  const glyphs = "#%&*+=?<>|01ABCDEFabcdef";
  const kept = new Set(" \n\t.,:;!?()-«»—–·");
  const blocks = ".hero h1, .hero .btn, .chooser h1, .chooser .tagline span, .chooser .btn";

  const mix = (text, shown) => {
    let out = "";
    for (let i = 0; i < text.length; i += 1) {
      const c = text[i];
      out += i < shown || kept.has(c) ? c : glyphs[Math.floor(Math.random() * glyphs.length)];
    }
    return out;
  };

  const collect = (element) => {
    const nodes = [];
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      if (walker.currentNode.nodeValue.trim()) {
        nodes.push([walker.currentNode, walker.currentNode.nodeValue]);
      }
    }
    return nodes;
  };

  const paint = (nodes, shown) => {
    let left = shown;
    for (const [node, text] of nodes) {
      node.nodeValue = mix(text, Math.max(0, Math.min(text.length, left)));
      left -= text.length;
    }
  };

  const reveal = (element, nodes) => {
    const total = nodes.reduce((sum, [, text]) => sum + text.length, 0);
    const duration = Math.min(1400, 450 + total * 9);
    const start = performance.now();
    element.setAttribute("aria-busy", "true");
    const step = () => {
      const shown = Math.floor(total * Math.min(1, (performance.now() - start) / duration));
      if (shown >= total) {
        for (const [node, text] of nodes) {
          node.nodeValue = text;
        }
        element.removeAttribute("aria-busy");
        return;
      }
      paint(nodes, shown);
      setTimeout(step, 35);
    };
    step();
  };

  const prepared = new Map();
  const seen = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        seen.unobserve(entry.target);
        reveal(entry.target, prepared.get(entry.target));
      }
    }
  }, { threshold: 0.15 });
  const near = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        near.unobserve(entry.target);
        const nodes = collect(entry.target);
        prepared.set(entry.target, nodes);
        paint(nodes, 0);
        seen.observe(entry.target);
      }
    }
  }, { rootMargin: "0px 0px 30% 0px" });

  for (const element of document.querySelectorAll(blocks)) {
    if (!element.parentElement.closest(blocks)) {
      near.observe(element);
    }
  }
})();
