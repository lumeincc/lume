// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

"use strict";

(() => {
  const body = document.body;
  if (!body.classList.contains("home")) {
    return;
  }
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    return;
  }

  const glyphs = "#%&*+=?<>|01ABCDEFabcdef";
  const kept = new Set(" \n\t.,:;!?()-«»—–·");
  const blocks = ".hero h1, .hero .btn";

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
