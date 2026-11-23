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


(() => {
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const background = [13, 13, 14];
  const dim = [40, 40, 44];
  const light = [214, 212, 218];
  const coral = [244, 140, 100];
  const levels = 18;
  const hues = 7;
  const empty = -1;
  const frame = 1000 / 30;

  const mix = (a, b, t) => a.map((value, index) => Math.round(value + (b[index] - value) * t));
  const smooth = (t) => {
    const c = Math.min(1, Math.max(0, t));
    return c * c * (3 - 2 * c);
  };
  const tone = (brightness, warmth) => {
    const hue = Math.min(hues - 1, Math.max(0, Math.round(warmth * (hues - 1))));
    const level = Math.min(levels - 1, Math.max(0, Math.round(brightness * (levels - 1))));
    return hue * levels + level;
  };

  const field = (canvas, scene) => {
    const context = canvas.getContext("2d", { alpha: false });
    if (context === null) {
      return;
    }
    let grid = null;
    let atlas = null;
    let digits = new Uint8Array(0);
    let shown = new Int16Array(0);
    let appear = new Float32Array(0);
    let born = -1;
    let last = 0;
    let running = false;
    let visible = false;

    const drawAtlas = (font, width, height) => {
      atlas = document.createElement("canvas");
      atlas.width = width * 2;
      atlas.height = height * levels * hues;
      const glyphs = atlas.getContext("2d");
      glyphs.fillStyle = `rgb(${background.join(", ")})`;
      glyphs.fillRect(0, 0, atlas.width, atlas.height);
      glyphs.font = `500 ${font}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;
      glyphs.textAlign = "center";
      glyphs.textBaseline = "middle";
      for (let hue = 0; hue < hues; hue += 1) {
        const target = mix(light, coral, hue / (hues - 1));
        for (let level = 0; level < levels; level += 1) {
          const [r, g, b] = mix(dim, target, level / (levels - 1));
          glyphs.fillStyle = `rgb(${r}, ${g}, ${b})`;
          const y = (hue * levels + level) * height + height / 2;
          glyphs.fillText("0", width / 2, y);
          glyphs.fillText("1", width * 1.5, y);
        }
      }
    };

    const layout = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (width === 0 || height === 0) {
        grid = null;
        return false;
      }
      const scale = Math.min(window.devicePixelRatio || 1, 2);
      const cell = scene.cell(width);
      const pixelWidth = Math.max(1, Math.round(cell.width * scale));
      const pixelHeight = Math.max(1, Math.round(cell.height * scale));
      canvas.width = Math.round(width * scale);
      canvas.height = Math.round(height * scale);
      grid = {
        columns: Math.ceil(canvas.width / pixelWidth),
        rows: Math.ceil(canvas.height / pixelHeight),
        width: pixelWidth / scale,
        height: pixelHeight / scale,
        pixelWidth,
        pixelHeight,
        frameWidth: width,
        frameHeight: height,
      };
      const count = grid.columns * grid.rows;
      digits = new Uint8Array(count);
      appear = new Float32Array(count);
      for (let index = 0; index < count; index += 1) {
        digits[index] = Math.random() < 0.5 ? 0 : 1;
        appear[index] = Math.random();
      }
      shown = new Int16Array(count).fill(-2);
      drawAtlas(cell.font * scale, pixelWidth, pixelHeight);
      scene.layout(grid);
      return true;
    };

    const paint = (time) => {
      scene.frame(time);
      const { columns, rows, pixelWidth, pixelHeight } = grid;
      const reveal = still ? 1 : Math.min(1, Math.max(0, (time - born) / 1100));
      if (!still) {
        const flips = Math.ceil(digits.length * 0.012);
        for (let flip = 0; flip < flips; flip += 1) {
          const index = Math.floor(Math.random() * digits.length);
          if (Math.random() < scene.flip(index)) {
            digits[index] ^= 1;
          }
        }
      }
      context.fillStyle = `rgb(${background.join(", ")})`;
      for (let row = 0; row < rows; row += 1) {
        for (let column = 0; column < columns; column += 1) {
          const index = row * columns + column;
          const value = appear[index] > reveal ? empty : scene.value(index, column, row);
          const slot = value === empty ? empty : value * 2 + digits[index];
          if (slot === shown[index]) {
            continue;
          }
          shown[index] = slot;
          const x = column * pixelWidth;
          const y = row * pixelHeight;
          if (slot === empty) {
            context.fillRect(x, y, pixelWidth, pixelHeight);
          } else {
            context.drawImage(atlas, digits[index] * pixelWidth, value * pixelHeight, pixelWidth, pixelHeight, x, y, pixelWidth, pixelHeight);
          }
        }
      }
    };

    const tick = (time) => {
      if (!running) {
        return;
      }
      if (grid !== null && time - last >= frame) {
        last = time;
        paint(time);
      }
      requestAnimationFrame(tick);
    };

    const start = () => {
      if (running || still || grid === null || !visible || document.hidden) {
        return;
      }
      running = true;
      requestAnimationFrame(tick);
    };

    const stop = () => {
      running = false;
    };

    const ready = () => {
      stop();
      if (!layout()) {
        return;
      }
      if (born < 0) {
        born = performance.now();
      }
      paint(performance.now());
      canvas.classList.add("shown");
      start();
    };

    let resizing = 0;
    window.addEventListener("resize", () => {
      clearTimeout(resizing);
      resizing = setTimeout(ready, 150);
    });
    document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
    new IntersectionObserver((entries) => {
      visible = entries.some((entry) => entry.isIntersecting);
      if (visible) {
        start();
      } else {
        stop();
      }
    }).observe(scene.target);

    (document.fonts ? document.fonts.ready : Promise.resolve()).then(ready);
  };

  const shapes = [
    (pen, x, y, size) => {
      pen.beginPath();
      pen.arc(x, y, size, 0, Math.PI * 2);
      pen.fill();
      pen.globalCompositeOperation = "destination-out";
      pen.beginPath();
      pen.arc(x + size * 0.42, y - size * 0.22, size * 0.86, 0, Math.PI * 2);
      pen.fill();
      pen.globalCompositeOperation = "source-over";
      pen.globalAlpha = 0.45;
      pen.lineWidth = size * 0.05;
      pen.beginPath();
      pen.arc(x, y, size * 1.22, 0, Math.PI * 2);
      pen.stroke();
      pen.globalAlpha = 1;
    },
    (pen, x, y, size) => {
      pen.lineWidth = size * 0.2;
      pen.beginPath();
      pen.arc(x, y - size * 0.32, size * 0.5, Math.PI, 0);
      pen.lineTo(x + size * 0.5, y);
      pen.moveTo(x - size * 0.5, y);
      pen.lineTo(x - size * 0.5, y - size * 0.32);
      pen.stroke();
      pen.beginPath();
      pen.roundRect(x - size * 0.82, y - size * 0.05, size * 1.64, size * 1.15, size * 0.16);
      pen.fill();
      pen.globalCompositeOperation = "destination-out";
      pen.beginPath();
      pen.arc(x, y + size * 0.42, size * 0.15, 0, Math.PI * 2);
      pen.fill();
      pen.fillRect(x - size * 0.06, y + size * 0.42, size * 0.12, size * 0.32);
      pen.globalCompositeOperation = "source-over";
    },
    (pen, x, y, size) => {
      pen.beginPath();
      pen.roundRect(x - size * 1.1, y - size * 0.75, size * 2.2, size * 1.35, size * 0.4);
      pen.fill();
      pen.beginPath();
      pen.moveTo(x - size * 0.55, y + size * 0.5);
      pen.lineTo(x - size * 0.75, y + size * 1.05);
      pen.lineTo(x - size * 0.1, y + size * 0.55);
      pen.fill();
      pen.globalCompositeOperation = "destination-out";
      for (const step of [-1, 0, 1]) {
        pen.beginPath();
        pen.arc(x + step * size * 0.5, y - size * 0.08, size * 0.13, 0, Math.PI * 2);
        pen.fill();
      }
      pen.globalCompositeOperation = "source-over";
    },
    (pen, x, y, size) => {
      pen.beginPath();
      pen.arc(x - size * 0.6, y, size * 0.48, 0, Math.PI * 2);
      pen.fill();
      pen.fillRect(x - size * 0.2, y - size * 0.12, size * 1.45, size * 0.24);
      pen.fillRect(x + size * 0.85, y, size * 0.18, size * 0.42);
      pen.fillRect(x + size * 0.5, y, size * 0.18, size * 0.3);
      pen.globalCompositeOperation = "destination-out";
      pen.beginPath();
      pen.arc(x - size * 0.68, y, size * 0.17, 0, Math.PI * 2);
      pen.fill();
      pen.globalCompositeOperation = "source-over";
    },
  ];

  const heroScene = (hero, canvas) => {
    const hold = 5200;
    const change = 2200;
    let grid = null;
    let masks = [];
    let shade = new Float32Array(0);
    let fades = new Float32Array(0);
    let grain = new Float32Array(0);
    let order = new Float32Array(0);
    let scatter = new Float32Array(0);
    let from = shade;
    let to = shade;
    let progress = 0;
    let seconds = 0;
    let started = 0;

    const drawMasks = () => {
      const step = 4;
      const sketch = document.createElement("canvas");
      sketch.width = Math.max(1, Math.ceil(grid.frameWidth / step));
      sketch.height = Math.max(1, Math.ceil(grid.frameHeight / step));
      const pen = sketch.getContext("2d", { willReadFrequently: true });
      const portrait = sketch.height > sketch.width * 1.2;
      const size = portrait ? sketch.width * 0.34 : Math.min(sketch.width * 0.3, sketch.height * 0.4);
      const middle = portrait ? sketch.height * 0.4 : sketch.height * 0.44;
      masks = shapes.map((shape) => {
        pen.clearRect(0, 0, sketch.width, sketch.height);
        pen.fillStyle = "#fff";
        pen.strokeStyle = "#fff";
        shape(pen, sketch.width / 2, middle, size);
        const pixels = pen.getImageData(0, 0, sketch.width, sketch.height).data;
        const mask = new Float32Array(grid.columns * grid.rows);
        for (let row = 0; row < grid.rows; row += 1) {
          const y = Math.min(sketch.height - 1, Math.floor(((row + 0.5) * grid.height) / step));
          for (let column = 0; column < grid.columns; column += 1) {
            const x = Math.min(sketch.width - 1, Math.floor(((column + 0.5) * grid.width) / step));
            mask[row * grid.columns + column] = pixels[(y * sketch.width + x) * 4 + 3] / 255;
          }
        }
        return mask;
      });
    };

    const drawShade = () => {
      const { columns, rows, frameWidth, frameHeight } = grid;
      shade = new Float32Array(columns * rows).fill(1);
      fades = new Float32Array(rows);
      const frameBox = canvas.getBoundingClientRect();
      const pad = 10;
      const boxes = [...hero.querySelectorAll(".actions")].map((element) => {
        const box = element.getBoundingClientRect();
        return {
          left: box.left - frameBox.left - pad,
          top: box.top - frameBox.top - pad,
          right: box.right - frameBox.left + pad,
          bottom: box.bottom - frameBox.top + pad,
        };
      });
      const feather = Math.min(frameWidth, frameHeight) * 0.07;
      const fade = frameHeight * 0.34;
      for (let row = 0; row < rows; row += 1) {
        const y = (row + 0.5) * grid.height;
        fades[row] = smooth((frameHeight - y) / fade);
        for (let column = 0; column < columns; column += 1) {
          const x = (column + 0.5) * grid.width;
          let distance = Infinity;
          for (const box of boxes) {
            const dx = Math.max(box.left - x, 0, x - box.right);
            const dy = Math.max(box.top - y, 0, y - box.bottom);
            distance = Math.min(distance, Math.hypot(dx, dy));
          }
          shade[row * columns + column] = 0.14 + 0.86 * smooth(distance / feather);
        }
      }
    };

    return {
      target: hero,
      cell: (width) => (width < 760 ? { width: 10, height: 15, font: 12 } : { width: 11, height: 16, font: 13 }),
      layout: (next) => {
        grid = next;
        const count = grid.columns * grid.rows;
        grain = new Float32Array(count);
        order = new Float32Array(count);
        scatter = new Float32Array(count);
        for (let index = 0; index < count; index += 1) {
          grain[index] = Math.random();
          order[index] = Math.random();
          scatter[index] = Math.random();
        }
        drawMasks();
        drawShade();
        started = performance.now();
      },
      frame: (time) => {
        const elapsed = Math.max(0, time - started);
        const cycle = hold + change;
        const index = Math.floor(elapsed / cycle) % masks.length;
        const into = elapsed % cycle;
        progress = into < hold ? 0 : (into - hold) / change;
        from = masks[index];
        to = masks[(index + 1) % masks.length];
        seconds = time / 1000;
      },
      flip: (index) => 0.18 + 0.82 * Math.max(from[index], to[index]),
      value: (index, column, row) => {
        const fade = fades[row];
        if (scatter[index] > fade) {
          return empty;
        }
        const x = column * grid.width;
        const y = row * grid.height;
        const local = smooth(progress * 1.6 - order[index] * 0.6);
        const inside = from[index] + (to[index] - from[index]) * local;
        const wave = 0.5 + 0.5 * Math.sin((x * 0.9 + y * 1.4) * 0.006 - seconds * 1.3);
        const swirl = 0.5 + 0.5 * Math.sin((x - y) * 0.004 + seconds * 0.7);
        const base = 0.06 + 0.1 * grain[index] + 0.06 * wave;
        const glow = inside * (0.55 + 0.45 * wave);
        return tone((base + glow) * shade[index] * (0.35 + 0.65 * fade), inside * (0.15 + 0.85 * swirl * wave));
      },
    };
  };

  const edgeScene = (canvas) => {
    let grid = null;
    let presence = new Float32Array(0);
    let grain = new Float32Array(0);
    let scatter = new Float32Array(0);
    let seconds = 0;

    return {
      target: canvas,
      cell: () => ({ width: 11, height: 16, font: 13 }),
      layout: (next) => {
        grid = next;
        const { columns, rows, frameWidth, frameHeight } = grid;
        const count = columns * rows;
        presence = new Float32Array(count);
        grain = new Float32Array(count);
        scatter = new Float32Array(count);
        const ends = frameHeight * 0.1;
        for (let row = 0; row < rows; row += 1) {
          const y = (row + 0.5) * grid.height;
          const down = smooth(y / ends) * smooth((frameHeight - y) / ends);
          for (let column = 0; column < columns; column += 1) {
            const x = (column + 0.5) * grid.width;
            const index = row * columns + column;
            presence[index] = smooth((x / frameWidth - 0.06) / 0.82) * down;
            grain[index] = Math.random();
            scatter[index] = Math.random();
          }
        }
      },
      frame: (time) => {
        seconds = time / 1000;
      },
      flip: (index) => 0.3 * presence[index],
      value: (index, column, row) => {
        const near = presence[index];
        if (scatter[index] > near) {
          return empty;
        }
        const x = column * grid.width;
        const y = row * grid.height;
        const wave = 0.5 + 0.5 * Math.sin((x * 0.8 + y * 1.3) * 0.006 - seconds * 1.1);
        const drift = 0.5 + 0.5 * Math.sin(y * 0.012 + x * 0.03 - seconds * 0.8);
        const patch = (0.5 + 0.5 * Math.sin(x * 0.011 + y * 0.0045 + seconds * 0.45)) * (0.5 + 0.5 * Math.sin(y * 0.0085 - seconds * 0.55));
        const glow = patch * patch;
        const brightness = (0.05 + 0.08 * grain[index] + 0.05 * wave + 0.34 * glow * (0.55 + 0.45 * drift)) * (0.4 + 0.6 * near);
        return tone(brightness, Math.min(1, glow * 1.3) * (0.45 + 0.55 * wave));
      },
    };
  };

  const hero = document.querySelector(".hero");
  const heroCanvas = hero === null ? null : hero.querySelector(".binary");
  if (heroCanvas !== null) {
    field(heroCanvas, heroScene(hero, heroCanvas));
  }
  const edge = document.querySelector(".edge");
  if (edge !== null) {
    field(edge, edgeScene(edge));
  }
})();
