An **independent, live transparency monitor** for [LUME](https://github.com/lumeincc/lume) — a Wireshark-in-plain-language for one question: _is my data actually encrypted, and what can the relay still see?_

It is a separate application, deliberately: a panel living inside LUME could only ever be as trustworthy as LUME itself. This tool launches its **own** Chromium and watches the **real** network traffic through the Chrome DevTools Protocol — it reports what the browser actually observed leaving the machine, not what the app claims.

## What it shows

Every request and WebSocket frame is classified into one of four lanes, in plain language:

| Lane | Meaning |
|---|---|
| 🟢 **sealed** | Content the relay only ever sees as ciphertext (message text, encrypted file blobs, incoming messages). The opaque blob the server receives is previewed so you can see it is unreadable. |
| 🟡 **metadata** | Visible to the relay because delivery needs it: who ↔ whom, timing, sizes, presence, group membership, "fetching a prekey bundle = intent to start a chat". |
| 🔴 **exposed** | Readable by the relay in the clear: group names, display names, public/unencrypted avatars — and **data sent to any host that is not the LUME relay**. |
| ⚪ **app** | Loading the client itself or keepalive pings — not your data. Hidden by default. |

The lane verdicts are derived from the LUME server source (Zod schemas + SQLite schema), not guessed. A wrong colour in either direction would defeat the purpose, so each rule maps to a real endpoint and field.

## How it works

```
┌─────────────────┐   CDP Network.*    ┌──────────────────┐   IPC    ┌──────────────┐
│ own Chromium    │ ─────────────────▶ │ main (capture +  │ ───────▶ │ live UI       │
│ (LUME loads here)│  requests, WS      │  classify)       │  verdict │ (this window) │
└─────────────────┘  frames            └──────────────────┘          └──────────────┘
```

- **`src/capture.js`** — turns raw CDP / app-reported events into a normalized shape.
- **`src/classify.js`** — pure, dependency-free classifier (the honesty model). Unit-tested.
- **`src/inject.js`** — page hook installed in the controlled browser (lane 2, below).
- **`src/correlate.js`** — cross-checks the two lanes.
- **`src/main.js`** — Electron main: launches Chromium via puppeteer, subscribes to CDP, streams verdicts to the UI.
- **`renderer/`** — the live window.

### Two lanes

Each row is tagged with its source:

- **`wire`** — observed independently on the wire via CDP. The trust anchor: it is what the browser actually sent, not what the app says.
- **`app`** — reported by the app itself. A tiny hook (`src/inject.js`) transparently wraps `fetch` and `WebSocket.send` in the page and reports what LUME sends.

When the **same payload** shows up on both lanes within a short window, the row is marked **✓ confirmed** — evidence that the app did not lie about what it transmitted. That cross-check is the whole reason lane 2 exists.

Lane 2 is also the delivery channel for an **optional** plaintext → ciphertext narrative. A dev build of LUME may call:

```js
window.__lumeMonitorReport({ event: 'encrypt', recipient, plaintextPreview, ciphertextPreview, ratchetStep })
```

If (and only if) LUME calls it, the monitor shows "you typed …" next to the resulting sealed blob. It is never required, never active in production, and the monitor never persists it.

## Run

```bash
npm install
npm start
```

`npm install` downloads a private Chromium for puppeteer (the controlled browser). `npm start` opens two windows: the monitor, and the controlled browser with LUME loaded. Use LUME normally — every action shows up classified in the monitor.

### Configure the target

`config.json` (or env vars) point it at a deployment:

```json
{
  "lumeUrl": "https://lume-dev-version.vercel.app",
  "relayHosts": ["lume-api-3dnb.onrender.com"]
}
```

`LUME_URL` and `LUME_RELAY_HOSTS` (comma-separated) override the file. Point `lumeUrl` at `http://localhost:3000` to watch a local dev client.

## Tests

```bash
npm test
```

Runs the classifier and the two-lane correlator against representative payloads (message send, public avatar, group create, prekey fetch, incoming message, unexpected host, telemetry, cross-lane match, …) with no dependencies. Currently **26/26**.

## Independence & privacy

- **Independent:** reads CDP `Network.*` events — what the browser sent — not LUME's self-report. It does not break TLS.
- **Local-only:** everything stays in memory in this process. The monitor has **no persistence** — it never writes a log of your traffic, and it must not (a stored social graph would be a honeypot).
- **No secrets:** it shows ciphertext previews and metadata only — never keys or plaintext.

## Status

MVP. Working: the independent CDP capture (lane 1), the "reported by the app" lane with cross-check (lane 2), the classifier, and the live UI. Verified by the unit tests (26/26); the Electron capture + UI run on the developer's machine (not yet CI). Next: wiring the optional dev telemetry hook into a LUME dev build so the plaintext → ciphertext narrative is live, and a session-level summary of what the relay holds.

_License: TBD (not yet chosen)._
