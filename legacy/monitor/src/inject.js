'use strict'

/**
 * Page-context instrumentation, injected into the controlled browser before any
 * LUME script runs. Two jobs:
 *
 *   1. Transparently wrap `fetch` and `WebSocket.prototype.send` to report what
 *      the app ITSELF sends ("reported by the app" lane). The monitor then
 *      cross-checks these against what CDP independently saw on the wire — if
 *      they match, the app told the truth about what it transmitted.
 *
 *   2. Expose `window.__lumeMonitorReport(payload)` as an opt-in channel a DEV
 *      build of LUME can call to narrate the plaintext → ciphertext step. It is
 *      never required and never active unless LUME explicitly calls it.
 *
 * Everything is wrapped in try/catch and always calls through to the original,
 * so the page behaves identically whether or not the monitor is attached.
 */

module.exports = `(() => {
  if (window.__lumeMonitorInstalled) return;
  window.__lumeMonitorInstalled = true;

  const report = (p) => {
    try { if (typeof window.__lumeMonitorBridge === 'function') window.__lumeMonitorBridge(p); } catch (e) {}
  };

  // Opt-in dev telemetry channel (plaintext narrative). No-op unless LUME calls it.
  window.__lumeMonitorReport = (payload) => report(Object.assign({ kind: 'telemetry' }, payload || {}));

  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input, init) {
      try {
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        const method = (init && init.method) || (input && input.method) || 'GET';
        let body = init && init.body;
        if (typeof body !== 'string') body = null; // only capture string bodies (JSON)
        report({ kind: 'http', source: 'app', method: method, url: url, body: body });
      } catch (e) {}
      return origFetch.apply(this, arguments);
    };
  }

  const OrigWS = window.WebSocket;
  if (OrigWS && OrigWS.prototype && OrigWS.prototype.send) {
    const origSend = OrigWS.prototype.send;
    OrigWS.prototype.send = function (data) {
      try {
        if (typeof data === 'string') report({ kind: 'ws', source: 'app', direction: 'out', url: this.url, body: data });
      } catch (e) {}
      return origSend.apply(this, arguments);
    };
  }
})();`
