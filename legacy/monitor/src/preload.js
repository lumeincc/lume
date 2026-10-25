'use strict'

const { contextBridge, ipcRenderer } = require('electron')

// Minimal, one-way bridge: the renderer only ever receives classified verdicts.
// No node APIs are exposed to the page.
contextBridge.exposeInMainWorld('monitor', {
  onEvent: callback => ipcRenderer.on('lume:event', (_event, payload) => callback(payload)),
})
