const { contextBridge, ipcRenderer } = require("electron");

// Minimal, audited surface for the bundled pages (connect screen + the local
// "This Device" surface). The dashboard itself is loaded from the configured
// server origin and gets no Node/Electron access.
contextBridge.exposeInMainWorld("rootwatch", {
  getConnection: () => ipcRenderer.invoke("rw:connection:get"),
  saveConnection: (opts) => ipcRenderer.invoke("rw:connection:save", opts),
  disconnect: () => ipcRenderer.invoke("rw:connection:disconnect"),

  // This-device surface: local listener inventory + pairing/sync.
  deviceStatus: () => ipcRenderer.invoke("rw:device:status"),
  deviceListeners: (force) => ipcRenderer.invoke("rw:device:listeners", { force }),
  deviceChecks: () => ipcRenderer.invoke("rw:device:checks"),
  devicePerformance: (force) => ipcRenderer.invoke("rw:device:performance", { force }),
  deviceStop: (pid, confirmSystem, disable) =>
    ipcRenderer.invoke("rw:device:stop", { pid, confirmSystem, disable }),
  deviceEnrollStart: () => ipcRenderer.invoke("rw:device:enroll:start"),
  deviceEnrollPoll: () => ipcRenderer.invoke("rw:device:enroll:poll"),
  deviceUnpair: () => ipcRenderer.invoke("rw:device:unpair"),
  deviceScan: (dir) => ipcRenderer.invoke("rw:device:scan", { dir }),
  deviceHistory: () => ipcRenderer.invoke("rw:device:history"),
  deviceQueue: () => ipcRenderer.invoke("rw:device:queue"),
  openExternal: (url) => ipcRenderer.invoke("rw:open-external", url),
});
