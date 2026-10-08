const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('securePass', {

    /* =========================
       Authentication
       ========================= */

    status: () =>
        ipcRenderer.invoke('auth:status'),

    setup: (password) =>
        ipcRenderer.invoke(
            'auth:setup',
            password
        ),

    login: (password) =>
        ipcRenderer.invoke(
            'auth:login',
            password
        ),

    logout: () =>
        ipcRenderer.invoke(
            'auth:logout'
        ),

    /* =========================
       Vault
       ========================= */

    list: () =>
        ipcRenderer.invoke(
            'vault:list'
        ),

    save: (credential) =>
        ipcRenderer.invoke(
            'vault:save',
            credential
        ),

    remove: (id) =>
        ipcRenderer.invoke(
            'vault:delete',
            id
        )
});