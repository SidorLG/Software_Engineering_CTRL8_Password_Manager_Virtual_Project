const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

/*
 * SecurePass - Electron Password Manager
 *
 * Architecture:
 * MainController
 * ├── SessionManager
 * ├── EncryptionService
 * ├── Vault
 * └── LocalStorage
 *
 * Local files:
 * settings.json
 * user_vault.enc
 * user_vault.enc.bak
 */

const ITERATIONS = 100000;
const KEY_LENGTH = 32;
const DIGEST = 'sha256';

let win = null;

/* =========================================================
   Credential
   ========================================================= */

class Credential {
    constructor({
        id,
        website,
        username,
        password
    }) {
        this.id = id || crypto.randomUUID();
        this.website = String(website || '').trim();
        this.username = String(username || '').trim();
        this.password = String(password || '');
    }
}

/* =========================================================
   EncryptionService
   ========================================================= */

class EncryptionService {

    static hashPassword(password) {
        return crypto
            .createHash('sha256')
            .update(password)
            .digest('hex');
    }

    static generateSalt() {
        return crypto.randomBytes(16);
    }

    static deriveKey(password, salt) {
        return crypto.pbkdf2Sync(
            password,
            salt,
            ITERATIONS,
            KEY_LENGTH,
            DIGEST
        );
    }

    static encrypt(data, key) {
        const iv = crypto.randomBytes(16);

        const cipher = crypto.createCipheriv(
            'aes-256-cbc',
            key,
            iv
        );

        const plaintext = JSON.stringify(data);

        const encrypted = Buffer.concat([
            cipher.update(plaintext, 'utf8'),
            cipher.final()
        ]);

        return JSON.stringify({
            iv: iv.toString('base64'),
            ciphertext: encrypted.toString('base64')
        });
    }

    static decrypt(payload, key) {
        const encrypted = JSON.parse(payload);

        const iv = Buffer.from(
            encrypted.iv,
            'base64'
        );

        const ciphertext = Buffer.from(
            encrypted.ciphertext,
            'base64'
        );

        const decipher = crypto.createDecipheriv(
            'aes-256-cbc',
            key,
            iv
        );

        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);

        return JSON.parse(
            decrypted.toString('utf8')
        );
    }
}

/* =========================================================
   LocalStorage
   ========================================================= */

class LocalStorage {

    constructor() {
        const directory = app.getPath('userData');

        this.settingsPath = path.join(
            directory,
            'settings.json'
        );

        this.vaultPath = path.join(
            directory,
            'user_vault.enc'
        );

        this.backupPath = path.join(
            directory,
            'user_vault.enc.bak'
        );
    }

    exists(filePath) {
        return fs.existsSync(filePath);
    }

    read(filePath) {
        return fs.readFileSync(
            filePath,
            'utf8'
        );
    }

    write(filePath, data) {
        fs.writeFileSync(
            filePath,
            data,
            'utf8'
        );
    }

    delete(filePath) {
        if (this.exists(filePath)) {
            fs.unlinkSync(filePath);
        }
    }

    backup() {
        if (this.exists(this.vaultPath)) {
            fs.copyFileSync(
                this.vaultPath,
                this.backupPath
            );
        }
    }

    readSettings() {
        if (!this.exists(this.settingsPath)) {
            return null;
        }

        return JSON.parse(
            this.read(this.settingsPath)
        );
    }

    writeSettings(settings) {
        this.write(
            this.settingsPath,
            JSON.stringify(
                settings,
                null,
                2
            )
        );
    }

    readVault() {
        if (!this.exists(this.vaultPath)) {
            return null;
        }

        return this.read(this.vaultPath);
    }

    writeVault(data) {
        this.write(
            this.vaultPath,
            data
        );
    }
}

/* =========================================================
   SessionManager
   ========================================================= */

class SessionManager {

    constructor() {
        this.sessionActive = false;
        this.sessionKey = null;
        this.lastActivity = null;
        this.lockTimeoutMinutes = 30;
    }

    startSession(key) {
        this.sessionKey = key;
        this.sessionActive = true;
        this.lastActivity = new Date();
    }

    updateActivity() {
        if (this.sessionActive) {
            this.lastActivity = new Date();
        }
    }

    isSessionActive() {
        return (
            this.sessionActive &&
            this.sessionKey !== null
        );
    }

    getKey() {
        if (!this.isSessionActive()) {
            throw new Error('Vault is locked.');
        }

        this.updateActivity();

        return this.sessionKey;
    }

    lock() {
        if (this.sessionKey) {
            this.sessionKey.fill(0);
        }

        this.sessionKey = null;
        this.sessionActive = false;
        this.lastActivity = null;
    }

    endSession() {
        this.lock();
    }
}

/* =========================================================
   Vault
   ========================================================= */

class Vault {

    constructor(localStorage, encryptionService) {
        this.localStorage = localStorage;
        this.encryptionService = encryptionService;

        this.credentials = [];
        this.createdAt = new Date();
        this.lastModified = new Date();
    }

    load(key) {
        const encryptedVault =
            this.localStorage.readVault();

        if (!encryptedVault) {
            this.credentials = [];
            return;
        }

        /*
         * Important:
         * A damaged or undecryptable vault is NOT
         * treated as an empty vault.
         */
        const decrypted =
            EncryptionService.decrypt(
                encryptedVault,
                key
            );

        if (!Array.isArray(decrypted)) {
            throw new Error(
                'Vault data is invalid.'
            );
        }

        this.credentials = decrypted.map(
            item => new Credential(item)
        );

        this.lastModified = new Date();
    }

    save(key) {

        /*
         * Backup the current encrypted vault
         * before every write.
         */
        this.localStorage.backup();

        const encrypted =
            EncryptionService.encrypt(
                this.credentials,
                key
            );

        this.localStorage.writeVault(
            encrypted
        );

        this.lastModified = new Date();
    }

    getAll() {
        return this.credentials;
    }

    add(credential) {
        this.credentials.push(
            new Credential(credential)
        );
    }

    update(credential) {

        const index =
            this.credentials.findIndex(
                item => item.id === credential.id
            );

        if (index === -1) {
            throw new Error(
                'Credential not found.'
            );
        }

        this.credentials[index] =
            new Credential(credential);
    }

    delete(id) {

        const originalLength =
            this.credentials.length;

        this.credentials =
            this.credentials.filter(
                item => item.id !== id
            );

        if (
            this.credentials.length === originalLength
        ) {
            throw new Error(
                'Credential not found.'
            );
        }
    }
}

/* =========================================================
   MainController
   ========================================================= */

class MainController {

    constructor() {
        this.localStorage =
            new LocalStorage();

        this.encryptionService =
            EncryptionService;

        this.sessionManager =
            new SessionManager();

        this.vault =
            new Vault(
                this.localStorage,
                this.encryptionService
            );
    }

    isFirstRun() {
        return !this.localStorage.exists(
            this.localStorage.settingsPath
        );
    }

    setupMasterPassword(password) {

        if (
            typeof password !== 'string' ||
            password.length < 8
        ) {
            return {
                ok: false,
                error:
                    'Master password must be at least 8 characters.'
            };
        }

        const salt =
            EncryptionService.generateSalt();

        const verifier =
            EncryptionService.hashPassword(
                password
            );

        const settings = {
            masterHash: verifier,
            salt: salt.toString('base64')
        };

        this.localStorage.writeSettings(
            settings
        );

        const key =
            EncryptionService.deriveKey(
                password,
                salt
            );

        this.sessionManager.startSession(key);

        this.vault.credentials = [];

        this.vault.save(key);

        this.sessionManager.endSession();

        return {
            ok: true
        };
    }

    login(password) {

        try {

            const settings =
                this.localStorage.readSettings();

            if (!settings) {
                return {
                    ok: false,
                    error:
                        'Master password has not been configured.'
                };
            }

            const verifier =
                EncryptionService.hashPassword(
                    password
                );

            if (
                verifier !== settings.masterHash
            ) {
                return {
                    ok: false,
                    error:
                        'Incorrect master password. Please try again.'
                };
            }

            const salt =
                Buffer.from(
                    settings.salt,
                    'base64'
                );

            const key =
                EncryptionService.deriveKey(
                    password,
                    salt
                );

            /*
             * Load must succeed before the session
             * is considered authenticated.
             */
            this.vault.load(key);

            this.sessionManager.startSession(
                key
            );

            return {
                ok: true
            };

        } catch (error) {

            this.sessionManager.endSession();

            return {
                ok: false,
                error:
                    'Unable to unlock the vault. The vault may be damaged or invalid.'
            };
        }
    }

    logout() {
        this.sessionManager.endSession();

        return {
            ok: true
        };
    }

    readCredentials() {

        try {

            const key =
                this.sessionManager.getKey();

            /*
             * Reload the vault so that the current
             * encrypted file is always the source.
             */
            this.vault.load(key);

            return {
                ok: true,
                items: this.vault.getAll()
            };

        } catch (error) {

            return {
                ok: false,
                error: error.message
            };
        }
    }

    createCredential(data) {

        try {

            const key =
                this.sessionManager.getKey();

            const credential =
                new Credential(data);

            if (
                !credential.website ||
                !credential.username ||
                !credential.password
            ) {
                return {
                    ok: false,
                    error:
                        'Please complete all fields.'
                };
            }

            this.vault.load(key);

            this.vault.add(
                credential
            );

            this.vault.save(key);

            return {
                ok: true
            };

        } catch (error) {

            return {
                ok: false,
                error: error.message
            };
        }
    }

    updateCredential(data) {

        try {

            const key =
                this.sessionManager.getKey();

            const credential =
                new Credential(data);

            if (
                !credential.id ||
                !credential.website ||
                !credential.username ||
                !credential.password
            ) {
                return {
                    ok: false,
                    error:
                        'Please complete all fields.'
                };
            }

            this.vault.load(key);

            this.vault.update(
                credential
            );

            this.vault.save(key);

            return {
                ok: true
            };

        } catch (error) {

            return {
                ok: false,
                error: error.message
            };
        }
    }

    saveCredential(data) {

        if (data.id) {
            return this.updateCredential(
                data
            );
        }

        return this.createCredential(
            data
        );
    }

    deleteCredential(id) {

        try {

            const key =
                this.sessionManager.getKey();

            this.vault.load(key);

            this.vault.delete(id);

            this.vault.save(key);

            return {
                ok: true
            };

        } catch (error) {

            return {
                ok: false,
                error: error.message
            };
        }
    }
}

/* =========================================================
   Application
   ========================================================= */

const controller =
    new MainController();

/* =========================================================
   Electron Window
   ========================================================= */

function createWindow() {

    win = new BrowserWindow({
        width: 1100,
        height: 720,
        minWidth: 850,
        minHeight: 600,

        webPreferences: {
            preload: path.join(
                __dirname,
                'preload.js'
            ),

            contextIsolation: true,
            nodeIntegration: false
        }
    });

    win.loadFile(
        path.join(
            __dirname,
            'index.html'
        )
    );
}

app.whenReady().then(() => {

    createWindow();

    app.on('activate', () => {

        if (
            BrowserWindow.getAllWindows()
                .length === 0
        ) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {

    controller.logout();

    if (
        process.platform !== 'darwin'
    ) {
        app.quit();
    }
});

/* =========================================================
   Authentication IPC
   ========================================================= */

ipcMain.handle(
    'auth:status',
    () => ({
        firstRun:
            controller.isFirstRun()
    })
);

ipcMain.handle(
    'auth:setup',
    (_, password) =>
        controller.setupMasterPassword(
            password
        )
);

ipcMain.handle(
    'auth:login',
    (_, password) =>
        controller.login(
            password
        )
);

ipcMain.handle(
    'auth:logout',
    () =>
        controller.logout()
);

/* =========================================================
   Vault IPC
   ========================================================= */

ipcMain.handle(
    'vault:list',
    () =>
        controller.readCredentials()
);

ipcMain.handle(
    'vault:save',
    (_, credential) =>
        controller.saveCredential(
            credential
        )
);

ipcMain.handle(
    'vault:delete',
    (_, id) =>
        controller.deleteCredential(
            id
        )
);