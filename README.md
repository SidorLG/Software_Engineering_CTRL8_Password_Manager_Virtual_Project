# SecurePass — CPU5005-20 Assessment 2


## Run in VS Code
1. Install Node.js (LTS).
2. Open this folder in VS Code.
3. Open Terminal > New Terminal.
4. Run: `npm install`
5. Run: `npm start`

## First launch
Create a master password of at least 8 characters. The app then creates an encrypted local vault.

## Implemented project requirements
- Master password login/logout
- SHA-256 password verifier
- PBKDF2 key derivation (100,000 iterations)
- AES-256-GCM encrypted local `user_vault.enc`
- CRUD: add, view, edit and delete credentials
- Automatic `.bak` backup before vault writes
- Search
- Keyboard focus indicators, labels, error feedback and responsive desktop UI
- Electron context isolation and preload IPC bridge

## Data location
Electron stores `auth.json`, `user_vault.enc` and the backup in its per-user application data folder, not inside the source-code folder.

## Academic note
Test results should only be marked Pass after the team actually runs and records the tests.
