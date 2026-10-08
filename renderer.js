const $ = id => document.getElementById(id);

let cache = [];

const loginView = $('loginView');
const vaultView = $('vaultView');
const modal = $('modal');

async function init() {
    const status = await window.securePass.status();

    $('loginBtn').textContent =
        status.firstRun
            ? 'Create Master Password'
            : 'Login';

    $('master').placeholder =
        status.firstRun
            ? 'Minimum 8 characters'
            : '';
}

$('showMaster').onclick = () => {
    $('master').type =
        $('master').type === 'password'
            ? 'text'
            : 'password';
};

$('loginForm').onsubmit = async event => {
    event.preventDefault();

    const status =
        await window.securePass.status();

    const result = status.firstRun
        ? await window.securePass.setup(
            $('master').value
        )
        : await window.securePass.login(
            $('master').value
        );

    if (!result.ok) {
        $('loginMsg').textContent =
            result.error;
        return;
    }

    $('loginMsg').textContent = '';
    $('master').value = '';

    loginView.hidden = true;
    vaultView.hidden = false;

    await load();
};

async function load() {
    const result =
        await window.securePass.list();

    if (!result.ok) {
        $('loginMsg').textContent =
            result.error;
        return;
    }

    cache = result.items;
    render();
}

function esc(value) {
    return String(value).replace(
        /[&<>"']/g,
        character => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[character])
    );
}

function render() {
    const query =
        $('search').value.toLowerCase();

    const items = cache.filter(item =>
        (
            item.website +
            ' ' +
            item.username
        )
            .toLowerCase()
            .includes(query)
    );

    $('rows').innerHTML =
        items.map(item => `
            <tr>
                <td>${esc(item.website)}</td>
                <td>${esc(item.username)}</td>
                <td>••••••••</td>
                <td>
                    <button
                        class="small"
                        data-show="${item.id}"
                        aria-label="Show password">
                        👁
                    </button>

                    <button
                        class="small"
                        data-edit="${item.id}"
                        aria-label="Edit credential">
                        ✎
                    </button>

                    <button
                        class="small danger"
                        data-del="${item.id}"
                        aria-label="Delete credential">
                        🗑
                    </button>
                </td>
            </tr>
        `)
        .join('');

    $('empty').hidden =
        items.length > 0;
}

$('search').oninput = render;

function openForm(item = {}) {
    $('formTitle').textContent =
        item.id
            ? 'Edit Credential'
            : 'Add Credential';

    $('editId').value =
        item.id || '';

    $('website').value =
        item.website || '';

    $('username').value =
        item.username || '';

    $('password').value =
        item.password || '';

    $('formMsg').textContent = '';

    modal.hidden = false;

    $('website').focus();
}

$('addBtn').onclick = () =>
    openForm();

$('addSide').onclick = () =>
    openForm();

$('cancel').onclick = () =>
    modal.hidden = true;

$('credForm').onsubmit = async event => {
    event.preventDefault();

    const result =
        await window.securePass.save({
            id:
                $('editId').value ||
                undefined,

            website:
                $('website').value,

            username:
                $('username').value,

            password:
                $('password').value
        });

    if (!result.ok) {
        $('formMsg').textContent =
            result.error;
        return;
    }

    modal.hidden = true;

    await load();
};

$('rows').onclick = async event => {

    const button =
        event.target.closest('button');

    if (!button) return;

    const id =
        button.dataset.edit ||
        button.dataset.del ||
        button.dataset.show;

    const item =
        cache.find(
            credential =>
                credential.id === id
        );

    if (!item) return;

    if (button.dataset.edit) {
        openForm(item);
    }

    if (
        button.dataset.del &&
        confirm(
            `Delete credential for ${item.website}? This action cannot be undone.`
        )
    ) {
        const result =
            await window.securePass.remove(id);

        if (!result.ok) {
            alert(result.error);
            return;
        }

        await load();
    }

    if (button.dataset.show) {
        alert(
            `Password for ${item.website}: ${item.password}`
        );
    }
};

$('logout').onclick = async () => {

    await window.securePass.logout();

    cache = [];

    vaultView.hidden = true;
    loginView.hidden = false;

    $('loginMsg').textContent =
        'Vault locked.';
};

$('master').addEventListener(
    'keydown',
    event => {
        if (event.key === 'Enter') {
            $('loginForm').requestSubmit();
        }
    }
);

init();