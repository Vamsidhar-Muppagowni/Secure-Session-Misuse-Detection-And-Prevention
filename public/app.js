const API_URL = ''; // Relative path

// === DOM Elements ===
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const uploadForm = document.getElementById('upload-form');
const authView = document.getElementById('auth-view');
const dashboardView = document.getElementById('dashboard-view');
const fileList = document.getElementById('file-list');
const authMessage = document.getElementById('auth-message');
const mfaModal = document.getElementById('mfa-modal');

// === State ===
let currentUser = null;

// === Auth Logic ===
const switchAuthTab = (tab) => {
    document.querySelectorAll('.auth-tabs button').forEach(b => b.classList.remove('active'));
    document.getElementById(`tab-${tab}`).classList.add('active');

    if (tab === 'login') {
        loginForm.classList.remove('hidden');
        registerForm.classList.add('hidden');
    } else {
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
    }
    authMessage.textContent = '';
};

const handleLogin = async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
        const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();

        if (res.ok) {
            currentUser = data.user;
            // Trigger MFA Flow
            authView.style.opacity = '0.5';
            mfaModal.style.display = 'block';
        } else {
            authMessage.textContent = data.error;
        }
    } catch (err) {
        authMessage.textContent = 'Connection Error';
    }
};

const verifyMFA = async () => {
    const code = document.getElementById('mfa-code').value;
    if (code.length < 6) {
        alert('Please enter a valid 6-digit code');
        return;
    }

    try {
        const res = await fetch('/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });
        if (res.ok) {
            mfaModal.style.display = 'none';
            authView.style.opacity = '1';
            showDashboard();
        }
    } catch (e) {
        alert('MFA Verification Failed');
    }
};

const sendEmailOTP = async () => {
    const email = document.getElementById('reg-email').value;
    if (!email || !email.includes('@')) {
        alert('Please enter a valid email first');
        return;
    }

    try {
        const res = await fetch('/send-email-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();

        if (res.ok) {
            alert('OTP Sent! Please check your email inbox.');
        } else {
            alert(data.error);
        }
    } catch (e) {
        alert('Failed to send OTP');
    }
};

const handleRegister = async (e) => {
    e.preventDefault();
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const emailOtp = document.getElementById('reg-email-otp').value;
    const password = document.getElementById('reg-password').value;
    const role = document.getElementById('reg-role').value;

    try {
        const res = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, role, emailOtp })
        });
        const data = await res.json();

        if (res.ok) {
            // Show QR Code Setup
            registerForm.classList.add('hidden');
            document.getElementById('2fa-setup').classList.remove('hidden');
            document.getElementById('qr-code-img').src = data.qrCodeUrl;
        } else {
            authMessage.textContent = data.error;
        }
    } catch (err) {
        authMessage.textContent = 'Connection Error';
    }
};

const finishRegistration = () => {
    document.getElementById('2fa-setup').classList.add('hidden');
    switchAuthTab('login');
};

const logout = async () => {
    await fetch('/logout', { method: 'POST' });
    location.reload();
};

// === Dashboard Logic ===
const showDashboard = async () => {
    authView.classList.add('hidden');
    dashboardView.classList.remove('hidden');
    document.getElementById('user-display').textContent = `User: ${currentUser.username} (${currentUser.role})`;

    loadFiles();
    loadFiles();
    fetchSecurityLogs(); // Load logs on startup
    if (currentUser.role === 'faculty') fetchRequests();
};

const fetchRequests = async () => {
    try {
        const res = await fetch('/access/pending');
        const data = await res.json();
        const list = document.getElementById('request-list');
        const panel = document.getElementById('access-requests-panel');

        if (data.requests.length > 0) {
            panel.style.display = 'block';
            list.innerHTML = '';
            data.requests.forEach(req => {
                const li = document.createElement('li');
                li.style.padding = '10px';
                li.style.borderBottom = '1px solid #ddd';
                li.style.display = 'flex';
                li.style.justifyContent = 'space-between';
                li.innerHTML = `
                    <span><strong>${req.student}</strong> requests <strong>${req.fileId.filename}</strong></span>
                    <div>
                        <button class="secondary" onclick="approveRequest('${req._id}', 'approved')">Approve</button>
                        <button class="danger" onclick="approveRequest('${req._id}', 'rejected')">Deny</button>
                    </div>
                `;
                list.appendChild(li);
            });
        }
    } catch (e) { console.error(e); }
};

const approveRequest = async (requestId, action) => {
    await fetch('/access/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId, action })
    });
    fetchRequests(); // Refresh
};

const requestAccess = async (fileId) => {
    await fetch('/access/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fileId })
    });
    alert('Request Sent! Waiting for Faculty approval.');
    loadFiles();
};

const fetchSecurityLogs = async () => {
    try {
        const res = await fetch('/security-logs');
        const data = await res.json();
        const logList = document.getElementById('security-log-list');

        logList.innerHTML = '';
        if (data.logs.length === 0) {
            logList.innerHTML = '<li style="text-align: center; color: var(--success-color); padding: 10px;">✅ System Secure. No threats detected.</li>';
            return;
        }

        data.logs.forEach(log => {
            const li = document.createElement('li');
            li.style.borderBottom = '1px solid var(--border-color)';
            li.style.padding = '10px';
            li.style.background = 'rgba(218, 54, 51, 0.1)'; // Light red background
            li.innerHTML = `
                <strong style="color: var(--danger-color)">🚨 ${log.type} DETECTED!</strong> <br>
                <small style="color: var(--text-primary)">Target User: <strong>${log.username}</strong> | IP: ${log.ip}</small> <br>
                <div style="background: rgba(0,0,0,0.05); padding: 5px; margin-top: 5px; border-radius: 4px; font-family: monospace; font-size: 0.85em; color: var(--text-secondary);">
                    Expected Monitor: ${log.expectedUA.substring(0, 50)}... <br>
                    Actual Access: <span style="color: var(--danger-color)">${log.actualUA.substring(0, 50)}...</span>
                </div>
                <small style="color: grey; display: block; margin-top: 5px;">Timestamp: ${new Date(log.timestamp).toLocaleTimeString()}</small>
            `;
            logList.appendChild(li);
        });
    } catch (e) { console.error("Log fetch failed", e); }
};


const loadFiles = async () => {
    try {
        const res = await fetch('/files');
        if (res.status === 401 || res.status === 403) {
            // Session Misuse or Timeout
            alert('Session Invalid or Hijacked! Please login again.');
            location.reload();
            return;
        }
        const data = await res.json();

        fileList.innerHTML = '';
        if (data.files.length === 0) {
            fileList.innerHTML = '<li class="file-item" style="justify-content: center;">No files accessible.</li>';
            return;
        }

        data.files.forEach(file => {
            const li = document.createElement('li');
            li.className = 'file-item';

            let actionBtn = `<button onclick="downloadFile('${file.id}')" class="secondary" style="width: auto; padding: 5px 10px;">Safe Decrypt & Download</button>`;

            if (file.access === 'none') {
                actionBtn = `<button onclick="requestAccess('${file.id}')" style="width: auto; padding: 5px 10px; background: #ffc107; color: black;">Request Access</button>`;
            } else if (file.access === 'pending') {
                actionBtn = `<button disabled style="width: auto; padding: 5px 10px; opacity: 0.6;">Pending...</button>`;
            } else if (file.access === 'rejected') {
                actionBtn = `<button disabled style="width: auto; padding: 5px 10px; background: red; color: white;">Access Denied</button>`;
            }

            li.innerHTML = `
                <div>
                    <strong>${file.filename}</strong> <br>
                    <small style="color: grey">Owner: ${file.owner} | Role: <span class="badge badge-${file.ownerRole}">${file.ownerRole}</span></small>
                </div>
                <div>
                    ${actionBtn}
                </div>
            `;
            fileList.appendChild(li);
        });
    } catch (e) {
        console.error(e);
    }
};

const handleUpload = async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById('file-input');
    const fileNameInput = document.getElementById('file-name');

    if (!fileInput.files[0]) return;

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    if (fileNameInput.value) formData.append('filename', fileNameInput.value);

    try {
        const res = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();

        if (res.ok) {
            alert('File Encrypted & Uploaded!');
            loadFiles();
            uploadForm.reset();
        } else {
            alert(data.error);
        }
    } catch (e) {
        alert('Upload failed');
    }
};

const downloadFile = async (id) => {
    window.location.href = `/files/${id}/download`;
};



const encodeText = async () => {
    const text = document.getElementById('encode-input').value;
    const res = await fetch('/encode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, type: 'base64' })
    });
    const data = await res.json();
    document.getElementById('encode-output').innerText = data.encoded || 'Error';
};

const simulateAttack = async () => {
    if (!confirm("This will simulate a hacker stealing your session. You will be logged out. Proceed?")) return;

    try {
        console.log("Sending simulation request...");
        const res = await fetch('/simulate-attack', { method: 'POST' });

        if (res.ok) {
            console.log("Simulation Active. Triggering security check...");
            // Now try to access a protected resource immediately to trigger the trap
            // We use a slight delay to ensure server state is updated
            setTimeout(() => loadFiles(), 500);
        } else {
            console.error("Simulation request failed", res.status);
            alert(`Simulation failed to start. Server responded with: ${res.status} ${res.statusText}. \n\nDid you restart the server?`);
        }
    } catch (e) {
        console.error("Simulation Network Error:", e);
        alert("Network Error: Could not reach server. Is it running?");
    }
};

// === Event Listeners ===
loginForm.addEventListener('submit', handleLogin);
registerForm.addEventListener('submit', handleRegister);
uploadForm.addEventListener('submit', handleUpload);

// Initial Check
fetch('/me').then(async res => {
    if (res.ok) {
        const data = await res.json();
        currentUser = data.user;
        showDashboard();
    }
});
