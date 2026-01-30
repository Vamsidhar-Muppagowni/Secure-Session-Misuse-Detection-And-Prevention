require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const multer = require('multer');
const qrcode = require('qrcode');
const speakeasy = require('speakeasy');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

// === MongoDB Connection ===
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// === Schemas ===
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['student', 'faculty', 'admin'], default: 'student' },
    twoFactorSecret: { type: String },
    publicKey: { type: String }, // RSA Public Key
    privateKey: { type: String }, // RSA Private Key (Stored for Demo)
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const FileSchema = new mongoose.Schema({
    filename: { type: String, required: true },
    owner: { type: String, required: true },
    ownerRole: { type: String, required: true },
    data: { type: String, required: true }, // Encrypted Hex
    iv: { type: String, required: true }, // Initialization Vector
    signature: { type: String }, // Digital Signature
    hash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const File = mongoose.model('File', FileSchema);

const AccessRequestSchema = new mongoose.Schema({
    student: { type: String, required: true },
    fileId: { type: mongoose.Schema.Types.ObjectId, ref: 'File', required: true },
    faculty: { type: String, required: true }, // Owner of file
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});
const AccessRequest = mongoose.model('AccessRequest', AccessRequestSchema);

// === 1. Simple In-Memory Session Storage ===
// In a real app, uses a database. Here, we use a simple object to show how it works.
const sessions = {};
// Store security alerts for the dashboard to show
const securityLogs = [];
// Store OTPs temporarily: { email: { code: '123456', expires: timestamp } }
const otpStore = {};

// Setup Nodemailer Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', // Easy setup for Gmail
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});


app.use(bodyParser.json());
app.use(express.static('public'));

// === 2. Manual Session Middleware ===
// We check the "Cookie" header manually to find the Session ID.
// Then we look up the user in our 'sessions' object.
const accessControl = (req, res, next) => {
    // A. Parse Cookies
    const cookieHeader = req.headers.cookie;
    let sessionId = null;

    if (cookieHeader) {
        // Cookies are "key=value; key2=value2". We just want "sessionId".
        const cookies = cookieHeader.split(';').map(c => c.trim());
        const sessionCookie = cookies.find(c => c.startsWith('sessionId='));
        if (sessionCookie) {
            sessionId = sessionCookie.split('=')[1];
        }
    }

    // B. Check Session Validation
    if (!sessionId || !sessions[sessionId]) {
        return res.status(401).json({ error: 'Unauthorized: No valid session found.' });
    }

    const sessionData = sessions[sessionId];

    // C. Misuse Detection (Simpler Logic)
    const currentUA = req.headers['user-agent'];
    if (sessionData.userAgent !== currentUA) {
        console.warn(`[SECURITY ALERT] Session Hijack Attempt! User: ${sessionData.username}`);

        // LOG THE EVENT FOR THE DASHBOARD
        securityLogs.unshift({
            id: crypto.randomUUID(),
            type: 'SESSION_HIJACK',
            message: 'User-Agent Mismatch Detected',
            username: sessionData.username,
            ip: req.ip,
            expectedUA: sessionData.userAgent,
            actualUA: currentUA,
            timestamp: new Date().toISOString()
        });

        delete sessions[sessionId]; // Kill the session
        return res.status(403).json({ error: 'Session Validated Failed: User-Agent Mismatch (Potential Session Hijack)' });
    }

    // Attach user info to request for the next steps
    req.user = sessionData;
    req.sessionId = sessionId; // Attach ID for routes to use
    next();
};

// === 3. Simple Cryptography (Demonstration) ===

// A. Simple Password Hashing (SHA-256)
const hashPassword = (password) => {
    return crypto.createHash('sha256').update(password).digest('hex');
};

// B. AES-256-CBC Encryption
const AES_ALGORITHM = 'aes-256-cbc';

const encryptAES = (buffer) => {
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(process.env.AES_SECRET, 'hex');
    const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), content: encrypted.toString('hex') };
};

const decryptAES = (encryptedHex, ivHex) => {
    const iv = Buffer.from(ivHex, 'hex');
    const key = Buffer.from(process.env.AES_SECRET, 'hex');
    const encryptedText = Buffer.from(encryptedHex, 'hex');
    const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
};

// === Routes ===

// SEND EMAIL OTP
app.post('/send-email-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Store OTP (valid for 5 mins)
    otpStore[email] = {
        code: otp,
        expires: Date.now() + 5 * 60 * 1000
    };

    if (!transporter) return res.status(500).json({ error: 'Mail server not ready' });

    try {
        const info = await transporter.sendMail({
            from: '"Secure Lab" <noreply@securelab.com>',
            to: email,
            subject: "Your Registration OTP",
            text: `Your OTP is: ${otp}`,
            html: `<b>Your OTP is: ${otp}</b>`
        });

        console.log(`[MAIL] OTP sent to ${email}`);
        res.json({ message: 'OTP Sent to your email!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to send email' });
    }
});

// REGISTER call
app.post('/register', async (req, res) => {
    const { username, password, role, email, emailOtp } = req.body;
    if (!username || !password || !email || !emailOtp) return res.status(400).json({ error: 'Missing fields' });

    // Verify OTP
    const storedOtp = otpStore[email];
    if (!storedOtp || storedOtp.code !== emailOtp) {
        return res.status(400).json({ error: 'Invalid or Expired Email OTP' });
    }
    if (Date.now() > storedOtp.expires) {
        return res.status(400).json({ error: 'OTP Expired' });
    }

    // Clean up OTP
    delete otpStore[email];

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Generate 2FA Secret
        const secret = speakeasy.generateSecret({ name: `SecureSessionLab (${username})` });

        // Generate RSA Key Pair for Digital Signatures
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        // Save User with Hashed Password
        await User.create({
            username,
            email,
            password: hashPassword(password),
            role: ['admin', 'student', 'faculty'].includes(role) ? role : 'student',
            twoFactorSecret: secret.base32,
            publicKey,
            privateKey
        });

        // Generate QR Code
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
        res.json({ message: 'Registration successful!', qrCodeUrl, secret: secret.base32 });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// LOGIN
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        console.log(`[LOGIN DEBUG] Attempting login for: ${username}`);
        const user = await User.findOne({ username });

        if (!user) {
            console.log('[LOGIN DEBUG] User NOT found in database.');
            return res.status(401).json({ error: 'Invalid credentials (User not found)' });
        }

        const computedHash = hashPassword(password);
        console.log(`[LOGIN DEBUG] User found. Stored Hash: ${user.password}`);
        console.log(`[LOGIN DEBUG] Computed Hash: ${computedHash}`);

        // Verify Hash
        if (user.password !== computedHash) {
            console.log('[LOGIN DEBUG] Password verification FAILED.');
            return res.status(401).json({ error: 'Invalid credentials (Password mismatch)' });
        }

        console.log('[LOGIN DEBUG] Password verified. Proceeding to session creation.');

        // === SINGLE SESSION ENFORCEMENT ===
        // Check if user is already logged in elsewhere
        Object.keys(sessions).forEach(existingSessionId => {
            if (sessions[existingSessionId].username === user.username) {
                console.warn(`[SECURITY] Killing old session for ${user.username} due to new login.`);

                // Log this event so it shows on the Admin Dashboard
                securityLogs.unshift({
                    id: crypto.randomUUID(),
                    type: 'CONCURRENT_LOGIN_KICK',
                    message: 'New login detected from another device. Old session terminated.',
                    username: user.username,
                    ip: req.ip,
                    expectedUA: sessions[existingSessionId].userAgent,
                    actualUA: req.headers['user-agent'],
                    timestamp: new Date().toISOString()
                });

                delete sessions[existingSessionId];
            }
        });

        // Create Session
        const sessionId = crypto.randomUUID(); // Random ID
        sessions[sessionId] = {
            id: user._id.toString(),
            username: user.username,
            role: user.role,
            userAgent: req.headers['user-agent'], // Bind to Browser
            ip: req.ip,
            isMfaVerified: false // Flag for 2FA
        };

        // Set Cookie Manually
        res.setHeader('Set-Cookie', `sessionId=${sessionId}; HttpOnly; Path=/`);

        res.json({ message: 'Login successful', user: { username: user.username, role: user.role } });
    } catch (err) {
        console.error('[LOGIN DEBUG] Error during login:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// MISUSE SIMULATOR (For Demo Only)
app.post('/simulate-attack', accessControl, (req, res) => {
    const sessionId = req.sessionId; // Use the ID passed by middleware

    if (sessions[sessionId]) {
        // Tamper with the server's record of the user's browser
        sessions[sessionId].userAgent = "Evil Hacker Browser v1.0";
        console.log(`[DEMO] Simulating Attack: Changed stored User-Agent for ${req.user.username} to 'Evil Hacker Browser'. Next request should fail.`);
    }
    res.json({ message: 'Attack Simulated! Next request will trigger security alert.' });
});

// UPLOAD (Encrypted)
const upload = multer({ storage: multer.memoryStorage() });
app.post('/upload', accessControl, upload.single('file'), async (req, res) => {
    const { filename } = req.body;
    if (!req.file) return res.status(400).json({ error: 'No file' });

    // Encryption Step
    // Encryption Step
    const { iv, content } = encryptAES(req.file.buffer);

    // Digital Signature Step
    let signature = null;
    try {
        const user = await User.findOne({ username: req.user.username });
        if (user && user.privateKey) {
            const sign = crypto.createSign('SHA256');
            sign.update(req.file.buffer);
            sign.end();
            signature = sign.sign(user.privateKey, 'hex');
        }
    } catch (sigErr) {
        console.warn('Signing failed (legacy user?):', sigErr);
    }

    try {
        await File.create({
            filename: filename || req.file.originalname,
            owner: req.user.username,
            ownerRole: req.user.role,
            // We store the encrypted data as a Hex string to save in JSON easily
            data: content,
            iv: iv,
            signature: signature,
            hash: crypto.createHash('sha256').update(req.file.buffer).digest('hex')
        });
        res.json({ message: 'File Encrypted (AES-256) & Stored!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// LIST FILES (ACL)
app.get('/files', accessControl, async (req, res) => {
    const { role, username } = req.user;

    try {
        const files = await File.find({}); // Get all files, filter in memory or query

        const visibleFiles = files.filter(f => {
            if (role === 'admin') return true;
            // Student sees Own + Faculty Files
            if (role === 'student') {
                return f.owner === username || f.ownerRole === 'faculty';
            }
            // Faculty sees Own + Student Files
            if (role === 'faculty') {
                return f.owner === username || f.ownerRole === 'student';
            }
            return false;
        });

        // Enrich with Access Permission status for Students viewing Faculty files
        const fileList = await Promise.all(visibleFiles.map(async f => {
            const { data, ...rest } = f.toObject();
            let access = 'granted'; // Default for own files or Admin

            if (role === 'student' && f.ownerRole === 'faculty') {
                // Check if request exists
                const req = await AccessRequest.findOne({ student: username, fileId: f._id });
                if (req) {
                    access = req.status; // pending, approved, rejected
                } else {
                    access = 'none'; // Need to request
                }
            }

            return { ...rest, id: f._id, access };
        }));

        res.json({ files: fileList });
    } catch (err) {
        res.status(500).json({ error: 'Fetch failed' });
    }
});

// DOWNLOAD (Decrypt)
app.get('/files/:id/download', accessControl, async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) return res.status(404).json({ error: 'File not found' });

        // ACL Check
        const { role, username } = req.user;
        let allowed = false;

        if (role === 'admin') allowed = true;
        else if (file.owner === username) allowed = true;
        else if (role === 'faculty' && file.ownerRole === 'student') allowed = true;
        else if (role === 'student' && file.ownerRole === 'faculty') {
            // Check Approval
            const req = await AccessRequest.findOne({ student: username, fileId: file._id, status: 'approved' });
            if (req) allowed = true;
        }

        if (!allowed) return res.status(403).json({ error: 'Access Denied. Request permission first.' });

        // Decryption Step
        // Decryption Step
        const decryptedBuffer = decryptAES(file.data, file.iv);

        // Integrity Check
        const currentHash = crypto.createHash('sha256').update(decryptedBuffer).digest('hex');
        if (currentHash !== file.hash) console.error('Integrity Mismatch!');

        res.setHeader('Content-Disposition', 'attachment; filename=' + file.filename);
        res.write(decryptedBuffer);
        res.end();
    } catch (err) {
        res.status(500).json({ error: 'Download failed' });
    }
});

// ACCESS REQUEST ROUTES
app.post('/access/request', accessControl, async (req, res) => {
    const { fileId } = req.body;
    try {
        const file = await File.findById(fileId);
        if (!file) return res.status(404).json({ error: 'File not found' });

        await AccessRequest.create({
            student: req.user.username,
            fileId: file._id,
            faculty: file.owner
        });
        res.json({ message: 'Request Sent' });
    } catch (err) { res.status(500).json({ error: 'Request Failed' }); }
});

app.get('/access/pending', accessControl, async (req, res) => {
    try {
        const requests = await AccessRequest.find({ faculty: req.user.username, status: 'pending' }).populate('fileId', 'filename');
        res.json({ requests });
    } catch (err) { res.status(500).json({ error: 'Fetch Failed' }); }
});

app.post('/access/approve', accessControl, async (req, res) => {
    const { requestId, action } = req.body; // action: approved/rejected
    try {
        await AccessRequest.findByIdAndUpdate(requestId, { status: action });
        res.json({ message: 'Success' });
    } catch (err) { res.status(500).json({ error: 'Update Failed' }); }
});


// UTILS
app.get('/me', accessControl, (req, res) => {
    res.json({ user: req.user });
});

app.post('/logout', (req, res) => {
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        const sessionId = cookieHeader.split('sessionId=')[1]?.split(';')[0];
        if (sessionId) delete sessions[sessionId];
    }
    res.setHeader('Set-Cookie', 'sessionId=; Max-Age=0; Path=/');
    res.json({ message: 'Logged out' });
});

// SECURITY MONITOR (Admin / Demo View)
app.get('/security-logs', (req, res) => {
    res.json({ logs: securityLogs });
});


app.post('/verify-mfa', accessControl, async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Code required' });

    try {
        const user = await User.findOne({ username: req.user.username });

        if (!user || !user.twoFactorSecret) {
            return res.status(400).json({ error: '2FA not set up for this user' });
        }

        const isValid = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: code
        });

        if (isValid) {
            sessions[req.sessionId].isMfaVerified = true;
            res.json({ message: 'MFA Verified' });
        } else {
            res.status(401).json({ error: 'Invalid Token' });
        }
    } catch (err) {
        res.status(500).json({ error: 'MFA Verification failed' });
    }
});
app.post('/encode', (req, res) => res.json({ encoded: Buffer.from(req.body.text).toString('base64') }));

// DB VIEWER (Simple UI to see data)
app.get('/db-viewer', async (req, res) => {
    try {
        const users = await User.find({});
        const files = await File.find({});

        let html = `
        <html>
        <head>
            <title>Database Viewer</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; padding: 20px; background: #f4f4f4; }
                .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                table { border-collapse: collapse; width: 100%; margin-bottom: 30px; font-size: 14px; }
                th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
                th { background-color: #007bff; color: white; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .hash { font-family: monospace; font-size: 12px; color: #d63384; word-break: break-all; }
                .key { font-family: monospace; font-weight: bold; color: #198754; }
                h2 { border-bottom: 2px solid #ddd; padding-bottom: 10px; margin-top: 50px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Secure Session - Database Inspector</h1>
                
                <h2>🔑 System Keys</h2>
                <p><strong>Encryption Algorithm:</strong> <span class="key">AES-256-CBC</span></p>
                <p><strong>Hashing Algorithm:</strong> <span class="key">SHA-256</span></p>
                <p><strong>Digital Signature:</strong> <span class="key">RSA-2048 (SHA-256)</span></p>

                <h2>👤 Users (${users.length})</h2>
                <table>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Password Hash (SHA-256)</th>
                        <th>2FA Secret (Base32)</th>
                    </tr>
                    ${users.map(u => `
                        <tr>
                            <td>${u.username}</td>
                            <td>${u.role}</td>
                            <td>${u.role}</td>
                            <td class="hash">${u.password}</td>
                            <td class="hash">${u.twoFactorSecret || '<span style="color:red">Not Set</span>'}</td>
                        </tr>
                        <tr>
                             <td colspan="4" style="background:#f0f0f0; font-size:10px;">
                                <strong>Public Key:</strong> <span style="color:blue">${u.publicKey ? u.publicKey.replace(/\n/g, '') : 'None'}</span>
                             </td>
                        </tr>`).join('')}
                </table>

                <h2>📂 Encrypted Files (${files.length})</h2>
                <table>
                        <tr>
                            <th>Filename</th>
                            <th>Owner</th>
                            <th>Key Type</th>
                            <th>IV (Hex)</th>
                            <th>Digital Signature (Hex)</th>
                            <th>Integrity Hash (SHA-256)</th>
                            <th>Encrypted Data Preview (Hex)</th>
                        </tr>
                    ${files.map(f => `
                        <tr>
                            <td>${f.filename}</td>
                            <td>${f.owner}</td>
                            <td><span class="key">Symmetric (AES)</span></td>
                            <td class="hash">${f.iv || '<span style="color:red">Legacy (XOR)</span>'}</td>
                            <td class="hash">${f.signature ? f.signature.substring(0, 30) + '...' : '<span style="color:red">Unsigned</span>'}</td>
                            <td class="hash">${f.hash}</td>
                            <td class="hash">${f.data.substring(0, 60)}...</td>
                        </tr>`).join('')}
                </table>
            </div>
        </body>
        </html>
        `;
        res.send(html);
    } catch (err) {
        res.status(500).send('Error fetching data: ' + err.message);
    }
});

app.listen(PORT, () => console.log(`Simple Server running on http://localhost:${PORT}`));
