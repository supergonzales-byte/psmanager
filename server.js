const express = require('express')
const fs      = require('fs')
const path    = require('path')

const { PORT, HTTPS_PORT, SSL_KEY, SSL_CERT, INSTALLERS_DIR } = require('./lib/constants')
const { loadConfig, ensureSslCert }                            = require('./lib/config')
const { requireAuth }                                          = require('./lib/sessions')

const app = express()
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))
// Expose les installeurs pour téléchargement par les postes distants (sans auth — URL interne seulement)
app.use('/installers', express.static(INSTALLERS_DIR))

// ── Middleware auth — toutes les routes /api/ sauf /auth et /logout ──
app.use('/api', (req, res, next) => {
    if (req.path === '/auth' || req.path === '/logout') return next()
    requireAuth(req, res, next)
})

// ── Routes ──
app.use('/api', require('./routes/auth'))
app.use('/api', require('./routes/inventory'))
app.use('/api', require('./routes/uploads'))
app.use('/api', require('./routes/execution'))
app.use('/api', require('./routes/actions'))
app.use('/api', require('./routes/installation'))
app.use('/api', require('./routes/drivers'))
app.use('/api', require('./routes/filesystem'))
app.use('/api', require('./routes/rdp'))
app.use('/api', require('./routes/reports'))
app.use('/api', require('./routes/lldp'))
app.use('/api', require('./routes/disk'))
app.use('/api', require('./routes/dns'))
app.use('/api', require('./routes/registry'))
app.use('/api', require('./routes/warranty'))
app.use('/api', require('./routes/admin'))
app.use('/api', require('./routes/scheduling'))

// ── Serveur HTTP/HTTPS ──
const http  = require('http')
const https = require('https')
const cfg   = loadConfig()
let server

if (cfg.httpsEnabled) {
    ensureSslCert()
    server = https.createServer({ key: fs.readFileSync(SSL_KEY), cert: fs.readFileSync(SSL_CERT) }, app)
} else {
    server = http.createServer(app)
}

// ── WebSocket terminal interactif (node-pty) ──
try {
    const WebSocket = require('ws')
    const pty       = require('node-pty')
    const wss       = new WebSocket.Server({ server })

    wss.on('connection', ws => {
        let ptyProcess = null

        ws.on('message', raw => {
            let msg
            try { msg = JSON.parse(raw) } catch { msg = null }

            if (msg && msg.type === 'init') {
                const { hostname, username, password } = msg
                const psCmd = `$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass); Enter-PSSession -ComputerName '${hostname}' -Credential $cred`
                ptyProcess = pty.spawn('powershell.exe', ['-NoExit', '-Command', psCmd], {
                    name: 'xterm-color',
                    cols: msg.cols || 120,
                    rows: msg.rows || 30,
                    env: process.env
                })
                ptyProcess.onData(data => { if (ws.readyState === WebSocket.OPEN) ws.send(data) })
                ptyProcess.onExit(() => {
                    if (ws.readyState === WebSocket.OPEN) ws.send('\r\n[Session terminée]\r\n')
                    ptyProcess = null
                })
            } else if (msg && msg.type === 'resize' && ptyProcess) {
                ptyProcess.resize(msg.cols, msg.rows)
            } else if (ptyProcess) {
                ptyProcess.write(typeof raw === 'string' ? raw : raw.toString())
            }
        })

        ws.on('close', () => { if (ptyProcess) { try { ptyProcess.kill() } catch {} } })
    })

    console.log('✔ WebSocket terminal PS actif')
} catch(e) {
    console.warn('node-pty ou ws non installé — terminal interactif désactivé:', e.message)
}

// ── Démarrage ──
const listenPort  = cfg.httpsEnabled ? HTTPS_PORT : PORT
const listenProto = cfg.httpsEnabled ? 'https' : 'http'
server.listen(listenPort, '0.0.0.0', () => {
    console.log(`PS Manager Node — ${listenProto}://localhost:${listenPort}`)
})
