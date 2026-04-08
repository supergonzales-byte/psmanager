const fs   = require('fs')
const os   = require('os')
const { CONFIG_FILE, SSL_DIR, SSL_KEY, SSL_CERT, PORT, HTTPS_PORT } = require('./constants')

function loadConfig() {
    try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) }
    catch { return { httpsEnabled: false } }
}

function saveConfig(cfg) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2))
}

function ensureSslCert() {
    if (!fs.existsSync(SSL_DIR)) fs.mkdirSync(SSL_DIR)
    if (!fs.existsSync(SSL_KEY) || !fs.existsSync(SSL_CERT)) {
        const selfsigned = require('selfsigned')
        const attrs = [{ name: 'commonName', value: 'ps-manager' }]
        const pems  = selfsigned.generate(attrs, { days: 3650, keySize: 2048 })
        fs.writeFileSync(SSL_KEY,  pems.private)
        fs.writeFileSync(SSL_CERT, pems.cert)
    }
}

// Remplace localhost par l'IP LAN réelle (les postes clients ne peuvent pas atteindre localhost)
function resolveServerOrigin(serverOrigin) {
    if (!serverOrigin || /localhost|127\.0\.0\.1|::1/.test(serverOrigin)) {
        const ifaces = os.networkInterfaces()
        for (const addrs of Object.values(ifaces)) {
            for (const addr of addrs) {
                if (addr.family === 'IPv4' && !addr.internal) {
                    const cfg   = loadConfig()
                    const proto = cfg.httpsEnabled ? 'https' : 'http'
                    const port  = cfg.httpsEnabled ? HTTPS_PORT : PORT
                    return `${proto}://${addr.address}:${port}`
                }
            }
        }
    }
    return serverOrigin
}

module.exports = { loadConfig, saveConfig, ensureSslCert, resolveServerOrigin }
