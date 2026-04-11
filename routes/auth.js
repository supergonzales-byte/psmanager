const express = require('express')
const crypto  = require('crypto')
const { loadConfig, saveConfig } = require('../lib/config')
const { loadUsers }              = require('../lib/users')
const { createSession, deleteSession } = require('../lib/sessions')
const { getLdapConfig, ldapBind, ldapCheckGroup } = require('../lib/ldap')

const router = express.Router()

// Rate limiting login : max 5 tentatives échouées / 5 min par IP
const loginAttempts = new Map()
function isRateLimited(ip) {
    const now = Date.now()
    const entry = loginAttempts.get(ip)
    if (!entry) return false
    if (now - entry.first > 5 * 60 * 1000) { loginAttempts.delete(ip); return false }
    return entry.count >= 5
}
function recordFailure(ip) {
    const now = Date.now()
    const entry = loginAttempts.get(ip) || { count: 0, first: now }
    if (now - entry.first > 5 * 60 * 1000) { entry.count = 0; entry.first = now }
    entry.count++
    loginAttempts.set(ip, entry)
}
function clearFailures(ip) {
    loginAttempts.delete(ip)
}
setInterval(() => {
    const now = Date.now()
    for (const [ip, e] of loginAttempts) if (now - e.first > 5 * 60 * 1000) loginAttempts.delete(ip)
}, 60000)

router.post('/auth', async (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown'
    if (isRateLimited(ip)) return res.status(429).json({ ok: false, error: 'Trop de tentatives, réessayez dans 5 minutes' })
    const { username, password } = req.body
    if (!username || !password) return res.json({ ok: false, error: 'Identifiants manquants' })

    // 1. Vérification compte local (hash SHA-256 côté serveur)
    const localUsers = loadUsers()
    const hash = crypto.createHash('sha256').update(password, 'utf8').digest('hex')
    if (localUsers[username.toLowerCase()] && localUsers[username.toLowerCase()] === hash) {
        clearFailures(ip)
        const token = createSession(username)
        res.setHeader('Set-Cookie', `psm_token=${token}; HttpOnly; SameSite=Strict; Path=/`)
        return res.json({ ok: true, user: username, mode: 'local' })
    }

    // 2. Vérifier que LDAP est activé
    const ldapCfg = getLdapConfig()
    if (!ldapCfg.enabled) { recordFailure(ip); return res.json({ ok: false, error: 'Authentification LDAP désactivée' }) }

    // 3. Normaliser le username
    let cleanUser = username
    const bs = cleanUser.indexOf(String.fromCharCode(92))
    if (bs !== -1) cleanUser = cleanUser.slice(bs + 1)
    const at = cleanUser.indexOf('@')
    if (at !== -1) cleanUser = cleanUser.slice(0, at)

    // 4. Bind LDAP avec les credentials de l'utilisateur
    const userDN = `${cleanUser}@${ldapCfg.domain}`
    const client = await ldapBind(userDN, password)
    if (!client) { recordFailure(ip); return res.json({ ok: false, error: 'Identifiants incorrects ou serveur LDAP inaccessible' }) }
    try { await client.unbind() } catch {}

    // 5. Vérification appartenance au groupe AD
    const inGroup = await ldapCheckGroup(cleanUser)
    if (!inGroup) { recordFailure(ip); return res.json({ ok: false, error: 'Accès refusé — vous n\'êtes pas membre du groupe autorisé' }) }

    clearFailures(ip)
    const token = createSession(username)
    res.setHeader('Set-Cookie', `psm_token=${token}; HttpOnly; SameSite=Strict; Path=/`)
    res.json({ ok: true, user: username, mode: 'ldap' })
})

router.post('/logout', (req, res) => {
    const cookieHeader = req.headers.cookie || ''
    const match = cookieHeader.match(/(?:^|;\s*)psm_token=([^;]+)/)
    deleteSession(match ? match[1] : null)
    res.setHeader('Set-Cookie', 'psm_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
    res.json({ ok: true })
})

router.get('/ldap-config', (req, res) => {
    const cfg = loadConfig()
    res.json({
        enabled : !!cfg.ldapEnabled,
        servers : cfg.ldapServers || [],
        domain  : cfg.ldapDomain  || '',
        baseDn  : cfg.ldapBaseDn  || '',
        groupDn : cfg.ldapGroupDn || '',
        readDn  : cfg.ldapReadDn  || '',
        // mot de passe jamais renvoyé au client
    })
})

router.post('/ldap-config', (req, res) => {
    const { enabled, servers, domain, baseDn, groupDn, readDn, readPwd } = req.body
    const cfg = loadConfig()
    cfg.ldapEnabled = !!enabled
    cfg.ldapServers = servers
    cfg.ldapDomain  = domain
    cfg.ldapBaseDn  = baseDn
    cfg.ldapGroupDn = groupDn
    cfg.ldapReadDn  = readDn
    if (readPwd) cfg.ldapReadPwd = readPwd
    saveConfig(cfg)
    res.json({ ok: true })
})

module.exports = router
