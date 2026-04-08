const crypto = require('crypto')

const sessions = new Map()

// Nettoyer les sessions expirées toutes les heures
setInterval(() => {
    const now = Date.now()
    for (const [t, s] of sessions) if (s.expires < now) sessions.delete(t)
}, 3600000)

function createSession(username) {
    const token = crypto.randomBytes(32).toString('hex')
    sessions.set(token, { user: username, expires: Date.now() + 8 * 3600 * 1000 })
    return token
}

function requireAuth(req, res, next) {
    const cookieHeader = req.headers.cookie || ''
    const match = cookieHeader.match(/(?:^|;\s*)psm_token=([^;]+)/)
    const token = match ? match[1] : null
    if (!token) return res.status(401).json({ error: 'Non authentifié' })
    const session = sessions.get(token)
    if (!session || session.expires < Date.now()) {
        sessions.delete(token)
        return res.status(401).json({ error: 'Session expirée' })
    }
    next()
}

function deleteSession(token) {
    if (token) sessions.delete(token)
}

module.exports = { sessions, createSession, requireAuth, deleteSession }
