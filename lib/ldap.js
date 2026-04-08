const { loadConfig } = require('./config')

function escapeLdapFilter(s) {
    return s.replace(/[\\*()\x00]/g, c => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'))
}

function getLdapConfig() {
    const cfg = loadConfig()
    return {
        enabled : !!cfg.ldapEnabled,
        servers : Array.isArray(cfg.ldapServers) ? cfg.ldapServers : [],
        domain  : cfg.ldapDomain  || '',
        baseDn  : cfg.ldapBaseDn  || '',
        groupDn : cfg.ldapGroupDn || '',
        readDn  : cfg.ldapReadDn  || '',
        readPwd : cfg.ldapReadPwd || '',
    }
}

// Retourne un client ldapts connecté et bindé, ou null si échec
// Mauvais identifiants → stop immédiat (évite le verrouillage AD sur plusieurs serveurs)
// Erreur réseau → essaie le serveur suivant
async function ldapBind(userDN, password) {
    const { Client } = require('ldapts')
    const servers = getLdapConfig().servers

    for (const server of servers) {
        const s = String(server || '').trim()
        if (!s) continue
        const url = /^ldaps?:\/\//i.test(s) ? s : `ldap://${s}`
        const client = new Client({
            url,
            timeout        : 5000,
            connectTimeout : 5000,
            tlsOptions     : { rejectUnauthorized: false }
        })
        try {
            await client.bind(userDN, password)
            return client
        } catch (err) {
            try { await client.unbind() } catch {}
            // Mauvais identifiants → stop immédiat, ne pas tenter les autres serveurs
            if (err.code === 49 || err.name === 'InvalidCredentialsError') return null
            // Erreur réseau/connexion → essayer le serveur suivant
        }
    }
    return null
}

async function ldapCheckGroup(username) {
    const { readDn, readPwd, baseDn, groupDn } = getLdapConfig()
    const client = await ldapBind(readDn, readPwd)
    if (!client) return false
    if (!groupDn) { try { await client.unbind() } catch {}; return false }
    try {
        const filter = `(&(sAMAccountName=${escapeLdapFilter(username)})(memberOf:1.2.840.113556.1.4.1941:=${escapeLdapFilter(groupDn)}))`
        const { searchEntries } = await client.search(baseDn, {
            scope      : 'sub',
            filter,
            attributes : ['sAMAccountName'],
            sizeLimit  : 1
        })
        return searchEntries.length > 0
    } catch {
        return false
    } finally {
        try { await client.unbind() } catch {}
    }
}

module.exports = { escapeLdapFilter, getLdapConfig, ldapBind, ldapCheckGroup }
