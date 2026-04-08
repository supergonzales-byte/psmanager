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

    console.log(`[LDAP] ldapBind — userDN="${userDN}" servers=${JSON.stringify(servers)}`)

    if (!servers.length) {
        console.log('[LDAP] Aucun serveur configuré')
        return null
    }

    for (const server of servers) {
        const s = String(server || '').trim()
        if (!s) continue

        // Si protocole explicite → une seule URL, sinon on essaie ldaps:// puis ldap://
        const hasProto = /^ldaps?:\/\//i.test(s)
        const urls = hasProto ? [s] : [`ldaps://${s}`, `ldap://${s}`]

        for (const url of urls) {
            console.log(`[LDAP] Tentative bind sur ${url}`)
            const isLdaps = url.toLowerCase().startsWith('ldaps://')
            const client = new Client({
                url,
                timeout        : 5000,
                connectTimeout : 5000,
                ...(isLdaps ? { tlsOptions: { rejectUnauthorized: false } } : {})
            })
            try {
                await client.bind(userDN, password)
                console.log(`[LDAP] Bind réussi sur ${url}`)
                return client
            } catch (err) {
                console.log(`[LDAP] Erreur sur ${url} — code=${err.code} name=${err.name} message=${err.message}`)
                try { await client.unbind() } catch {}
                // Mauvais identifiants → stop immédiat, ne pas tenter les autres serveurs/urls
                if (err.code === 49 || err.name === 'InvalidCredentialsError') {
                    console.log('[LDAP] Mauvais identifiants — arrêt immédiat')
                    return null
                }
                // Erreur réseau → essayer l'url suivante (ldap:// si ldaps:// a échoué)
                console.log('[LDAP] Erreur réseau — essai suivant')
            }
        }
    }
    console.log('[LDAP] Tous les serveurs ont échoué')
    return null
}

async function ldapCheckGroup(username) {
    const { readDn, readPwd, baseDn, groupDn } = getLdapConfig()
    console.log(`[LDAP] ldapCheckGroup — username="${username}" readDn="${readDn}" groupDn="${groupDn}"`)
    const client = await ldapBind(readDn, readPwd)
    if (!client) { console.log('[LDAP] ldapCheckGroup — bind readDn échoué'); return false }
    if (!groupDn) { try { await client.unbind() } catch {}; return false }
    try {
        const filter = `(&(sAMAccountName=${escapeLdapFilter(username)})(memberOf:1.2.840.113556.1.4.1941:=${escapeLdapFilter(groupDn)}))`
        console.log(`[LDAP] Search filter: ${filter}`)
        const { searchEntries } = await client.search(baseDn, {
            scope      : 'sub',
            filter,
            attributes : ['sAMAccountName'],
            sizeLimit  : 1
        })
        console.log(`[LDAP] Search résultat: ${searchEntries.length} entrée(s)`)
        return searchEntries.length > 0
    } catch (err) {
        console.log(`[LDAP] Erreur search: ${err.message}`)
        return false
    } finally {
        try { await client.unbind() } catch {}
    }
}

module.exports = { escapeLdapFilter, getLdapConfig, ldapBind, ldapCheckGroup }
