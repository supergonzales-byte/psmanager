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
        const urls = hasProto ? [s] : [`ldap://${s}`]

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
                // Mauvais identifiants ou compte bloqué → stop immédiat, ne pas tenter les autres serveurs
                // code 49 = InvalidCredentials, 19 = ConstraintViolation (compte verrouillé/expiré)
                if (err.code === 49 || err.code === 19 || err.name === 'InvalidCredentialsError' || err.name === 'ConstraintViolationError') {
                    console.log(`[LDAP] Mauvais identifiants ou compte bloqué (code ${err.code}) — arrêt immédiat`)
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

async function ldapGetComputerOU(hostname) {
    const { readDn, readPwd, baseDn } = getLdapConfig()
    const client = await ldapBind(readDn, readPwd)
    if (!client) throw new Error('Impossible de se connecter au serveur LDAP')

    function getOuName(dn) {
        const p = dn.split(',').find(s => s.trim().toUpperCase().startsWith('OU='))
        return p ? p.replace(/^OU=/i, '').trim() : ''
    }
    function getParentDn(dn) { return dn.split(',').slice(1).join(',') }

    try {
        // 1. Trouver le poste dans l'AD
        const { searchEntries: found } = await client.search(baseDn, {
            scope: 'sub',
            filter: `(&(objectCategory=computer)(name=${escapeLdapFilter(hostname)}))`,
            attributes: ['dn'], sizeLimit: 1
        })
        if (!found.length) throw new Error(`Ordinateur "${hostname}" introuvable dans l'AD`)

        const compDn  = found[0].dn
        const ouDn    = getParentDn(compDn)
        const ouName  = getOuName(ouDn)

        // 2. Compter les postes dans l'OU directe (subtree comme le PS1)
        const { searchEntries: ouComps } = await client.search(ouDn, {
            scope: 'sub', filter: '(objectCategory=computer)', attributes: ['name'],
        })

        let location, computers
        if (ouComps.length <= 1) {
            // Poste seul dans son OU — valide uniquement si l'OU s'appelle Postes_Prof
            if (!/postes?[_\s-]?prof/i.test(ouName))
                throw new Error(`Poste isolé hors OU Postes_Prof (OU courante : "${ouName}")`)

            // Structure : OU=Postes_Prof sous OU=Salle → les élèves sont dans OU=Salle
            const parentDn = getParentDn(ouDn)
            location = getOuName(parentDn)
            const { searchEntries: parentComps } = await client.search(parentDn, {
                scope: 'sub', filter: '(objectCategory=computer)', attributes: ['name'],
            })
            // Exclure le poste prof lui-même
            computers = parentComps.map(c => c.name).filter(n => n && n.toLowerCase() !== hostname.toLowerCase())
        } else {
            location  = ouName
            // Exclure le poste prof lui-même
            computers = ouComps.map(c => c.name).filter(n => n && n.toLowerCase() !== hostname.toLowerCase())
        }
        return { location, computers }
    } finally {
        try { await client.unbind() } catch {}
    }
}

module.exports = { escapeLdapFilter, getLdapConfig, ldapBind, ldapCheckGroup, ldapGetComputerOU }
