const net  = require('net')
const os   = require('os')

/**
 * Récupère les interfaces réseau IPv4 locales
 * (exclut loopback et APIPA 169.254.x.x)
 */
function getNetworkInterfaces() {
    const ifaces  = os.networkInterfaces()
    const results = []
    for (const [name, addrs] of Object.entries(ifaces)) {
        for (const addr of addrs) {
            if (addr.family !== 'IPv4') continue
            if (addr.internal) continue
            if (addr.address.startsWith('169.254')) continue
            results.push({
                alias  : name,
                ip     : addr.address,
                prefix : cidrFromNetmask(addr.netmask)
            })
        }
    }
    return results
}

/**
 * Convertit un masque (255.255.255.0) en préfixe CIDR (24)
 */
function cidrFromNetmask(netmask) {
    return netmask.split('.').reduce((acc, octet) => {
        let n = parseInt(octet)
        let count = 0
        while (n) { count += n & 1; n >>= 1 }
        return acc + count
    }, 0)
}

/**
 * Génère toutes les IPs hôtes d'un sous-réseau
 */
function getNetworkRange(ip, prefix) {
    const ipParts  = ip.split('.').map(Number)
    const mask     = (-1 << (32 - prefix)) >>> 0
    const ipInt    = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0
    const netInt   = (ipInt & mask) >>> 0
    const bcast    = (netInt | (~mask >>> 0)) >>> 0
    const hosts    = []
    for (let i = netInt + 1; i < bcast; i++) {
        hosts.push(`${(i >>> 24) & 0xff}.${(i >>> 16) & 0xff}.${(i >>> 8) & 0xff}.${i & 0xff}`)
    }
    return hosts
}

/**
 * Vérifie si le port 5985 est ouvert sur un hôte
 * Envoie une requête HTTP basique et attend une vraie réponse WinRM
 */
function checkPort5985(host, timeout = 1000) {
    return new Promise(resolve => {
        const sock = new net.Socket()
        let resolved = false

        const done = (result) => {
            if (resolved) return
            resolved = true
            sock.destroy()
            resolve(result)
        }

        sock.setTimeout(timeout)
        sock.connect(5985, host, () => {
            // Port ouvert — envoyer requête HTTP basique pour confirmer WinRM
            sock.write(`GET / HTTP/1.0\r\nHost: ${host}\r\n\r\n`)
        })
        sock.on('data', () => done(true))
        sock.on('timeout', () => done(false))
        sock.on('error', () => done(false))
    })
}

/**
 * Scan parallèle d'un sous-réseau — émet des événements via callback
 * @param {string[]} ips - Liste d'IPs à scanner
 * @param {number}   concurrency - Nombre de scans simultanés
 * @param {Function} onProgress - callback(scanned, total, found, ip) appelé à chaque résultat
 * @returns {Promise<string[]>} - Liste des IPs WinRM actives
 */
async function scanNetwork(ips, concurrency, onProgress, isCancelled) {
    const found   = []
    let   scanned = 0
    let   index   = 0

    async function worker() {
        while (index < ips.length) {
            if (isCancelled && isCancelled()) return
            const ip    = ips[index++]
            const alive = await checkPort5985(ip, 1000)
            scanned++
            if (alive) found.push(ip)
            onProgress(scanned, ips.length, found.length, alive ? ip : null)
        }
    }

    const workers = Array.from({ length: Math.min(concurrency, ips.length) }, worker)
    await Promise.all(workers)
    return found
}

module.exports = { getNetworkInterfaces, getNetworkRange, scanNetwork, cidrFromNetmask, checkPort5985 }
