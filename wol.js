const dgram = require('dgram')
const os    = require('os')

/**
 * Convertit une IP string en entier 32 bits
 */
function ipToInt(ip) {
    return ip.split('.').reduce((acc, oct) => (acc << 8) | parseInt(oct), 0) >>> 0
}

/**
 * Convertit un masque string en entier 32 bits
 */
function maskToInt(mask) {
    return ipToInt(mask)
}

/**
 * Trouve l'IP source de la bonne interface pour atteindre targetIp
 * Retourne null si aucune interface ne correspond (fallback broadcast général)
 */
function findSourceIp(targetIp) {
    const targetInt = ipToInt(targetIp)
    const ifaces    = os.networkInterfaces()
    for (const [, addrs] of Object.entries(ifaces)) {
        for (const addr of addrs) {
            if (addr.family !== 'IPv4' || addr.internal) continue
            const ifaceInt = ipToInt(addr.address)
            const maskInt  = maskToInt(addr.netmask)
            if ((targetInt & maskInt) === (ifaceInt & maskInt)) {
                return addr.address
            }
        }
    }
    return null // fallback : 0.0.0.0 → broadcast général
}

/**
 * Envoie un paquet magique Wake-on-LAN (UDP broadcast port 9)
 * @param {string} mac      - Adresse MAC (XX:XX:XX:XX:XX:XX ou XX-XX-XX-XX-XX-XX)
 * @param {string} targetIp - IP du poste cible (pour choisir automatiquement l'interface)
 */
function sendWol(mac, targetIp = null) {
    return new Promise((resolve, reject) => {
        const macClean = mac.replace(/[:\-\.]/g, '')
        if (macClean.length !== 12) return reject(new Error(`Adresse MAC invalide : ${mac}`))

        const macBytes = Buffer.from(macClean, 'hex')
        const magic    = Buffer.concat([
            Buffer.alloc(6, 0xff),
            ...Array(16).fill(macBytes)
        ])

        const sourceIp = targetIp ? findSourceIp(targetIp) : null

        const sock = dgram.createSocket('udp4')
        sock.once('error', reject)

        sock.bind(0, sourceIp || '0.0.0.0', () => {
            sock.setBroadcast(true)
            sock.send(magic, 0, magic.length, 9, '255.255.255.255', (err) => {
                sock.close()
                if (err) reject(err)
                else resolve(sourceIp)
            })
        })
    })
}

module.exports = { sendWol, findSourceIp }
