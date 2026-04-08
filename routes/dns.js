const express = require('express')
const fs      = require('fs')
const dns     = require('dns')
const { PARC_FILE } = require('../lib/constants')

const router = express.Router()

function resolveHostname(hostname) {
    return new Promise(resolve => {
        dns.lookup(hostname, { family: 4 }, (err, address) => {
            resolve(err ? null : address)
        })
    })
}

function updateParcIp(hostname, ip) {
    try {
        const lines = fs.readFileSync(PARC_FILE, 'utf-8')
            .split('\n').map(l => l.trim()).filter(l => l)
        const idx = lines.findIndex(l => l.startsWith(hostname + '|'))
        if (idx >= 0) {
            const parts = lines[idx].split('|')
            if (parts[1] !== ip) {
                parts[1] = ip
                lines[idx] = parts.join('|')
                fs.writeFileSync(PARC_FILE, lines.join('\n'), 'utf-8')
                return true
            }
        }
        return false
    } catch { return false }
}

router.get('/resolve', async (req, res) => {
    const { hostname } = req.query
    if (!hostname) return res.status(400).json({ error: 'hostname requis' })
    const ip = await resolveHostname(hostname)
    if (!ip) return res.json({ ok: false, error: 'Résolution impossible' })
    const changed = updateParcIp(hostname, ip)
    res.json({ ok: true, ip, changed })
})

router.post('/resolve-batch', async (req, res) => {
    const { hostnames } = req.body
    if (!hostnames || !hostnames.length) return res.json({ results: [] })

    const results = await Promise.all(
        hostnames.map(hostname =>
            resolveHostname(hostname)
                .then(ip => ({ hostname, ok: !!ip, ip: ip || '' }))
        )
    )

    try {
        let lines = fs.readFileSync(PARC_FILE, 'utf-8')
            .split('\n').map(l => l.trim()).filter(l => l)
        let updated = false
        for (const { hostname, ok, ip } of results) {
            if (!ok) continue
            const idx = lines.findIndex(l => l.startsWith(hostname + '|'))
            if (idx >= 0) {
                const parts = lines[idx].split('|')
                if (parts[1] !== ip) { parts[1] = ip; lines[idx] = parts.join('|'); updated = true }
            }
        }
        if (updated) fs.writeFileSync(PARC_FILE, lines.join('\n'), 'utf-8')
    } catch(e) { console.error('resolve-batch parc.txt:', e.message) }

    res.json({ results })
})

module.exports = router
