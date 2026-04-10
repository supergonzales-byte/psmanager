const express = require('express')
const fs      = require('fs')
const path    = require('path')
const { PARC_FILE, SCRIPTS_DIR, LOG_BASE } = require('../lib/constants')
const { getNetworkInterfaces, getNetworkRange, scanNetwork, checkPort5985 } = require('../scan')
const { runInventory } = require('../inventory')
const { sendWol }      = require('../wol')

const LLDP_SCRIPT = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'lldp-capture.ps1'), 'utf8')

function runLldpOnHost(hostname, username, password) {
    return new Promise(resolve => {
        const { spawn } = require('child_process')
        const safeUser = username.replace(/'/g, "''")
        const safePass = password.replace(/'/g, "''")
        const safeHost = hostname.replace(/'/g, "''")
        const psCmd = `$pw = ConvertTo-SecureString '${safePass}' -AsPlainText -Force\n$cred = New-Object System.Management.Automation.PSCredential('${safeUser}', $pw)\n$sb = [scriptblock]::Create(@'\n${LLDP_SCRIPT}\n'@)\nInvoke-Command -ComputerName '${safeHost}' -Credential $cred -ScriptBlock $sb -ErrorAction Stop`
        const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psCmd], { windowsHide: true })
        const out = [], err = []
        const timer = setTimeout(() => { ps.kill(); resolve({ ok: false, error: 'TIMEOUT' }) }, 90000)
        ps.stdout.on('data', d => out.push(d))
        ps.stderr.on('data', d => err.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            const iconv  = require('iconv-lite')
            const stdout = iconv.decode(Buffer.concat(out), 'cp850')
            const okLine = stdout.split('\n').find(l => l.trim().startsWith('LLDP_OK|'))
            if (okLine) {
                const p = okLine.trim().split('|')
                resolve({ ok: true, switch: p[1]||'', port: p[2]||'', vlan: p[3]||'', ip_sw: p[4]||'', desc: (p[5]||'').substring(0, 25) })
            } else {
                resolve({ ok: false, error: 'Aucune trame LLDP' })
            }
        })
    })
}

function updateParcLldp(hostname, lldp) {
    try {
        const lines = fs.readFileSync(PARC_FILE, 'utf-8').split('\n').map(l => l.trim()).filter(l => l)
        const idx   = lines.findIndex(l => l.split('|')[0] === hostname)
        if (idx === -1) return
        const parts = lines[idx].split('|')
        while (parts.length < 16) parts.push('')
        parts[16] = lldp.switch || ''
        parts[17] = lldp.port   || ''
        parts[18] = String(lldp.vlan || '')
        parts[19] = lldp.ip_sw  || ''
        parts[20] = (lldp.desc  || '').substring(0, 25)
        lines[idx] = parts.join('|')
        fs.writeFileSync(PARC_FILE, lines.join('\n') + '\n', 'utf-8')
    } catch(e) { console.error('updateParcLldp:', e.message) }
}

const router = express.Router()

router.get('/parc', (req, res) => {
    try {
        if (!fs.existsSync(PARC_FILE)) return res.json([])
        const lines = fs.readFileSync(PARC_FILE, 'utf-8')
            .split('\n').map(l => l.trim()).filter(l => l)
        const hosts = lines.map(line => {
            const p = line.split('|')
            return {
                hostname    : p[0]  || '',
                ip          : p[1]  || '',
                fabricant   : p[2]  || '',
                modele      : p[3]  || '',
                serial      : p[4]  || '',
                os          : p[5]  || '',
                ram         : p[6]  || '',
                disque      : p[7]  || '',
                typeDisque  : p[8]  || '',
                gpu         : p[9]  || '',
                date        : p[10] || '',
                bios        : p[11] || '',
                mac         : p[12] || '',
                typeRam     : p[13] || '',
                cpu         : p[14] || '',
                installDate : p[15] || '',
                lldpSwitch  : p[16] || '',
                lldpPort    : p[17] || '',
                lldpVlan    : p[18] || '',
                lldpIp      : p[19] || '',
                lldpDesc    : p[20] || '',
            }
        })
        res.json(hosts)
    } catch(e) { res.status(500).json({ error: e.message }) }
})

router.get('/scripts', (req, res) => {
    try {
        if (!fs.existsSync(SCRIPTS_DIR)) return res.json([])
        res.json(fs.readdirSync(SCRIPTS_DIR).filter(f => f.endsWith('.ps1')))
    } catch { res.json([]) }
})

router.get('/interfaces', (req, res) => {
    res.json(getNetworkInterfaces())
})

router.get('/ping', (req, res) => {
    const ip = req.query.ip
    if (!ip) return res.json({ alive: false })
    checkPort5985(ip, 1000).then(alive => res.json({ alive })).catch(() => res.json({ alive: false }))
})

router.post('/ping-batch', async (req, res) => {
    const { hosts } = req.body
    if (!hosts || !hosts.length) return res.json({ results: [] })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = data => { if (!res.writableEnded) res.write(`data: ${JSON.stringify(data)}\n\n`) }

    let index = 0
    async function worker() {
        while (index < hosts.length) {
            const i      = index++
            const target = hosts[i].ip || hosts[i].hostname
            const alive  = await checkPort5985(target, 1000).catch(() => false)
            send({ hostname: hosts[i].hostname, alive })
        }
    }
    const workers = Array.from({ length: Math.min(50, hosts.length) }, worker)
    await Promise.all(workers)
    send({ done: true })
    res.end()
})

router.get('/scan', async (req, res) => {
    const { ip, prefix, throttle = 50, doInventory, excludeKnown, doLldp, username, password } = req.query
    if (!ip || !prefix) return res.status(400).json({ error: 'ip et prefix requis' })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    let cancelled = false
    req.on('close', () => { cancelled = true })
    const isCancelled = () => cancelled

    const ips   = getNetworkRange(ip, parseInt(prefix))
    const total = ips.length

    send('phase', { phase: 1, label: `Phase 1 — Scan de ${total} adresses`, total })

    const found = await scanNetwork(ips, parseInt(throttle), (scanned, total, foundCount, newIp) => {
        if (newIp) send('found', { ip: newIp })
        if (scanned % 25 === 0 || scanned === total)
            send('progress', { scanned, total, found: foundCount, pct: Math.round(scanned / total * 100) })
    }, isCancelled)

    if (cancelled) return res.end()

    send('phase1done', { found: found.length, total })

    if (!found.length) {
        send('done', { ok: 0, err: 0, message: 'Aucun hote WinRM detecte.' })
        return res.end()
    }

    if (!doInventory || doInventory === 'false') {
        send('done', { ok: 0, err: 0, message: `${found.length} hote(s) detecte(s). Inventaire non demande.` })
        return res.end()
    }

    let toInventory  = found
    let skippedCount = 0
    if (excludeKnown === 'true') {
        const knownIps = new Set()
        try {
            if (fs.existsSync(PARC_FILE))
                fs.readFileSync(PARC_FILE, 'utf-8').split('\n')
                    .map(l => l.trim()).filter(l => l)
                    .forEach(line => { const p = line.split('|'); if (p[1]) knownIps.add(p[1].trim()) })
        } catch {}
        toInventory  = found.filter(ip => !knownIps.has(ip))
        skippedCount = found.length - toInventory.length
    }

    if (!toInventory.length) {
        send('done', { ok: 0, err: 0, message: `Tous les postes détectés sont déjà inventoriés (${skippedCount} exclus).` })
        return res.end()
    }

    const skipLabel = skippedCount > 0 ? ` — ${skippedCount} déjà inventorié(s) exclus` : ''
    send('phase', { phase: 2, label: `Phase 2 — Inventaire WinRM sur ${toInventory.length} poste(s)${skipLabel}`, total: toInventory.length })

    const { ok, err } = await runInventory({
        targets    : toInventory,
        username, password,
        parcFile   : PARC_FILE,
        logBaseDir : LOG_BASE,
        concurrency: parseInt(throttle),
        isCancelled,
        onProgress : ({ done, total, ok, err, result }) => {
            send('inv_progress', { done, total, ok, err, pct: Math.round(done / total * 100) })
            if (result.ok) send('inv_ok',  { display: result.display })
            else           send('inv_err', { addr: result.addr, error: result.error })
        }
    })

    if (cancelled) return res.end()

    if (doLldp === 'true') {
        await runLldpPhase(found, username, password, send, isCancelled)
    }

    send('done', { ok, err, message: `Termine — OK:${ok}  ERR:${err}` })
    res.end()
})

async function runLldpPhase(foundIps, username, password, send, isCancelled) {
    // Résoudre les hostnames depuis parc.txt pour les IPs trouvées
    const foundSet = new Set(foundIps)
    let parcLines = []
    try { parcLines = fs.readFileSync(PARC_FILE, 'utf-8').split('\n').map(l => l.trim()).filter(l => l) } catch {}
    const targets = parcLines
        .map(l => { const p = l.split('|'); return { hostname: p[0], ip: p[1] } })
        .filter(h => h.hostname && foundSet.has(h.ip))

    if (!targets.length) return

    const total = targets.length
    send('phase', { phase: 3, label: `Phase 3 — LLDP sur ${total} poste(s) (~32s/poste)`, total })

    let done = 0, ok = 0, err = 0, idx = 0
    const concurrency = Math.min(4, total)

    async function worker() {
        while (idx < targets.length) {
            if (isCancelled && isCancelled()) return
            const { hostname } = targets[idx++]
            const result = await runLldpOnHost(hostname, username, password)
            done++
            if (result.ok) {
                ok++
                updateParcLldp(hostname, result)
                send('lldp_ok', { done, total, hostname, switch: result.switch, port: result.port, vlan: result.vlan })
            } else {
                err++
                send('lldp_err', { done, total, hostname, error: result.error })
            }
            send('lldp_progress', { done, total, ok, err, pct: Math.round(done / total * 100) })
        }
    }
    await Promise.all(Array.from({ length: concurrency }, worker))
}

router.post('/wol', async (req, res) => {
    const { hostnames } = req.body
    if (!hostnames || !hostnames.length)
        return res.status(400).json({ error: 'Aucun poste fourni' })

    let parcLines = []
    try {
        parcLines = fs.readFileSync(PARC_FILE, 'utf-8')
            .split('\n').map(l => l.trim()).filter(l => l)
    } catch {}

    const results = []
    for (const hostname of hostnames) {
        const line = parcLines.find(l => l.startsWith(hostname + '|'))
        if (!line) { results.push({ hostname, ok: false, error: 'Poste introuvable dans parc.txt' }); continue }
        const parts = line.split('|')
        const ip    = parts[1]  || ''
        const mac   = parts[12] || ''
        if (!mac) { results.push({ hostname, ok: false, error: 'Adresse MAC absente dans parc.txt' }); continue }
        try {
            const usedIface = await sendWol(mac, ip || null)
            results.push({ hostname, ok: true, mac, iface: usedIface || '0.0.0.0' })
        } catch(e) {
            results.push({ hostname, ok: false, error: e.message })
        }
    }
    res.json(results)
})

module.exports = router
