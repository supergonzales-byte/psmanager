const express      = require('express')
const fs           = require('fs')
const path         = require('path')
const crypto       = require('crypto')
const nodeSchedule = require('node-schedule')
const { PARC_FILE, SCRIPTS_DIR, KEY_FILE, SCHEDULES_FILE } = require('../lib/constants')
const { sendWol }      = require('../wol')
const { runOneScript, runOneScriptBlock } = require('../lib/remote-execution')

const router = express.Router()

const DAY_LABELS = ['dim', 'lun', 'mar', 'mer', 'jeu', 'ven', 'sam']

// ── Chiffrement des mots de passe dans schedules.json ──
let _schedKey
function _getSchedKey() {
    if (_schedKey) return _schedKey
    if (fs.existsSync(KEY_FILE)) {
        _schedKey = Buffer.from(fs.readFileSync(KEY_FILE, 'utf-8').trim(), 'hex')
    } else {
        _schedKey = crypto.randomBytes(32)
        fs.writeFileSync(KEY_FILE, _schedKey.toString('hex'))
        console.log('✔ Clé de chiffrement planification créée :', KEY_FILE)
    }
    return _schedKey
}

function encryptSchedPassword(plain) {
    if (!plain) return null
    const iv     = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv('aes-256-cbc', _getSchedKey(), iv)
    const enc    = Buffer.concat([cipher.update(plain, 'utf-8'), cipher.final()])
    return 'enc:' + iv.toString('hex') + ':' + enc.toString('hex')
}

function decryptSchedPassword(stored) {
    if (!stored) return null
    if (!stored.startsWith('enc:')) return stored
    try {
        const parts    = stored.split(':')
        const iv       = Buffer.from(parts[1], 'hex')
        const enc      = Buffer.from(parts[2], 'hex')
        const decipher = crypto.createDecipheriv('aes-256-cbc', _getSchedKey(), iv)
        return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf-8')
    } catch { return null }
}

// ── Helpers ──
function describeRecurrence(recurrence, daysOfWeek, time) {
    if (recurrence === 'daily') return `Tous les jours à ${time}`
    const labels = [...new Set((daysOfWeek || []).map(Number))]
        .sort((a, b) => (a === 0 ? 7 : a) - (b === 0 ? 7 : b))
        .map(d => DAY_LABELS[d])
    return `${labels.join(', ')} à ${time}`
}

// ── Gestion des tâches ──
const scheduledJobs = new Map()  // id → { task, job }

function persistSchedules() {
    const list = [...scheduledJobs.values()].map(e => e.task)
    fs.writeFileSync(SCHEDULES_FILE, JSON.stringify(list, null, 2))
}

async function executeScheduledTask(task) {
    const { type, targets, username, script } = task
    const password = decryptSchedPassword(task.password)

    if (type === 'wol') {
        let parcLines = []
        try { parcLines = fs.readFileSync(PARC_FILE, 'utf-8').split('\n').map(l => l.trim()).filter(Boolean) } catch {}
        for (const hostname of targets) {
            const line = parcLines.find(l => l.startsWith(hostname + '|'))
            if (!line) continue
            const parts = line.split('|')
            const mac   = parts[12] || ''
            const ip    = parts[1]  || ''
            if (mac) await sendWol(mac, ip || null).catch(() => {})
        }
        return
    }

    const { spawn } = require('child_process')
    let idx = 0
    const throttle = task.throttle || 10

    async function worker() {
        while (idx < targets.length) {
            const hostname = targets[idx++]
            if (type === 'script') {
                if (task.scriptBlock) {
                    await runOneScriptBlock(task.scriptBlock, hostname, hostname, username, password).catch(() => {})
                } else {
                    const scriptPath = path.join(SCRIPTS_DIR, script)
                    if (fs.existsSync(scriptPath))
                        await runOneScript(scriptPath, hostname, hostname, username, password).catch(() => {})
                }
            } else {
                const psCmd = type === 'reboot'
                    ? `Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock { Restart-Computer -Force }`
                    : `Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock { Stop-Computer -Force }`
                const psScript = `
$secPass = ConvertTo-SecureString '${password.replace(/'/g, "''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try { ${psCmd} } catch {}
`
                await new Promise(resolve => {
                    const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psScript], { windowsHide: true })
                    ps.on('close', resolve)
                    setTimeout(() => { ps.kill(); resolve() }, 30000)
                })
            }
        }
    }

    const workers = Array.from({ length: Math.min(throttle, targets.length) }, worker)
    await Promise.all(workers)
}

// ── Planification ponctuelle ──
function scheduleTask(task) {
    const date = new Date(task.at)
    const job  = nodeSchedule.scheduleJob(task.id, date, async () => {
        await executeScheduledTask(task).catch(e => console.error('Erreur tâche planifiée:', e.message))
        scheduledJobs.delete(task.id)
        persistSchedules()
    })
    if (job) scheduledJobs.set(task.id, { task, job })
}

// ── Planification récurrente ──
function scheduleRecurringTask(task) {
    const [hours, minutes] = task.time.split(':').map(Number)
    const rule = new nodeSchedule.RecurrenceRule()
    rule.hour   = hours
    rule.minute = minutes
    rule.second = 0
    if (task.recurrence === 'weekly') {
        rule.dayOfWeek = task.daysOfWeek
    }
    const job = nodeSchedule.scheduleJob(task.id, rule, async () => {
        task.runCount  = (task.runCount || 0) + 1
        task.lastRunAt = new Date().toISOString()
        task.status    = 'running'
        persistSchedules()
        try {
            await executeScheduledTask(task)
            task.status = 'scheduled'
        } catch (e) {
            task.status    = 'error'
            task.lastError = e.message
            console.error('Erreur tâche récurrente:', e.message)
        }
        persistSchedules()
    })
    if (job) scheduledJobs.set(task.id, { task, job })
}

function loadSchedules() {
    if (!fs.existsSync(SCHEDULES_FILE)) return
    try {
        const list = JSON.parse(fs.readFileSync(SCHEDULES_FILE, 'utf-8'))
        let restored = 0
        for (const task of list) {
            if (task.recurrence && task.recurrence !== 'once') {
                scheduleRecurringTask(task)
                restored++
            } else {
                if (new Date(task.at) > new Date()) { scheduleTask(task); restored++ }
            }
        }
        if (restored) console.log(`✔ ${restored} tâche(s) planifiée(s) restaurée(s)`)
    } catch(e) { console.warn('Erreur chargement schedules.json:', e.message) }
}

loadSchedules()

// ── Routes ──
router.post('/schedule', (req, res) => {
    const { type, script, targets, at, username, password, label, throttle, recurrence, time, daysOfWeek, description } = req.body

    if (!type || !targets || !targets.length)
        return res.status(400).json({ error: 'Paramètres manquants' })
    if (['script', 'reboot', 'shutdown'].includes(type) && (!username || !password))
        return res.status(400).json({ error: 'Identifiants requis' })
    if (type === 'script' && !script && !req.body.scriptBlock)
        return res.status(400).json({ error: 'Script ou bloc de commandes requis' })

    const isRecurring = recurrence && recurrence !== 'once'

    if (isRecurring) {
        if (!['daily', 'weekly'].includes(recurrence))
            return res.status(400).json({ error: 'Récurrence invalide' })
        if (!/^\d{2}:\d{2}$/.test(time || ''))
            return res.status(400).json({ error: 'Heure invalide' })
        const days = recurrence === 'weekly'
            ? (Array.isArray(daysOfWeek) ? daysOfWeek.map(Number).filter(n => n >= 0 && n <= 6) : [])
            : []
        if (recurrence === 'weekly' && !days.length)
            return res.status(400).json({ error: 'Choisissez au moins un jour' })

        const id   = `sched_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`
        const task = {
            id, type, script: script || null, scriptBlock: req.body.scriptBlock || null, targets,
            username: username || null,
            password: encryptSchedPassword(password || null),
            recurrence, time,
            daysOfWeek: days,
            description: String(description || label || '').trim(),
            label: String(description || label || '').trim(),
            throttle: parseInt(throttle) || 10,
            runCount: 0, lastRunAt: null, status: 'scheduled',
            createdAt: new Date().toISOString()
        }
        scheduleRecurringTask(task)
        persistSchedules()
        return res.json({ ok: true, id })
    }

    // Ponctuelle
    if (!at) return res.status(400).json({ error: 'Paramètres manquants' })
    const date = new Date(at)
    if (isNaN(date.getTime()) || date <= new Date())
        return res.status(400).json({ error: 'Date invalide ou passée' })

    const id   = `sched_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`
    const task = {
        id, type, script: script || null, scriptBlock: req.body.scriptBlock || null, targets, at,
        username: username || null,
        password: encryptSchedPassword(password || null),
        recurrence: 'once',
        label: label || '',
        throttle: parseInt(throttle) || 10,
        createdAt: new Date().toISOString()
    }
    scheduleTask(task)
    persistSchedules()
    res.json({ ok: true, id })
})

router.get('/schedules', (req, res) => {
    const list = [...scheduledJobs.values()].map(({ task, job }) => {
        const base = {
            id: task.id, type: task.type, script: task.script,
            targets: task.targets, label: task.label || task.description || '',
            createdAt: task.createdAt, recurrence: task.recurrence || 'once',
        }
        if (task.recurrence && task.recurrence !== 'once') {
            const nextInv = job?.nextInvocation?.()
            return {
                ...base,
                time: task.time,
                daysOfWeek: task.daysOfWeek || [],
                description: task.description || '',
                runCount: task.runCount || 0,
                lastRunAt: task.lastRunAt || null,
                status: task.status || 'scheduled',
                nextRunAt: nextInv ? new Date(nextInv).toISOString() : null,
                summary: describeRecurrence(task.recurrence, task.daysOfWeek, task.time),
            }
        }
        return { ...base, at: task.at }
    })
    list.sort((a, b) => {
        const ta = new Date(a.nextRunAt || a.at || 0).getTime()
        const tb = new Date(b.nextRunAt || b.at || 0).getTime()
        return ta - tb
    })
    res.json(list)
})

router.delete('/schedule/:id', (req, res) => {
    const entry = scheduledJobs.get(req.params.id)
    if (!entry) return res.status(404).json({ error: 'Tâche introuvable' })
    entry.job.cancel()
    scheduledJobs.delete(req.params.id)
    persistSchedules()
    res.json({ ok: true })
})

module.exports = router
