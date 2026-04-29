const express = require('express')
const fs      = require('fs')
const path    = require('path')
const { SCRIPTS_DIR }  = require('../lib/constants')
const { runOneScript, runOneScriptBlock } = require('../lib/remote-execution')

const router = express.Router()

const runSessions   = new Map()
const runCancelled  = new Map()

function normalizeTarget(target) {
    return typeof target === 'string'
        ? { hostname: target, ip: '' }
        : { hostname: target.hostname, ip: target.ip || '' }
}

router.post('/run-cancel', (req, res) => {
    if (req.query.token) runCancelled.set(req.query.token, true)
    res.json({ ok: true })
})

router.post('/run-init', (req, res) => {
    const { script, scriptBlock, targets, username, password, throttle } = req.body
    if (!targets || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })
    if (!script && !scriptBlock)
        return res.status(400).json({ error: 'Script ou bloc de commandes requis' })
    const token = require('crypto').randomUUID()
    runSessions.set(token, { script, scriptBlock, targets, username, password, throttle: throttle || 10 })
    setTimeout(() => runSessions.delete(token), 30000)
    res.json({ token })
})

router.get('/run', async (req, res) => {
    const token = req.query.token
    let script, scriptBlock, targets, username, password, throttle
    if (token) {
        const session = runSessions.get(token)
        if (!session) return res.status(400).json({ error: 'Token invalide ou expiré' })
        runSessions.delete(token)
        ;({ script, scriptBlock, targets, username, password, throttle } = session)
    } else {
        ;({ script, scriptBlock, targets, username, password, throttle = 10 } = req.query)
    }
    if (!targets || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })
    if (!script && !scriptBlock)
        return res.status(400).json({ error: 'Script ou bloc de commandes requis' })

    let scriptPath
    if (script) {
        scriptPath = path.join(SCRIPTS_DIR, script)
        if (!fs.existsSync(scriptPath))
            return res.status(404).json({ error: 'Script introuvable' })
    }

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    const hostList = Array.isArray(targets)
        ? targets.map(normalizeTarget).filter(h => h.hostname)
        : String(targets).split(',').map(h => h.trim()).filter(Boolean).map(normalizeTarget)
    const total    = hostList.length
    let done       = 0, okCount = 0, errCount = 0, index = 0

    send('start', { total, script: script || '(commande inline)' })

    if (token) runCancelled.delete(token)
    const isCancelled = () => token ? runCancelled.get(token) === true : false

    let authFailed = false

    async function worker() {
        while (index < hostList.length && !authFailed && !isCancelled()) {
            const targetInfo = hostList[index++]
            const hostname = targetInfo.hostname
            const probeTarget = targetInfo.ip || hostname
            const result = scriptBlock
                ? await runOneScriptBlock(scriptBlock, hostname, hostname, username, password, probeTarget)
                : await runOneScript(scriptPath, hostname, hostname, username, password, probeTarget)
            done++
            if (result.ok) okCount++; else errCount++
            if (result.error && result.error.startsWith('ERR_AUTH')) authFailed = true
            send('result', { done, total, ok: okCount, err: errCount,
                hostname, success: result.ok, output: result.output, error: result.error })
        }
    }

    const workers = Array.from({ length: Math.min(parseInt(throttle), hostList.length) }, worker)
    await Promise.all(workers)
    if (token) runCancelled.delete(token)
    send('done', { ok: okCount, err: errCount, total })
    res.end()
})

module.exports = router
