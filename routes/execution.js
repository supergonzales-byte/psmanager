const express = require('express')
const fs      = require('fs')
const path    = require('path')
const { SCRIPTS_DIR }  = require('../lib/constants')
const { runOneScript } = require('../lib/remote-execution')

const router = express.Router()

const runSessions = new Map()

router.post('/run-init', (req, res) => {
    const { script, targets, username, password, throttle } = req.body
    if (!script || !targets || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })
    const token = require('crypto').randomUUID()
    runSessions.set(token, { script, targets, username, password, throttle: throttle || 10 })
    setTimeout(() => runSessions.delete(token), 30000)
    res.json({ token })
})

router.get('/run', async (req, res) => {
    let script, targets, username, password, throttle
    if (req.query.token) {
        const session = runSessions.get(req.query.token)
        if (!session) return res.status(400).json({ error: 'Token invalide ou expiré' })
        runSessions.delete(req.query.token)
        ;({ script, targets, username, password, throttle } = session)
    } else {
        ;({ script, targets, username, password, throttle = 10 } = req.query)
    }
    if (!script || !targets || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })

    const scriptPath = path.join(SCRIPTS_DIR, script)
    if (!fs.existsSync(scriptPath))
        return res.status(404).json({ error: 'Script introuvable' })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    const hostList = targets.split(',').map(h => h.trim()).filter(Boolean)
    const total    = hostList.length
    let done       = 0, okCount = 0, errCount = 0, index = 0

    send('start', { total, script })

    let authFailed = false

    async function worker() {
        while (index < hostList.length && !authFailed) {
            const hostname = hostList[index++]
            const result = await runOneScript(scriptPath, hostname, hostname, username, password)
            done++
            if (result.ok) okCount++; else errCount++
            if (result.error && result.error.startsWith('ERR_AUTH')) authFailed = true
            send('result', { done, total, ok: okCount, err: errCount,
                hostname, success: result.ok, output: result.output, error: result.error })
        }
    }

    const workers = Array.from({ length: Math.min(parseInt(throttle), hostList.length) }, worker)
    await Promise.all(workers)
    send('done', { ok: okCount, err: errCount, total })
    res.end()
})

module.exports = router
