const express = require('express')
const { checkPort5985 } = require('../scan')

const router         = express.Router()
const actionSessions = new Map()

router.post('/action', async (req, res) => {
    const { action, hostname, username, password, message } = req.body
    if (!action || !hostname || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })

    const target = hostname
    const { spawn } = require('child_process')

    const alive = await checkPort5985(target, 5000).catch(() => false)
    if (!alive) return res.json({ ok: false, error: 'Poste éteint ou port 5985 fermé' })

    const psCommands = {
        off     : `Invoke-Command -ComputerName '${target}' -Credential $cred -ScriptBlock { Stop-Computer -Force }`,
        rst     : `Invoke-Command -ComputerName '${target}' -Credential $cred -ScriptBlock { Restart-Computer -Force }`,
        msg     : `Invoke-Command -ComputerName '${target}' -Credential $cred -ScriptBlock { msg * '${(message||'').replace(/'/g,"''")}' }`,
        session : `$r = Invoke-Command -ComputerName '${target}' -Credential $cred -ScriptBlock { (query user 2>&1) | Out-String } -ErrorAction Stop; Write-Output "SESSION_OK|$r"`,
    }

    const cmd = psCommands[action]
    if (!cmd) return res.status(400).json({ error: 'Action inconnue' })

    const psScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try { ${cmd}; Write-Output "OK" } catch { Write-Output "ERROR|$($_.Exception.Message)" }
`
    const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psScript], { windowsHide: true })
    let stdout = '', stderr = '', responded = false
    const timer = setTimeout(() => {
        if (!responded) { responded = true; ps.kill(); res.json({ ok: false, error: 'TIMEOUT' }) }
    }, 30000)
    ps.stdout.on('data', d => stdout += d.toString())
    ps.stderr.on('data', d => stderr += d.toString())
    ps.on('close', () => {
        clearTimeout(timer)
        if (responded) return
        responded = true
        const out = stdout.trim(), err = stderr.trim()
        if (out.startsWith('ERROR|'))      res.json({ ok: false, error: out.replace('ERROR|', '') })
        else if (out.startsWith('SESSION_OK|')) res.json({ ok: true, output: out.replace('SESSION_OK|', '') })
        else if (out === 'OK')             res.json({ ok: true })
        else if (err)                      res.json({ ok: false, error: err.split('\n').find(l => l.trim() && !l.startsWith('    +')) || err.split('\n')[0] })
        else                               res.json({ ok: true })
    })
})

router.post('/action-bulk-init', (req, res) => {
    const { action, targets, username, password, throttle } = req.body
    if (!action || !targets || !targets.length || !username || !password)
        return res.status(400).json({ error: 'Paramètres manquants' })
    if (!['off', 'rst'].includes(action))
        return res.status(400).json({ error: 'Action non supportée' })
    const token = require('crypto').randomUUID()
    actionSessions.set(token, { action, targets, username, password, throttle: parseInt(throttle) || 10 })
    setTimeout(() => actionSessions.delete(token), 30000)
    res.json({ token })
})

router.get('/action-bulk', async (req, res) => {
    const session = actionSessions.get(req.query.token)
    if (!session) return res.status(400).json({ error: 'Token invalide ou expiré' })
    actionSessions.delete(req.query.token)
    const { action, targets, username, password, throttle } = session

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    const { spawn } = require('child_process')
    const hostList  = targets.map(h => (typeof h === 'string' ? h : h.hostname))
    const total     = hostList.length
    let done = 0, okCount = 0, errCount = 0, index = 0

    const psCmd = action === 'off'
        ? t => `Invoke-Command -ComputerName '${t}' -Credential $cred -ScriptBlock { Stop-Computer -Force }`
        : t => `Invoke-Command -ComputerName '${t}' -Credential $cred -ScriptBlock { Restart-Computer -Force }`

    send('start', { total, action })

    async function runOne(hostname) {
        const alive = await checkPort5985(hostname, 5000).catch(() => false)
        if (!alive) return { hostname, ok: false, error: 'Poste éteint ou port 5985 fermé' }
        const psScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try { ${psCmd(hostname)}; Write-Output "OK" } catch { Write-Output "ERROR|$($_.Exception.Message)" }
`
        return new Promise(resolve => {
            const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psScript], { windowsHide: true })
            let stdout = '', stderr = '', settled = false
            const timer = setTimeout(() => {
                if (!settled) { settled = true; ps.kill(); resolve({ hostname, ok: false, error: 'TIMEOUT' }) }
            }, 30000)
            ps.stdout.on('data', d => stdout += d.toString())
            ps.stderr.on('data', d => stderr += d.toString())
            ps.on('close', () => {
                clearTimeout(timer)
                if (settled) return
                settled = true
                const out = stdout.trim(), err = stderr.trim()
                if (out.startsWith('ERROR|')) resolve({ hostname, ok: false, error: out.replace('ERROR|', '') })
                else if (out === 'OK')        resolve({ hostname, ok: true })
                else if (err)                 resolve({ hostname, ok: false, error: err.split('\n').find(l => l.trim() && !l.startsWith('    +')) || err.split('\n')[0] })
                else                          resolve({ hostname, ok: true })
            })
        })
    }

    async function worker() {
        while (index < hostList.length) {
            const hostname = hostList[index++]
            const result   = await runOne(hostname)
            done++
            if (result.ok) okCount++; else errCount++
            send('result', { done, total, ok: okCount, err: errCount, hostname, success: result.ok, error: result.error })
        }
    }

    const workers = Array.from({ length: Math.min(throttle, hostList.length) }, worker)
    await Promise.all(workers)
    send('done', { ok: okCount, err: errCount, total })
    res.end()
})

module.exports = router
