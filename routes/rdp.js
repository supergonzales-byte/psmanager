const express = require('express')
const fs      = require('fs')
const path    = require('path')
const os      = require('os')

const router = express.Router()

function buildRdpLines(target, username, full = true) {
    return [
        'screen mode id:i:2',
        full ? 'use multimon:i:0' : null,
        'desktopwidth:i:1920',
        'desktopheight:i:1080',
        'session bpp:i:32',
        `full address:s:${target}`,
        username ? `username:s:${username}` : '',
        'authentication level:i:2',
        'prompt for credentials:i:0',
        'negotiate security layer:i:1',
        'compression:i:1',
        'bitmapcachepersistenable:i:1',
        full ? 'disable wallpaper:i:0' : null,
        full ? 'disable full window drag:i:1' : null,
        full ? 'disable menu anims:i:1' : null,
    ].filter(l => l !== null && l !== '').join('\r\n')
}

router.get('/rdp', (req, res) => {
    const { ip, hostname, username, password } = req.query
    if (!ip && !hostname) return res.status(400).json({ error: 'IP ou hostname requis' })

    const target   = hostname || ip
    const clientIp = req.socket.remoteAddress || ''
    const isLocal  = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1'
    const rdpLines = buildRdpLines(target, username, true)

    const sendFile = () => {
        res.setHeader('Content-Type', 'application/x-rdp')
        res.setHeader('Content-Disposition', `attachment; filename="${target}.rdp"`)
        res.send(rdpLines)
    }

    if (isLocal) {
        const { spawn, execSync, execFileSync } = require('child_process')
        const tmpRdp = path.join(os.tmpdir(), `psm_${Date.now()}.rdp`)
        try {
            fs.writeFileSync(tmpRdp, rdpLines, 'utf-8')
            if (username && password) {
                try { execSync(`cmdkey /generic:${target} /user:${username} /pass:${password}`, { windowsHide: true }) } catch {}
            }

            const sessionName   = process.env.SESSIONNAME || ''
            const isInteractive = sessionName !== '' && sessionName !== 'Services'

            if (!isInteractive) {
                const taskName    = `PSM_RDP_${Date.now()}`
                const currentUser = os.userInfo().username
                try {
                    execFileSync('schtasks', ['/create', '/tn', taskName, '/tr', `mstsc.exe "${tmpRdp}"`, '/sc', 'once', '/st', '00:00', '/ru', currentUser, '/it', '/f'], { windowsHide: true })
                    execFileSync('schtasks', ['/run', '/tn', taskName], { windowsHide: true })
                    setTimeout(() => {
                        try { execFileSync('schtasks', ['/delete', '/tn', taskName, '/f'], { windowsHide: true }) } catch {}
                        try { fs.unlinkSync(tmpRdp) } catch {}
                        if (username) try { execSync(`cmdkey /delete:${target}`, { windowsHide: true }) } catch {}
                    }, 15000)
                    return res.json({ ok: true, mode: 'mstsc' })
                } catch {
                    try { fs.unlinkSync(tmpRdp) } catch {}
                    return sendFile()
                }
            }

            const proc = spawn('mstsc.exe', [tmpRdp], { detached: true, windowsHide: false })
            proc.on('error', () => { if (!res.headersSent) sendFile() })
            setTimeout(() => {
                try { fs.unlinkSync(tmpRdp) } catch {}
                if (username) try { execSync(`cmdkey /delete:${target}`, { windowsHide: true }) } catch {}
            }, 10000)
            if (!res.headersSent) res.json({ ok: true, mode: 'mstsc' })
        } catch { if (!res.headersSent) sendFile() }
    } else {
        sendFile()
    }
})

router.get('/rdp-launch', (req, res) => {
    const { ip, hostname, username, password } = req.query
    if (!ip && !hostname) return res.status(400).json({ error: 'IP ou hostname requis' })

    const target   = hostname
    const rdpLines = buildRdpLines(target, username, false)
    const tmpRdp   = path.join(os.tmpdir(), `psm_${Date.now()}.rdp`)
    fs.writeFileSync(tmpRdp, rdpLines, 'utf-8')

    if (username && password) {
        const { execSync } = require('child_process')
        try { execSync(`cmdkey /generic:${target} /user:${username} /pass:${password}`, { windowsHide: true }) } catch {}
    }

    const { spawn } = require('child_process')
    spawn('mstsc.exe', [tmpRdp], { detached: true, windowsHide: false })

    setTimeout(() => {
        try { fs.unlinkSync(tmpRdp) } catch {}
        if (username) {
            try { require('child_process').execSync(`cmdkey /delete:${target}`, { windowsHide: true }) } catch {}
        }
    }, 10000)

    res.json({ ok: true })
})

router.post('/ps-external', (req, res) => {
    const { hostname, username, password } = req.body
    if (!hostname || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })

    const { spawn } = require('child_process')
    const psCmd = `
$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
Enter-PSSession -ComputerName '${hostname}' -Credential $cred
`
    const tmpFile = path.join(os.tmpdir(), `pssession_${Date.now()}.ps1`)
    fs.writeFileSync(tmpFile, psCmd, 'utf-8')
    spawn('powershell', ['-NoExit', '-ExecutionPolicy', 'Bypass', '-File', tmpFile],
        { detached: true, windowsHide: false })
    res.json({ ok: true })
})

router.get('/ps-terminal', async (req, res) => {
    const { hostname, username, password, command } = req.query
    if (!hostname || !username || !password || !command)
        return res.status(400).json({ error: 'Parametres manquants' })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    const { spawn } = require('child_process')
    const psScript  = `
$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try {
    $result = Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock {
        ${command}
    } -ErrorAction Stop
    $result | Out-String
} catch { Write-Error $_.Exception.Message }
`
    const ps    = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psScript], { windowsHide: true })
    const timer = setTimeout(() => { ps.kill(); send('error', 'TIMEOUT'); res.end() }, 60000)

    ps.stdout.on('data', d => send('stdout', d.toString()))
    ps.stderr.on('data', d => send('stderr', d.toString()))
    ps.on('close', code => { clearTimeout(timer); send('done', code === 0 ? 'OK' : `Exit ${code}`); res.end() })
    req.on('close', () => ps.kill())
})

module.exports = router
