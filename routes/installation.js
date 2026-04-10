const express = require('express')
const fs      = require('fs')
const path    = require('path')
const crypto  = require('crypto')
const { INSTALLERS_DIR }         = require('../lib/constants')
const { resolveServerOrigin }    = require('../lib/config')
const { checkPort5985 }          = require('../scan')

const router          = express.Router()
const installSessions = new Map()

router.post('/install-init', (req, res) => {
    const { installer, args, targets, username, password, throttle, serverOrigin } = req.body
    if (!installer || !targets || !targets.length || !username || !password)
        return res.status(400).json({ error: 'Paramètres manquants' })
    const token = crypto.randomUUID()
    installSessions.set(token, {
        installer, args: args || '', targets, username, password,
        throttle: parseInt(throttle) || 10,
        serverOrigin: resolveServerOrigin(serverOrigin)
    })
    setTimeout(() => installSessions.delete(token), 30000)
    res.json({ token })
})

router.get('/install', async (req, res) => {
    const session = installSessions.get(req.query.token)
    if (!session) return res.status(400).json({ error: 'Token invalide ou expiré' })
    installSessions.delete(req.query.token)
    const { installer, args, targets, username, password, throttle, serverOrigin } = session

    const installerPath = path.join(INSTALLERS_DIR, installer)
    if (!fs.existsSync(installerPath))
        return res.status(404).json({ error: `Installeur "${installer}" introuvable sur le serveur` })

    const ext         = path.extname(installer).toLowerCase()
    const downloadUrl = `${serverOrigin}/installers/${encodeURIComponent(installer)}`

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    const total = targets.length
    let done = 0, okCount = 0, errCount = 0, index = 0

    send('start', { total, installer })

    async function runOneInstall(hostname) {
        const alive = await checkPort5985(hostname, 5000).catch(() => false)
        if (!alive) return { ok: false, hostname, error: 'Poste éteint ou port 5985 fermé' }

        const safePass = password.replace(/'/g, "''")
        const safeUrl  = downloadUrl.replace(/'/g, "''")
        const safeName = installer.replace(/'/g, "''")
        const safeArgs = (args || '').replace(/'/g, "''")

        const psScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$secPass = ConvertTo-SecureString '${safePass}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try {
    $result = Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock {
        param($url, $name, $ext, $installArgs)
        try {
            Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class PsmTrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object PsmTrustAll
        } catch {}
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $dest = [System.IO.Path]::Combine(\$env:TEMP, "psm_install_\$name")
        try {
            Invoke-WebRequest -Uri \$url -OutFile \$dest -UseBasicParsing -TimeoutSec 1800
        } catch {
            throw "DOWNLOAD_FAIL: \$(\$_.Exception.Message)"
        }
        if (\$ext -eq '.msi') {
            \$fullArgs = ("/i \`"\$dest\`" /qn \$installArgs").Trim()
            \$proc = Start-Process msiexec.exe -ArgumentList \$fullArgs -Wait -PassThru
        } else {
            if (\$installArgs) {
                \$proc = Start-Process \$dest -ArgumentList \$installArgs -Wait -PassThru
            } else {
                \$proc = Start-Process \$dest -Wait -PassThru
            }
        }
        Remove-Item \$dest -Force -ErrorAction SilentlyContinue
        \$proc.ExitCode
    } -ArgumentList '${safeUrl}', '${safeName}', '${ext}', '${safeArgs}' -ErrorAction Stop
    "EXIT:\$result"
} catch {
    \$m = \$_.Exception.Message
    if (\$m -like "*Accès refusé*" -or \$m -like "*Access is denied*" -or \$m -like "*Autorisation refusée*") {
        "ERR_AUTH: Identifiants invalides ou droits insuffisants"
    } elseif (\$m -like "*DOWNLOAD_FAIL*") {
        "ERR_DL: " + (\$m -replace "^.*DOWNLOAD_FAIL: ", "")
    } elseif (\$m -like "*WinRM*" -or \$m -like "*12152*") {
        "ERR_WINRM: WinRM non configuré ou instable sur la cible"
    } else {
        "ERR_GENERAL: " + \$m.Split("\`n")[0].Trim()
    }
}
`
        return new Promise(resolve => {
            const { spawn } = require('child_process')
            const ps = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psScript], { windowsHide: true })
            let stdout = '', stderr = '', settled = false
            const timer = setTimeout(() => {
                if (!settled) { settled = true; ps.kill(); resolve({ ok: false, hostname, error: 'TIMEOUT — installation trop longue (>30 min)' }) }
            }, 1800000)
            ps.stdout.on('data', d => { stdout += d.toString() })
            ps.stderr.on('data', d => { stderr += d.toString() })
            ps.on('close', () => {
                clearTimeout(timer)
                if (settled) return
                settled = true
                const out = stdout.trim()
                if (out.startsWith('ERR_')) {
                    resolve({ ok: false, hostname, error: out })
                } else if (out.startsWith('EXIT:')) {
                    const code    = parseInt(out.replace('EXIT:', '').trim())
                    const success = code === 0 || code === 3010 || code === 1641
                    const msg     = code === 3010 ? 'OK — redémarrage requis'
                                  : code === 1641 ? 'OK — redémarrage en cours'
                                  : success      ? 'OK'
                                  : `Échec — code sortie ${code}`
                    resolve({ ok: success, hostname, output: msg, error: success ? '' : msg })
                } else {
                    const errLine = stderr.trim().split('\n').find(l => l.trim() && !l.startsWith('    +'))
                        || stderr.trim().split('\n')[0] || 'Erreur inconnue'
                    resolve({ ok: false, hostname, error: errLine })
                }
            })
        })
    }

    let authFailed = false

    async function worker() {
        while (index < targets.length && !authFailed) {
            const hostname = targets[index++]
            const result   = await runOneInstall(hostname)
            done++
            if (result.ok) okCount++; else errCount++
            if (result.error && result.error.startsWith('ERR_AUTH')) authFailed = true
            send('result', { done, total, ok: okCount, err: errCount,
                hostname, success: result.ok, output: result.output || '', error: result.error || '' })
        }
    }

    const workers = Array.from({ length: Math.min(throttle, targets.length) }, worker)
    await Promise.all(workers)
    send('done', { ok: okCount, err: errCount, total })
    res.end()
})

module.exports = router
