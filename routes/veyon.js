const express = require('express')
const fs      = require('fs')
const path    = require('path')
const crypto  = require('crypto')
const multer  = require('multer')
const os      = require('os')
const { VEYON_DIR }                        = require('../lib/constants')
const { resolveServerOrigin }              = require('../lib/config')
const { checkPort5985 }                    = require('../scan')
const { ldapGetComputerOU, getLdapConfig } = require('../lib/ldap')

const router = express.Router()
const upload = multer({ dest: os.tmpdir() })
const isTeacher = hn => /^.+-.+-p\d{2}$/i.test(hn)

// Liste les fichiers Veyon disponibles sur le serveur
router.get('/veyon-files-list', (req, res) => {
    try {
        if (!fs.existsSync(VEYON_DIR)) return res.json({ files: [], installer: null })
        const files     = fs.readdirSync(VEYON_DIR)
        const installer = files.find(f => /^veyon-.*-win64-setup\.exe$/i.test(f)) || null
        res.json({ files, installer })
    } catch(e) { res.status(500).json({ error: e.message }) }
})

// Upload de fichiers Veyon vers le serveur
router.post('/veyon-upload', upload.array('files'), (req, res) => {
    try {
        if (!req.files || !req.files.length)
            return res.status(400).json({ ok: false, error: 'Aucun fichier recu' })
        if (!fs.existsSync(VEYON_DIR)) fs.mkdirSync(VEYON_DIR, { recursive: true })
        const saved = []
        for (const file of req.files) {
            const name = Buffer.from(file.originalname, 'latin1').toString('utf8')
            const dest = path.join(VEYON_DIR, name)
            if (fs.existsSync(dest)) { try { fs.chmodSync(dest, 0o666) } catch {} }
            try { fs.renameSync(file.path, dest) }
            catch { fs.copyFileSync(file.path, dest); try { fs.unlinkSync(file.path) } catch {} }
            saved.push(name)
        }
        res.json({ ok: true, files: saved })
    } catch(e) { res.status(500).json({ ok: false, error: e.message }) }
})

const veyonSessions = new Map()

// Initialise une session de deploiement (retourne un token SSE)
router.post('/veyon-deploy-init', (req, res) => {
    const { targets, username, password, serverOrigin } = req.body
    if (!targets || !targets.length || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })
    const token = crypto.randomUUID()
    veyonSessions.set(token, {
        targets, username, password,
        serverOrigin: resolveServerOrigin(serverOrigin),
    })
    setTimeout(() => veyonSessions.delete(token), 30000)
    res.json({ token })
})

// SSE : deploiement Veyon sur les postes cibles
router.get('/veyon-deploy', async (req, res) => {
    const session = veyonSessions.get(req.query.token)
    if (!session) return res.status(400).json({ error: 'Token invalide ou expire' })
    veyonSessions.delete(req.query.token)
    const { targets, username, password, serverOrigin } = session

    if (!fs.existsSync(VEYON_DIR))
        return res.status(400).json({ error: 'Dossier Veyon introuvable sur le serveur' })
    const serverFiles = fs.readdirSync(VEYON_DIR)
    const installer   = serverFiles.find(f => /^veyon-.*-win64-setup\.exe$/i.test(f))
    if (!installer)                                        return res.status(400).json({ error: 'Installeur Veyon (.exe) manquant' })
    if (!serverFiles.includes('key'))                      return res.status(400).json({ error: 'Fichier "key" manquant' })
    if (!serverFiles.includes('publickey'))                return res.status(400).json({ error: 'Fichier "publickey" manquant' })
    if (!serverFiles.includes('veyon_configuration.json')) return res.status(400).json({ error: 'Fichier "veyon_configuration.json" manquant' })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    const total = targets.length
    let done = 0, okCount = 0, errCount = 0, index = 0
    send('start', { total, installer })

    async function runOneVeyon(hostname) {
        const alive = await checkPort5985(hostname, 5000).catch(() => false)
        if (!alive) return { ok: false, hostname, error: 'Poste eteint ou port 5985 ferme' }

        let preLocation   = ''
        let computersJson = '[]'

        if (isTeacher(hostname)) {
            const ldapCfg = getLdapConfig()
            if (!ldapCfg.enabled)
                return { ok: false, hostname, error: 'LDAP non configure' }
            try {
                const ouData  = await ldapGetComputerOU(hostname)
                preLocation   = ouData.location
                computersJson = JSON.stringify(ouData.computers)
            } catch(e) {
                return { ok: false, hostname, error: `Requete AD echouee : ${e.message}` }
            }
        }

        const safePass     = password.replace(/'/g, "''")
        const safeInst     = installer.replace(/'/g, "''")
        const safeOrigin   = serverOrigin.replace(/'/g, "''")
        const safeLoc      = preLocation.replace(/'/g, "''")
        const safeCompJson = computersJson.replace(/'/g, "''")

        const psScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$secPass = ConvertTo-SecureString '${safePass}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try {
    $result = Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock {
        param($origin, $inst, $loc, $compJson)

        # Bypass SSL pour WebClient
        try {
            Add-Type @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class PsmVeyonSSL : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
    public static RemoteCertificateValidationCallback GetCallback() {
        return delegate(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; };
    }
}
"@
        } catch {}
        try { [System.Net.ServicePointManager]::CertificatePolicy = New-Object PsmVeyonSSL } catch {}
        try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [PsmVeyonSSL]::GetCallback() } catch {}
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        \$tmpDir = Join-Path \$env:TEMP "veyon_deploy_\$(Get-Random)"
        New-Item -ItemType Directory -Path \$tmpDir -Force | Out-Null

        try {
            # Telechargement des fichiers depuis le serveur
            \$wc     = New-Object System.Net.WebClient
            \$isProf = \$loc -and \$compJson -and \$compJson -ne '[]'
            \$dlFiles = if (\$isProf) { @('veyon_configuration.json','key','publickey',\$inst) }
                        else          { @('veyon_configuration.json','publickey',\$inst) }

            foreach (\$f in \$dlFiles) {
                \$url  = "\$origin/veyon-files/\$([Uri]::EscapeDataString(\$f))"
                \$dest = Join-Path \$tmpDir \$f
                try { \$wc.DownloadFile(\$url, \$dest) }
                catch { "ERR_DOWNLOAD: Impossible de telecharger '\$f' -- \$(\$_.Exception.Message)"; exit 1 }
            }

            \$instPath = Join-Path \$tmpDir \$inst
            \$cfgPath  = Join-Path \$tmpDir 'veyon_configuration.json'
            \$pubPath  = Join-Path \$tmpDir 'publickey'
            \$privPath = Join-Path \$tmpDir 'key'
            \$cli      = 'C:\\Program Files\\Veyon\\veyon-cli.exe'
            \$svc      = 'C:\\Program Files\\Veyon\\veyon-service.exe'

            # Desinstaller l'ancienne version si presente, puis installer
            \$veyonReg = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue |
                Where-Object { \$_.DisplayName -like 'Veyon*' } | Select-Object -First 1
            if (-not \$veyonReg) {
                \$veyonReg = Get-ItemProperty 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue |
                    Where-Object { \$_.DisplayName -like 'Veyon*' } | Select-Object -First 1
            }
            if (\$veyonReg -and \$veyonReg.UninstallString) {
                \$uninstExe = (\$veyonReg.UninstallString -replace '"','').Trim()
                & \$uninstExe /S
                \$waited = 0
                while ((Test-Path \$svc) -and \$waited -lt 60) { Start-Sleep -Seconds 2; \$waited += 2 }
                if (Test-Path \$svc) { throw "Desinstallation echouee : service encore present apres 60s" }
            }
            Remove-Item 'HKLM:\\SOFTWARE\\Veyon Solutions' -Recurse -ErrorAction SilentlyContinue
            \$installArgs = if (\$isProf) { '/S' } else { '/S /NoMaster /NoStartMenuFolder' }
            \$p = Start-Process -FilePath \$instPath -ArgumentList \$installArgs -Wait -NoNewWindow -PassThru
            if (\$p.ExitCode -ne 0) { throw "Installation echouee (code \$(\$p.ExitCode))" }
            Start-Sleep -Seconds 10
            if (-not (Test-Path \$svc)) { throw "Service Veyon introuvable apres installation" }

            # Import configuration (2>$null supprime les warnings Qt sur stderr)
            & \$cli config import "\$cfgPath" 2>$null
            if (\$LASTEXITCODE -ne 0) { throw "Echec import config (code \$LASTEXITCODE)" }

            # Cle publique
            \$pubDest = 'C:\\ProgramData\\veyon\\keys\\public\\cle\\key'
            New-Item -ItemType Directory -Path (Split-Path \$pubDest) -Force | Out-Null
            Copy-Item \$pubPath \$pubDest -Force

            if (\$isProf) {
                # Cle privee
                \$privDest = 'C:\\ProgramData\\veyon\\keys\\private\\cle\\key'
                New-Item -ItemType Directory -Path (Split-Path \$privDest) -Force | Out-Null
                Copy-Item \$privPath \$privDest -Force

                # Import des postes eleves
                \$comps   = \$compJson | ConvertFrom-Json
                \$csvPath = Join-Path \$tmpDir 'veyon_machines.csv'
                \$comps | Sort-Object | ForEach-Object { "\$loc;\$_;\$_" } | Out-File \$csvPath -Encoding UTF8

                & \$cli networkobjects clear 2>$null
                & \$cli networkobjects import "\$csvPath" format '%location%;%name%;%host%' 2>$null
                if (\$LASTEXITCODE -ne 0) { throw "Echec import postes (code \$LASTEXITCODE)" }
            }

            "EXIT:0"
        } catch {
            "ERR_EXEC: \$(\$_.Exception.Message.Split(\"\`n\")[0])"
        } finally {
            Remove-Item \$tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } -ArgumentList '${safeOrigin}', '${safeInst}', '${safeLoc}', '${safeCompJson}' -ErrorAction Stop
    $result
} catch {
    $m = $_.Exception.Message
    if ($m -like "*Acces refuse*" -or $m -like "*Access is denied*" -or $m -like "*Autorisation*") { "ERR_AUTH: Identifiants invalides ou droits insuffisants" }
    elseif ($m -like "*WinRM*" -or $m -like "*12152*") { "ERR_WINRM: WinRM non configure ou instable" }
    else { "ERR_GENERAL: " + $m.Split("\`n")[0].Trim() }
}
`
        return new Promise(resolve => {
            const { spawn } = require('child_process')
            const ps = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psScript], { windowsHide: true })
            let stdout = '', stderr = '', settled = false
            const timer = setTimeout(() => {
                if (!settled) { settled = true; ps.kill(); resolve({ ok: false, hostname, error: 'TIMEOUT (>30 min)' }) }
            }, 1800000)
            ps.stdout.on('data', d => { stdout += d.toString() })
            ps.stderr.on('data', d => { stderr += d.toString() })
            ps.on('close', () => {
                clearTimeout(timer)
                if (settled) return
                settled = true
                const lines    = stdout.trim().split('\n').map(l => l.trim()).filter(l => l)
                const errLine  = lines.find(l => l.startsWith('ERR_'))
                const lastLine = lines[lines.length - 1] || ''
                if (errLine) {
                    resolve({ ok: false, hostname, error: errLine.substring(0, 200) })
                } else if (lastLine === 'EXIT:0') {
                    resolve({ ok: true, hostname, output: 'Veyon deploye avec succes' })
                } else {
                    const fallback = (stderr.trim() || stdout.trim()).split('\n').find(l => l.trim() && !l.startsWith('    +'))
                        || (stderr.trim() || stdout.trim()).split('\n')[0] || 'Erreur inconnue'
                    resolve({ ok: false, hostname, error: fallback.substring(0, 200) })
                }
            })
        })
    }

    let authFailed = false

    async function worker() {
        while (index < targets.length && !authFailed) {
            const hostname = targets[index++]
            const result   = await runOneVeyon(hostname)
            done++
            if (result.ok) okCount++; else errCount++
            // Arrêt immédiat si credentials invalides — évite de verrouiller le compte AD
            if (result.error && result.error.startsWith('ERR_AUTH')) authFailed = true
            send('result', { done, total, ok: okCount, err: errCount,
                hostname, success: result.ok, output: result.output || '', error: result.error || '' })
        }
    }

    const workers = Array.from({ length: Math.min(5, targets.length) }, worker)
    await Promise.all(workers)
    send('done', { ok: okCount, err: errCount, total })
    res.end()
})

module.exports = router
