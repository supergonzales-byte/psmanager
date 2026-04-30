const express = require('express')
const fs      = require('fs')
const path    = require('path')
const crypto  = require('crypto')
const multer  = require('multer')
const os      = require('os')
const https   = require('https')
const { VEYON_DIR }                        = require('../lib/constants')
const { resolveServerOrigin }              = require('../lib/config')
const { checkPort5985 }                    = require('../scan')
const { ldapGetComputerOU, getLdapConfig } = require('../lib/ldap')

const router = express.Router()
const upload = multer({ dest: os.tmpdir() })
const isTeacher = hn => /^.+-.+-p\d{2}$/i.test(hn)
const normalizeTarget = target => typeof target === 'string'
    ? { hostname: target, ip: '' }
    : { hostname: target.hostname, ip: target.ip || '' }

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

const veyonSessions  = new Map()
const veyonCancelled = new Map()
const downloadTokens = new Set()

router.post('/veyon-cancel', (req, res) => {
    if (req.query.token) veyonCancelled.set(req.query.token, true)
    res.json({ ok: true })
})

// Initialise une session de deploiement (retourne un token SSE)
router.post('/veyon-deploy-init', (req, res) => {
    const { targets, username, password, serverOrigin } = req.body
    if (!targets || !targets.length || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })
    const token   = crypto.randomUUID()
    const dlToken = crypto.randomUUID()
    downloadTokens.add(dlToken)
    setTimeout(() => downloadTokens.delete(dlToken), 7200000) // expire apres 2h
    veyonSessions.set(token, {
        targets, username, password,
        serverOrigin: resolveServerOrigin(serverOrigin),
        dlToken,
    })
    setTimeout(() => veyonSessions.delete(token), 30000)
    res.json({ token })
})

// SSE : deploiement Veyon sur les postes cibles
router.get('/veyon-deploy', async (req, res) => {
    const token   = req.query.token
    const session = veyonSessions.get(token)
    if (!session) return res.status(400).json({ error: 'Token invalide ou expire' })
    veyonSessions.delete(token)
    const { targets, username, password, serverOrigin, dlToken } = session
    veyonCancelled.delete(token)
    const isCancelled = () => veyonCancelled.get(token) === true

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

    async function runOneVeyon(targetInfo) {
        const hostname = targetInfo.hostname
        const probeTarget = targetInfo.ip || hostname
        const alive = await checkPort5985(probeTarget, 5000).catch(() => false)
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
        const safeDlToken  = dlToken.replace(/'/g, "''")

        const psScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$secPass = ConvertTo-SecureString '${safePass}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try {
    $result = Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock {
        param($origin, $inst, $loc, $compJson, $dlToken)

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
                \$url  = "\$origin/veyon-files/\$([Uri]::EscapeDataString(\$f))?token=\$dlToken"
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

            # Redemarrage du service Veyon pour acces master immediat
            try {
                \$vSvc = Get-Service -Name 'VeyonService' -ErrorAction SilentlyContinue
                if (\$vSvc) {
                    if (\$vSvc.Status -eq 'Running') {
                        Restart-Service -Name 'VeyonService' -Force -ErrorAction Stop
                    } else {
                        Start-Service -Name 'VeyonService' -ErrorAction Stop
                    }
                    \$waited = 0
                    while ((Get-Service -Name 'VeyonService').Status -ne 'Running' -and \$waited -lt 15) {
                        Start-Sleep -Seconds 1; \$waited++
                    }
                }
            } catch {}

            "EXIT:0"
        } catch {
            "ERR_EXEC: \$(\$_.Exception.Message.Split(\"\`n\")[0])"
        } finally {
            Remove-Item \$tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } -ArgumentList '${safeOrigin}', '${safeInst}', '${safeLoc}', '${safeCompJson}', '${safeDlToken}' -ErrorAction Stop
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
        while (index < targets.length && !authFailed && !isCancelled()) {
            const targetInfo = normalizeTarget(targets[index++])
            const result   = await runOneVeyon(targetInfo)
            done++
            if (result.ok) okCount++; else errCount++
            // Arrêt immédiat si credentials invalides — évite de verrouiller le compte AD
            if (result.error && result.error.startsWith('ERR_AUTH')) authFailed = true
            send('result', { done, total, ok: okCount, err: errCount,
                hostname: result.hostname, success: result.ok, output: result.output || '', error: result.error || '' })
        }
    }

    const workers = Array.from({ length: Math.min(5, targets.length) }, worker)
    await Promise.all(workers)
    veyonCancelled.delete(token)
    send('done', { ok: okCount, err: errCount, total })
    res.end()
})

// Télécharge le dernier installeur Veyon win64 depuis GitHub via PowerShell (proxy système)
router.post('/veyon-update-installer', async (req, res) => {
    try {
        const { downloadUrl, assetName } = req.body || {}
        if (!downloadUrl || !assetName) return res.status(400).json({ error: 'downloadUrl et assetName requis' })
        if (!/^https:\/\/github\.com\/veyon\/veyon\/releases\/download\//i.test(downloadUrl))
            return res.status(400).json({ error: 'URL non autorisée' })
        if (!/^veyon-.*-win64-setup\.exe$/i.test(assetName))
            return res.status(400).json({ error: 'Nom de fichier invalide' })

        if (!fs.existsSync(VEYON_DIR)) fs.mkdirSync(VEYON_DIR, { recursive: true })
        const existing = fs.readdirSync(VEYON_DIR).find(f => /^veyon-.*-win64-setup\.exe$/i.test(f))
        if (existing) try { fs.unlinkSync(path.join(VEYON_DIR, existing)) } catch {}

        const destPath = path.join(VEYON_DIR, assetName)
        const safeUrl  = downloadUrl.replace(/'/g, "''")
        const safeDest = destPath.replace(/'/g, "''")

        await new Promise((resolve, reject) => {
            const { spawn } = require('child_process')
            const ps = spawn('powershell.exe', [
                '-NoProfile', '-NonInteractive', '-Command',
                `Invoke-WebRequest -Uri '${safeUrl}' -OutFile '${safeDest}' -UseBasicParsing`
            ], { windowsHide: true })
            let stderr = ''
            ps.stderr.on('data', d => stderr += d.toString())
            ps.on('close', code => code === 0 ? resolve() : reject(new Error(stderr || `Exit ${code}`)))
            ps.on('error', reject)
        })

        res.json({ ok: true, filename: assetName })
    } catch(e) { res.status(500).json({ error: e.message }) }
})

// Génère un veyon_configuration.json par défaut si absent
router.post('/veyon-generate-config', (req, res) => {
    try {
        const dest = path.join(VEYON_DIR, 'veyon_configuration.json')
        if (fs.existsSync(dest)) return res.json({ ok: false, error: 'Fichier déjà présent' })
        if (!fs.existsSync(VEYON_DIR)) fs.mkdirSync(VEYON_DIR, { recursive: true })
        const { randomUUID } = require('crypto')
        const config = {
            Authentication: { Method: 1 },
            Core: {
                ApplicationVersion: 7,
                InstallationID: randomUUID(),
                PluginVersions: {
                    JsonStoreObject: {
                        "{14bacaaa-ebe5-449c-b881-5b382f952571}": "1.1",
                        "{1b08265b-348f-4978-acaa-45d4f6b90bd9}": "1.1",
                        "{1baa01e0-02d6-4494-a766-788f5b225991}": "1.1",
                        "{2917cdeb-ac13-4099-8715-20368254a367}": "1.1",
                        "{2ad98ccb-e9a5-43ef-8c4c-876ac5efbcb1}": "1.1",
                        "{387a0c43-1355-4ff6-9e1f-d098e9ce5127}": "1.1",
                        "{39d7a07f-94db-4912-aa1a-c4df8aee3879}": "1.1",
                        "{4122e8ca-b617-4e36-b851-8e050ed2d82e}": "1.2",
                        "{4790bad8-4c56-40d5-8361-099a68f0c24b}": "1.1",
                        "{67dfc1c1-8f37-4539-a298-16e74e34fd8b}": "1.1",
                        "{6f0a491e-c1c6-4338-8244-f823b0bf8670}": "1.2",
                        "{80580500-2e59-4297-9e35-e53959b028cd}": "1.2",
                        "{8ae6668b-9c12-4b29-9bfc-ff89f6604164}": "1.1",
                        "{a54ee018-42bf-4569-90c7-0d8470125ccf}": "2.0",
                        "{d4bb9c42-9eef-4ecb-8dd5-dfd84b355481}": "1.0",
                        "{e11bee03-b99c-465c-bf90-7e5339b83f6b}": "1.0",
                        "{ee322521-f4fb-482d-b082-82a79003afa7}": "1.1",
                        "{f626f759-7691-45c0-bd4a-37171d98d219}": "1.0"
                    }
                }
            },
            LDAP: {
                ComputerLocationAttribute: "",
                ComputerLocationsByAttribute: "false",
                ComputerLocationsByContainer: "false",
                LocationNameAttribute: "",
                UserLoginNameAttribute: ""
            },
            Master: {
                AllowAddingHiddenLocations: "false",
                AutoAdjustMonitoringIconSize: "false",
                AutoOpenComputerSelectPanel: "false",
                AutoSelectCurrentLocation: "false",
                ConfirmUnsafeActions: "false",
                HideComputerFilter: "false",
                HideEmptyLocations: "false",
                HideLocalComputer: true,
                ShowCurrentLocationOnly: "false"
            },
            Network: { FirewallExceptionEnabled: "1", VeyonServerPort: 11100 },
            Windows: { SoftwareSASEnabled: "1" }
        }
        fs.writeFileSync(dest, JSON.stringify(config, null, 4))
        res.json({ ok: true })
    } catch(e) { res.status(500).json({ error: e.message }) }
})

// Génère la paire de clés key / publickey pour Veyon via le module crypto Node.js
router.post('/veyon-generate-keys', async (req, res) => {
    try {
        if (!fs.existsSync(VEYON_DIR)) fs.mkdirSync(VEYON_DIR, { recursive: true })
        const { generateKeyPair } = require('crypto')
        const { privateKey, publicKey } = await new Promise((resolve, reject) =>
            generateKeyPair('rsa', {
                modulusLength: 2048,
                privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
                publicKeyEncoding:  { type: 'spki',  format: 'pem' }
            }, (err, pub, priv) => err ? reject(err) : resolve({ privateKey: priv, publicKey: pub }))
        )
        fs.writeFileSync(path.join(VEYON_DIR, 'key'),       privateKey)
        fs.writeFileSync(path.join(VEYON_DIR, 'publickey'), publicKey)
        res.json({ ok: true })
    } catch(e) { res.status(500).json({ error: e.message }) }
})

router.downloadTokens = downloadTokens
module.exports = router
