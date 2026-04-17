const express = require('express')
const fs      = require('fs')
const path    = require('path')
const crypto  = require('crypto')
const { PORT, HTTPS_PORT, SSL_KEY, SSL_CERT } = require('../lib/constants')
const { loadConfig, saveConfig, ensureSslCert } = require('../lib/config')
const { loadUsers, saveUsers } = require('../lib/users')

const router = express.Router()

// ── Gestion utilisateurs ──
router.get('/admin/users', (req, res) => {
    res.json(Object.keys(loadUsers()))
})

router.post('/admin/users', (req, res) => {
    const { username, password } = req.body
    if (!username || !password) return res.json({ ok: false, error: 'Champs manquants' })
    const name = username.toLowerCase().trim()
    if (!/^[a-z0-9._-]{2,32}$/.test(name)) return res.json({ ok: false, error: "Nom d'utilisateur invalide" })
    const users = loadUsers()
    if (users[name]) return res.json({ ok: false, error: 'Utilisateur déjà existant' })
    users[name] = crypto.createHash('sha256').update(password, 'utf8').digest('hex')
    saveUsers(users)
    res.json({ ok: true })
})

router.delete('/admin/users/:username', (req, res) => {
    const name = req.params.username.toLowerCase()
    const users = loadUsers()
    if (!users[name]) return res.json({ ok: false, error: 'Utilisateur introuvable' })
    if (Object.keys(users).length <= 1) return res.json({ ok: false, error: 'Impossible de supprimer le dernier compte' })
    delete users[name]
    saveUsers(users)
    res.json({ ok: true })
})

// ── Autostart ──
router.get('/admin/autostart', (req, res) => {
    const { execFile } = require('child_process')
    execFile('schtasks', ['/query', '/tn', 'PSManager'], err => {
        res.json({ enabled: !err })
    })
})

router.post('/admin/autostart', (req, res) => {
    const { enabled, username, password } = req.body
    const { execFile } = require('child_process')
    if (enabled) {
        if (!username || !password) return res.json({ ok: false, error: 'Identifiants requis pour créer la tâche planifiée.' })
        const nodePath   = process.execPath
        const scriptPath = path.join(__dirname, '..', 'server.js')
        const tr         = `"${nodePath}" "${scriptPath}"`
        execFile('schtasks', ['/create', '/tn', 'PSManager', '/tr', tr, '/sc', 'onstart', '/ru', username, '/rp', password, '/rl', 'HIGHEST', '/it', '/f'],
            (err, stdout, stderr) => res.json({ ok: !err, error: err ? (stderr || err.message) : undefined }))
    } else {
        execFile('schtasks', ['/delete', '/tn', 'PSManager', '/f'],
            (err, stdout, stderr) => res.json({ ok: !err, error: err ? (stderr || err.message) : undefined }))
    }
})

// ── Arrêt / redémarrage ──
router.post('/admin/shutdown', (req, res) => {
    res.json({ ok: true })
    setTimeout(() => process.exit(0), 300)
})

router.post('/admin/restart', (req, res) => {
    const cfg     = loadConfig()
    const proto   = cfg.httpsEnabled ? 'https' : 'http'
    const newPort = cfg.httpsEnabled ? HTTPS_PORT : PORT
    const host    = req.hostname === '::1' ? 'localhost' : req.hostname
    res.json({ ok: true, newUrl: `${proto}://${host}:${newPort}` })
    // WinSW redémarre automatiquement — pas besoin de spawner manuellement
    setTimeout(() => process.exit(0), 300)
})

// ── Configuration HTTPS ──
router.get('/admin/https-config', (req, res) => {
    const cfg = loadConfig()
    res.json({ ...cfg, certExists: fs.existsSync(SSL_CERT) })
})

router.post('/admin/https-config', (req, res) => {
    const cfg = loadConfig()
    if (typeof req.body.httpsEnabled === 'boolean') cfg.httpsEnabled = req.body.httpsEnabled
    saveConfig(cfg)
    res.json({ ok: true })
})

router.post('/admin/https-regen-cert', (req, res) => {
    try {
        if (fs.existsSync(SSL_KEY))  fs.unlinkSync(SSL_KEY)
        if (fs.existsSync(SSL_CERT)) fs.unlinkSync(SSL_CERT)
        ensureSslCert()
        res.json({ ok: true })
    } catch(e) {
        res.json({ ok: false, error: e.message })
    }
})

// ── Historique des logins ──
router.post('/login-history', (req, res) => {
    const { target, username, password, months = 6 } = req.body
    if (!target || !username || !password)
        return res.status(400).json({ error: 'Paramètres manquants' })

    const safeTarget = String(target).replace(/'/g, "''")
    const safeUser   = String(username).replace(/'/g, "''")
    const safePass   = String(password).replace(/'/g, "''")
    const safeMonths = Math.min(Math.max(parseInt(months) || 6, 1), 6)
    const { spawn }  = require('child_process')
    const iconv      = require('iconv-lite')

    const psScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$secPass = ConvertTo-SecureString '${safePass}' -AsPlainText -Force
$cred    = New-Object System.Management.Automation.PSCredential('${safeUser}', $secPass)
try {
    $r = Invoke-Command -ComputerName '${safeTarget}' -Credential $cred -ScriptBlock {
        $ignoredUsers = @('SYSTEM','SERVICE LOCAL','LOCAL SERVICE','SERVICE RESEAU','NETWORK SERVICE','ANONYMOUS LOGON','NX','nx')
        $since        = (Get-Date).AddMonths(-${safeMonths})
        $sinceUtc     = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        $tXp          = "TimeCreated[@SystemTime>='$sinceUtc']"
        $typeXp       = "Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11'"
        $typeXp4634   = "$typeXp or Data[@Name='LogonType']='0'"
        $xpLogon      = "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4624 and $tXp] and EventData[($typeXp)]]"
        $xpLogoff4634 = "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4634 and $tXp] and EventData[($typeXp4634)]]"
        $xpLogoff4647 = "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4647 and $tXp]]"

        $evts = [System.Collections.Generic.List[object]]::new()
        try { Get-WinEvent -LogName 'Security' -FilterXPath $xpLogon      -ErrorAction Stop | ForEach-Object { $evts.Add($_) } } catch {}
        try { Get-WinEvent -LogName 'Security' -FilterXPath $xpLogoff4634 -ErrorAction Stop | ForEach-Object { $evts.Add($_) } } catch {}
        try { Get-WinEvent -LogName 'Security' -FilterXPath $xpLogoff4647 -ErrorAction Stop | ForEach-Object { $evts.Add($_) } } catch {}

        $items = @($evts | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $map = @{}
            foreach ($node in $xml.Event.EventData.Data) {
                $map[[string]$node.Name] = [string]$node.'#text'
            }
            $username = [string]$map['TargetUserName']
            $domain   = [string]$map['TargetDomainName']
            if ([string]::IsNullOrWhiteSpace($username)) { return }
            if ($username -match '^(DWM-|UMFD-)') { return }
            if ($username.EndsWith('$')) { return }
            if ($ignoredUsers -contains $username.ToUpperInvariant()) { return }
            [pscustomobject]@{
                date     = $_.TimeCreated.ToString('dd/MM/yyyy')
                heure    = $_.TimeCreated.ToString('HH:mm:ss')
                isoDate  = $_.TimeCreated.ToString('yyyy-MM-dd')
                username = $username
                domaine  = if ([string]::IsNullOrWhiteSpace($domain)) { '-' } else { $domain }
                action   = if ($_.Id -eq 4624) { 'Ouverture' } else { 'Fermeture' }
                sortKey  = $_.TimeCreated.ToString('yyyyMMddHHmmss')
            }
        } | Group-Object { $_.sortKey + '|' + $_.username + '|' + $_.action } | ForEach-Object { $_.Group[0] } | Sort-Object sortKey -Descending)
        if ($null -eq $items) { $items = @() }
        $json = if ($items.Count -eq 0) { '[]' } else { $items | ConvertTo-Json -Compress -Depth 4 }
        if ([string]::IsNullOrEmpty($json)) { $json = '[]' }
        [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
    } -ErrorAction Stop
    Write-Output ('HISTORY_OK|' + [string]$r)
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const encoded    = Buffer.from(psScript, 'utf16le').toString('base64')
    const ps         = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], { windowsHide: true })
    const stdoutBufs = [], stderrBufs = []
    let responded    = false
    const timer      = setTimeout(() => {
        if (!responded) { responded = true; try { ps.kill() } catch {}; res.json({ ok: false, error: 'TIMEOUT — journal trop volumineux ?' }) }
    }, 180000)
    ps.stdout.on('data', d => stdoutBufs.push(d))
    ps.stderr.on('data', d => stderrBufs.push(d))
    ps.on('close', () => {
        clearTimeout(timer)
        if (responded) return
        responded    = true
        const out    = iconv.decode(Buffer.concat(stdoutBufs), 'cp850').trim()
        const errTxt = iconv.decode(Buffer.concat(stderrBufs), 'cp850').trim()
        if (out.startsWith('HISTORY_OK|')) {
            try {
                const raw   = Buffer.from(out.slice('HISTORY_OK|'.length).trim(), 'base64').toString('utf8')
                const items = JSON.parse(raw || '[]')
                return res.json({ ok: true, items: Array.isArray(items) ? items : [] })
            } catch(e) { return res.json({ ok: false, error: 'Réponse illisible : ' + e.message }) }
        }
        if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
        return res.json({ ok: false, error: errTxt || out || 'Réponse inattendue' })
    })
})

module.exports = router
