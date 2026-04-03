const express   = require('express')
const path      = require('path')
const fs        = require('fs')
const os        = require('os')
const crypto    = require('crypto')
const app       = express()

app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

const { getNetworkInterfaces, getNetworkRange, scanNetwork, checkPort5985 } = require('./scan')
const { runInventory } = require('./inventory')
const { sendWol }      = require('./wol')
const { generateReport, COL_DEFS } = require('./report')

// ── Configuration LDAP ──
const LDAP_SERVERS  = ['999-DC04.EDU.HDF','999-DC03.EDU.HDF','999-DC02.EDU.HDF','999-DC01.EDU.HDF']
const LDAP_DOMAIN   = 'EDU.HDF'
const LDAP_BASE_DN  = 'DC=EDU,DC=HDF'
const LDAP_GROUP    = 'GP-EM_PDC_1_Admins_T2'
const LDAP_READ_DN  = 'adread@EDU.HDF'
const LDAP_READ_PWD = '6nx2RE4JmxZzFXPz'

/**
 * Tente un bind LDAP sur les DC dans l'ordre, retourne le client connecté ou null
 */
function ldapBind(userDN, password) {
    const ldap = require('ldapjs')
    let idx = 0
    return new Promise(resolve => {
        function tryNext() {
            if (idx >= LDAP_SERVERS.length) return resolve(null)
            const server = LDAP_SERVERS[idx++]
            const client = ldap.createClient({
                url            : `ldap://${server}`,
                timeout        : 5000,
                connectTimeout : 5000,
                tlsOptions     : { rejectUnauthorized: false }
            })
            client.on('error', () => tryNext())
            client.bind(userDN, password, err => {
                if (err) { client.destroy(); return tryNext() }
                resolve(client)
            })
        }
        tryNext()
    })
}

/**
 * Vérifie si l'utilisateur appartient au groupe autorisé
 * Utilise le compte adread pour la recherche
 */
function ldapCheckGroup(username) {
    const ldap = require('ldapjs')
    return new Promise(async resolve => {
        const client = await ldapBind(LDAP_READ_DN, LDAP_READ_PWD)
        if (!client) return resolve(false)
        // member:1.2.840.113556.1.4.1941: = recherche récursive dans les groupes imbriqués (LDAP_MATCHING_RULE_IN_CHAIN)
        const filter = `(&(sAMAccountName=${username})(memberOf:1.2.840.113556.1.4.1941:=CN=${LDAP_GROUP},OU=EM_PDC_1,OU=ServiceExploitationPdc,OU=DepNum,DC=EDU,DC=HDF))`
        client.search(LDAP_BASE_DN, { scope: 'sub', filter, attributes: ['sAMAccountName'], sizeLimit: 1 }, (err, res) => {
            if (err) { client.destroy(); return resolve(false) }
            let found = false
            res.on('searchEntry', () => { found = true })
            res.on('error', () => { client.destroy(); resolve(false) })
            res.on('end', () => { client.destroy(); resolve(found) })
        })
    })
}

// ── Route authentification (LDAP + comptes locaux) ──
app.post('/api/auth', async (req, res) => {
    const { username, password } = req.body
    if (!username || !password) return res.json({ ok: false, error: 'Identifiants manquants' })

    // 1. Vérification compte local (hash SHA-256 côté serveur)
    const LOCAL_USERS = loadUsers()
    const hash = crypto.createHash('sha256').update(password, 'utf8').digest('hex')
    if (LOCAL_USERS[username.toLowerCase()] && LOCAL_USERS[username.toLowerCase()] === hash) {
        return res.json({ ok: true, user: username, mode: 'local' })
    }

    // 2. Normaliser le username (supprimer edu\ ou EDU\ en préfixe)
    let cleanUser = username
    const bs = cleanUser.indexOf(String.fromCharCode(92))
    if (bs !== -1) cleanUser = cleanUser.slice(bs + 1)
    const at = cleanUser.indexOf('@')
    if (at !== -1) cleanUser = cleanUser.slice(0, at)

    // 3. Authentification LDAP — bind avec les credentials de l'utilisateur
    const userDN = `${cleanUser}@${LDAP_DOMAIN}`
    const client = await ldapBind(userDN, password)
    if (!client) return res.json({ ok: false, error: 'Identifiants incorrects ou serveur LDAP inaccessible' })
    client.destroy()

    // 4. Vérification appartenance au groupe AD
    const inGroup = await ldapCheckGroup(cleanUser)
    if (!inGroup) return res.json({ ok: false, error: `Accès refusé — vous n'êtes pas membre de ${LDAP_GROUP}` })

    res.json({ ok: true, user: username, mode: 'ldap' })
})

const { copyFileToHosts, collectDrivers, deployDrivers, listDirectory, downloadFile, deleteRemote, mkdirRemote, uploadToRemote } = require('./actions')

const PORT        = 4000
const PARC_FILE   = "C:\\ps-manager\\inventaire\\parc.txt"
const SCRIPTS_DIR = "C:\\ps-manager\\scripts"
const LOG_BASE    = "C:\\ps-manager\\inventaire\\Logiciels"
const USERS_FILE  = path.join(__dirname, 'users.json')

function loadUsers() {
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')) }
    catch { return { aurelien: '07d83a12362fd614659f4ae220247b725f458faa5b1f5426ec14c4dd5a019927' } }
}
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2))
}
// Initialiser users.json si absent
if (!fs.existsSync(USERS_FILE)) saveUsers(loadUsers())


app.get('/api/parc', (req, res) => {
    try {
        if (!fs.existsSync(PARC_FILE)) return res.json([])
        const lines = fs.readFileSync(PARC_FILE, 'utf-8')
            .split('\n').map(l => l.trim()).filter(l => l)
        const hosts = lines.map(line => {
            const p = line.split('|')
            return {
                hostname  : p[0]  || '',
                ip        : p[1]  || '',
                fabricant : p[2]  || '',
                modele    : p[3]  || '',
                serial    : p[4]  || '',
                os        : p[5]  || '',
                ram       : p[6]  || '',
                disque    : p[7]  || '',
                typeDisque: p[8]  || '',
                gpu       : p[9]  || '',
                date      : p[10] || '',
                bios      : p[11] || '',
                mac       : p[12] || '',
                typeRam   : p[13] || '',
                cpu         : p[14] || '',
                installDate : p[15] || '',
            }
        })
        res.json(hosts)
    } catch(e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/scripts', (req, res) => {
    try {
        if (!fs.existsSync(SCRIPTS_DIR)) return res.json([])
        res.json(fs.readdirSync(SCRIPTS_DIR).filter(f => f.endsWith('.ps1')))
    } catch(e) { res.json([]) }
})

app.get('/api/interfaces', (req, res) => {
    res.json(getNetworkInterfaces())
})

app.get('/api/ping', (req, res) => {
    const { checkPort5985 } = require('./scan')
    const ip = req.query.ip
    if (!ip) return res.json({ alive: false })
    checkPort5985(ip, 1000).then(alive => res.json({ alive })).catch(() => res.json({ alive: false }))
})

// ── Ping batch via port 5985 — SSE streaming, résultats en temps réel
app.post('/api/ping-batch', async (req, res) => {
    const { hosts } = req.body
    if (!hosts || !hosts.length) return res.json({ results: [] })
    const { checkPort5985 } = require('./scan')

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

app.get('/api/scan', async (req, res) => {
    const { ip, prefix, throttle = 50, doInventory, username, password } = req.query
    if (!ip || !prefix) return res.status(400).json({ error: 'ip et prefix requis' })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    const ips   = getNetworkRange(ip, parseInt(prefix))
    const total = ips.length

    send('phase', { phase: 1, label: `Phase 1 — Scan de ${total} adresses`, total })

    const found = await scanNetwork(ips, parseInt(throttle), (scanned, total, foundCount, newIp) => {
        if (newIp) send('found', { ip: newIp })
        if (scanned % 25 === 0 || scanned === total)
            send('progress', { scanned, total, found: foundCount, pct: Math.round(scanned / total * 100) })
    })

    send('phase1done', { found: found.length, total })

    if (!found.length) {
        send('done', { ok: 0, err: 0, message: 'Aucun hote WinRM detecte.' })
        return res.end()
    }

    if (!doInventory || doInventory === 'false') {
        send('done', { ok: 0, err: 0, message: `${found.length} hote(s) detecte(s). Inventaire non demande.` })
        return res.end()
    }

    send('phase', { phase: 2, label: `Phase 2 — Inventaire WinRM sur ${found.length} poste(s)`, total: found.length })

    const { ok, err } = await runInventory({
        targets     : found,
        username,
        password,
        parcFile    : PARC_FILE,
        logBaseDir  : LOG_BASE,
        concurrency : parseInt(throttle),
        onProgress  : ({ done, total, ok, err, result }) => {
            send('inv_progress', { done, total, ok, err, pct: Math.round(done / total * 100) })
            if (result.ok) send('inv_ok',  { display: result.display })
            else           send('inv_err', { addr: result.addr, error: result.error })
        }
    })

    send('done', { ok, err, message: `Termine — OK:${ok}  ERR:${err}` })
    res.end()
})


// ── Store temporaire sessions d'exécution (contourne limite URL GET)
const runSessions = new Map()

app.post('/api/run-init', (req, res) => {
    const { script, targets, username, password, throttle } = req.body
    if (!script || !targets || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })
    const token = require('crypto').randomUUID()
    runSessions.set(token, { script, targets, username, password, throttle: throttle || 10 })
    setTimeout(() => runSessions.delete(token), 30000)
    res.json({ token })
})

// ── Exécution script PS sur plusieurs postes (SSE streaming)
app.get('/api/run', async (req, res) => {
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

    const hostList  = targets.split(',').map(h => h.trim()).filter(Boolean)
    const total     = hostList.length
    let   done      = 0, okCount = 0, errCount = 0
    let   index     = 0
    const outputs   = []

    send('start', { total, script })

    async function worker() {
        while (index < hostList.length) {
            const hostname = hostList[index++]
            const result = await runOneScript(scriptPath, hostname, hostname, username, password)
            done++
            if (result.ok) okCount++; else errCount++
            outputs.push(result)
            send('result', { done, total, ok: okCount, err: errCount,
                hostname, success: result.ok, output: result.output, error: result.error })
        }
    }

    const workers = Array.from({ length: Math.min(parseInt(throttle), hostList.length) }, worker)
    await Promise.all(workers)

    send('done', { ok: okCount, err: errCount, total })
    res.end()
})

/**
 * Exécute un script PowerShell sur une cible distante avec gestion d'erreurs propre
 */
async function runOneScript(scriptPath, target, hostname, username, password) {
    const alive = await checkPort5985(target, 5000).catch(() => false)
    if (!alive) return { ok: false, hostname: hostname || target, output: '', error: 'ERR_OFFLINE: Poste éteint ou 5985 fermé' }

    return new Promise(resolve => {
        const { spawn } = require('child_process');

        const escapedPassword = password.replace(/'/g, "''");
        const escapedPath     = scriptPath.replace(/\\/g, '\\\\').replace(/'/g, "''");

        const psCmd = `
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            $ErrorActionPreference = 'Stop'

            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect('${target}', 5985, $null, $null)
                if (-not $connect.AsyncWaitHandle.WaitOne(5000, $false)) { 
                    throw "OFFLINE" 
                }
                $tcp.EndConnect($connect)
                $tcp.Close()

                $secPass = ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
                
                $result = Invoke-Command -ComputerName '${target}' -Credential $cred -FilePath '${escapedPath}' -ErrorAction Stop
                
                if ($result) { $result | Out-String } else { "OK (Aucun retour)" }

            } catch {
                $m = $_.Exception.Message
                if ($m -eq "OFFLINE") { 
                    "ERR_OFFLINE: Poste éteint ou 5985 fermé" 
                }
                elseif ($m -like "*Accès refusé*" -or $m -like "*Access is denied*" -or $m -like "*Autorisation refusée*") { 
                    "ERR_AUTH: Identifiants invalides" 
                }
                elseif ($m -like "*12152*" -or $m -like "*non valide*") { 
                    "ERR_WINRM: Service instable (Erreur HTTP 12152)" 
                }
                elseif ($m -like "*WinRM*") { 
                    "ERR_CONFIG: WinRM non configuré sur la cible" 
                }
                else { 
                    "ERR_GENERAL: " + $m.Split("\`n")[0].Trim() 
                }
            }
        `;

        const ps = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psCmd]);

        let stdout = '';
        let stderr = '';

        ps.stdout.on('data', data => { stdout += data.toString(); });
        ps.stderr.on('data', data => { stderr += data.toString(); });

        ps.on('close', (code) => {
            const output = stdout.trim();
            if (output.startsWith('ERR_')) {
                resolve({ ok: false, hostname: hostname || target, output: '', error: output });
            } else if (output) {
                resolve({ ok: true, hostname: hostname || target, output: output, error: '' });
            } else {
                resolve({ ok: false, hostname: hostname || target, output: '', error: stderr.trim().substring(0, 100) || 'Délai d\'attente dépassé' });
            }
        });
    });
}


// ── Wake-on-LAN
app.post('/api/wol', async (req, res) => {
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
        const ip    = parts[1] || ''
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


// ── Upload temporaire pour copie de fichiers
const multer  = require('multer')
const upload  = multer({ dest: os.tmpdir() })

// ── Upload script PS1
app.post('/api/scripts/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ ok: false, error: 'Fichier manquant' })
        if (!req.file.originalname.endsWith('.ps1'))
            return res.status(400).json({ ok: false, error: 'Seuls les fichiers .ps1 sont acceptés' })
        if (!fs.existsSync(SCRIPTS_DIR)) fs.mkdirSync(SCRIPTS_DIR, { recursive: true })
        const dest = path.join(SCRIPTS_DIR, req.file.originalname)
        fs.renameSync(req.file.path, dest)
        res.json({ ok: true, name: req.file.originalname })
    } catch(e) {
        res.status(500).json({ ok: false, error: e.message })
    }
})

const DRIVERS_BASE = 'C:\\ps-manager\\Drivers'

// ── Copie de fichier(s) / dossier vers les postes sélectionnés (SSE streaming)
app.post('/api/copy-files', upload.array('files', 500), async (req, res) => {
    const { targets, destination, username, password, concurrency, relativePaths } = req.body
    if (!req.files?.length || !targets || !username || !password)
        return res.status(400).json({ error: 'Paramètres manquants (fichier, targets, credentials)' })

    const hostList = JSON.parse(targets)
    if (!hostList.length) return res.status(400).json({ error: 'Aucune cible' })

    const rPaths = relativePaths
        ? (Array.isArray(relativePaths) ? relativePaths : [relativePaths])
        : []

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => { if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`) }

    send('start', { total: hostList.length, fileCount: req.files.length, destination: destination || 'C:\\Windows\\Temp' })

    let totalOk = 0, totalErr = 0
    const dest = destination || 'C:\\Windows\\Temp'

    for (let i = 0; i < req.files.length; i++) {
        const file         = req.files[i]
        // Multer lit le Content-Disposition header en latin1 → reconvertir en UTF-8
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8')
        // Les champs texte (relativePaths) arrivent déjà en UTF-8 via busboy — pas de recodage
        const relPath      = rPaths[i] ? rPaths[i] : originalName
        send('file_start', { fileName: originalName, fileIndex: i + 1, fileCount: req.files.length })
        try {
            const { ok, err } = await copyFileToHosts({
                filePath   : file.path,
                fileName   : originalName,
                relPath,
                destination: dest,
                targets    : hostList,
                username, password,
                concurrency: parseInt(concurrency) || 5,
                onProgress : ({ done, total, ok, err, result }) => {
                    send('progress', { done, total, ok, err, pct: Math.round(done / total * 100) })
                    if (result.ok) send('ok',  { hostname: result.hostname, path: result.path })
                    else           send('err', { hostname: result.hostname, error: result.error })
                }
            })
            totalOk += ok
            totalErr += err
            send('file_done', { fileName: originalName, ok, err })
        } catch(e) {
            send('error', { message: e.message })
        } finally {
            try { fs.unlinkSync(file.path) } catch {}
        }
    }

    send('done', { ok: totalOk, err: totalErr })
    res.end()
})

// ── Aspiration des drivers d'un poste vers le serveur Node (SSE streaming)
app.post('/api/collect-drivers', async (req, res) => {
    const { hostname, modele, username, password } = req.body
    if (!hostname || !modele || !username || !password)
        return res.status(400).json({ error: 'Paramètres manquants' })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => { if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`) }

    send('start', { hostname, modele, dest: path.join(DRIVERS_BASE, modele) })

    try {
        const result = await collectDrivers({
            hostname, modele, username, password,
            driversBase: DRIVERS_BASE,
            onProgress : data => send('progress', typeof data === 'object' ? data : { message: data })
        })
        if (result.ok) send('done', { ok: true,  hostname, modele, localDest: result.localDest, fileCount: result.fileCount })
        else           send('done', { ok: false, hostname, error: result.error })
    } catch(e) {
        send('done', { ok: false, hostname, error: e.message })
    } finally {
        res.end()
    }
})


// ── Déploiement drivers depuis C:\ps-manager\Drivers\<modele>\ vers les postes (SSE)
app.post('/api/deploy-drivers', async (req, res) => {
    const { modele, targets, username, password, concurrency } = req.body
    if (!modele || !targets || !username || !password)
        return res.status(400).json({ error: 'Paramètres manquants' })

    const modelePath = path.join(DRIVERS_BASE, modele)
    if (!fs.existsSync(modelePath))
        return res.status(404).json({ error: `Dossier introuvable : ${modelePath}` })

    const hostList = Array.isArray(targets) ? targets : JSON.parse(targets)
    if (!hostList.length) return res.status(400).json({ error: 'Aucune cible' })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => { if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`) }

    send('start', { total: hostList.length, modele, modelePath })

    try {
        const { ok, err } = await deployDrivers({
            modelePath,
            targets    : hostList,
            username, password,
            concurrency: parseInt(concurrency) || 3,
            onProgress : ({ done, total, ok, err, result, fileProgress }) => {
                if (fileProgress) {
                    send('file_progress', fileProgress)
                } else {
                    send('progress', { done, total, ok, err, pct: Math.round(done / total * 100) })
                    if (result && result.ok) send('ok',  { hostname: result.hostname, detail: result.detail })
                    else if (result)         send('err', { hostname: result.hostname, error: result.error })
                }
            }
        })
        send('done', { ok, err })
    } catch(e) {
        send('error', { message: e.message })
    } finally {
        res.end()
    }
})

// ── Liste des dossiers modèles disponibles dans DRIVERS_BASE
app.get('/api/drivers-models', (req, res) => {
    try {
        if (!fs.existsSync(DRIVERS_BASE)) return res.json([])
        const models = fs.readdirSync(DRIVERS_BASE, { withFileTypes: true })
            .filter(d => d.isDirectory())
            .map(d => d.name)
        res.json(models)
    } catch(e) { res.json([]) }
})


// ════════════════════════════════════════════════════════════════
//  EXPLORATEUR DE FICHIERS DISTANT
// ════════════════════════════════════════════════════════════════

const multerFs = multer({ dest: os.tmpdir() })

// ── Lister un dossier distant
app.get('/api/fs/list', async (req, res) => {
    const { hostname, username, password, path: remotePath } = req.query
    if (!hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    const result = await listDirectory({ hostname, username, password, remotePath })
    res.json(result)
})

// ── Télécharger un fichier distant → stream vers le navigateur
app.get('/api/fs/download', async (req, res) => {
    const { hostname, username, password, path: remotePath } = req.query
    if (!hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })

    const result = await downloadFile({ hostname, username, password, remotePath })
    if (!result.ok) return res.status(500).json({ ok: false, error: result.error })

    // RFC 5987 — supporte les accents et caractères spéciaux
    const encoded = encodeURIComponent(result.fileName)
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encoded}`)
    res.setHeader('Content-Type', 'application/octet-stream')
    const stream = fs.createReadStream(result.localPath)
    stream.pipe(res)
    stream.on('end',   () => { try { fs.unlinkSync(result.localPath) } catch {} })
    stream.on('error', () => { try { fs.unlinkSync(result.localPath) } catch {} })
})

// ── Uploader un fichier (depuis le navigateur) vers un dossier distant
app.post('/api/fs/upload', multerFs.single('file'), async (req, res) => {
    const { hostname, username, password, remotePath } = req.body
    if (!req.file || !hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })

    // Multer reçoit le nom en latin-1 — reconvertir en UTF-8
    const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8')

    // Fichier tmp avec un nom safe (pas d'accents dans le chemin)
    const tmpOriginal = path.join(os.tmpdir(), `fsul_${Date.now()}_${req.file.filename}`)
    try { fs.renameSync(req.file.path, tmpOriginal) } catch { fs.copyFileSync(req.file.path, tmpOriginal); fs.unlinkSync(req.file.path) }

    // remotePath = dossier cible, on passe le vrai nom au script PS via uploadToRemote
    const result = await uploadToRemote({ hostname, username, password, localPath: tmpOriginal, remotePath, fileName: originalName })
    try { fs.unlinkSync(tmpOriginal) } catch {}
    res.json(result)
})

// ── Supprimer un fichier ou dossier distant
app.delete('/api/fs/delete', async (req, res) => {
    const { hostname, username, password, path: remotePath, isDir } = req.query
    if (!hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    const result = await deleteRemote({ hostname, username, password, remotePath, isDir: isDir === 'true' })
    res.json(result)
})

// ── Créer un dossier distant
app.post('/api/fs/mkdir', async (req, res) => {
    const { hostname, username, password, remotePath } = req.body
    if (!hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    const result = await mkdirRemote({ hostname, username, password, remotePath })
    res.json(result)
})


// ── OFF / RST / MSG / SESSION via PowerShell WinRM
app.post('/api/action', async (req, res) => {
    const { action, hostname, ip, username, password, message } = req.body
    if (!action || !hostname || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })

    const target = hostname
    const { spawn } = require('child_process')

    const alive = await checkPort5985(target, 5000).catch(() => false)
    if (!alive) return res.json({ ok: false, error: 'Poste éteint ou port 5985 fermé' })

    const psCommands = {
        off: `Stop-Computer -ComputerName '${target}' -Credential $cred -Force`,
        rst: `Restart-Computer -ComputerName '${target}' -Credential $cred -Force`,
        msg: `Invoke-Command -ComputerName '${target}' -Credential $cred -ScriptBlock { msg * '${(message||'').replace(/'/g,"''")}' }`,
        session: `$r = Invoke-Command -ComputerName '${target}' -Credential $cred -ScriptBlock { (query user 2>&1) | Out-String } -ErrorAction Stop; Write-Output "SESSION_OK|$r"`,
    }

    const cmd = psCommands[action]
    if (!cmd) return res.status(400).json({ error: 'Action inconnue' })

    const psScript = `
$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try { ${cmd}; Write-Output "OK" } catch { Write-Output "ERROR|$($_.Exception.Message)" }
`
    const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psScript],
        { windowsHide: true })
    let stdout = '', stderr = ''
    let responded = false
    const timer = setTimeout(() => { if (!responded) { responded = true; ps.kill(); res.json({ ok: false, error: 'TIMEOUT' }) } }, 30000)
    ps.stdout.on('data', d => stdout += d.toString())
    ps.stderr.on('data', d => stderr += d.toString())
    ps.on('close', () => {
        clearTimeout(timer)
        if (responded) return
        responded = true
        const out = stdout.trim()
        if (out.startsWith('ERROR|')) res.json({ ok: false, error: out.replace('ERROR|','') })
        else if (out.startsWith('SESSION_OK|')) res.json({ ok: true, output: out.replace('SESSION_OK|','') })
        else if (out === 'OK' || out === '') res.json({ ok: true, output: out })
        else res.json({ ok: true, output: out })
    })
})


// ── OFF / RST en masse avec worker pool (throttle configurable)
app.post('/api/action-bulk', async (req, res) => {
    const { action, targets, username, password, throttle = 10 } = req.body
    if (!action || !targets || !targets.length || !username || !password)
        return res.status(400).json({ error: 'Paramètres manquants' })
    if (!['off', 'rst'].includes(action))
        return res.status(400).json({ error: 'Action non supportée en bulk' })

    const { spawn } = require('child_process')
    const hostList = targets.map(h => (typeof h === 'string' ? h : h.hostname))
    const results  = []
    let index = 0

    const psCmd = action === 'off'
        ? (t) => `Stop-Computer -ComputerName '${t}' -Credential $cred -Force`
        : (t) => `Restart-Computer -ComputerName '${t}' -Credential $cred -Force`

    async function runOne(hostname) {
        const alive = await checkPort5985(hostname, 5000).catch(() => false)
        if (!alive) return { hostname, ok: false, error: 'Poste éteint ou port 5985 fermé' }
        const psScript = `
$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try { ${psCmd(hostname)}; Write-Output "OK" } catch { Write-Output "ERROR|$($_.Exception.Message)" }
`
        return new Promise(resolve => {
            const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psScript], { windowsHide: true })
            let stdout = '', settled = false
            const timer = setTimeout(() => { if (!settled) { settled = true; ps.kill(); resolve({ hostname, ok: false, error: 'TIMEOUT' }) } }, 30000)
            ps.stdout.on('data', d => stdout += d.toString())
            ps.on('close', () => {
                clearTimeout(timer)
                if (settled) return
                settled = true
                const out = stdout.trim()
                if (out.startsWith('ERROR|')) resolve({ hostname, ok: false, error: out.replace('ERROR|', '') })
                else resolve({ hostname, ok: true })
            })
        })
    }

    async function worker() {
        while (index < hostList.length) {
            const hostname = hostList[index++]
            results.push(await runOne(hostname))
        }
    }

    const workers = Array.from({ length: Math.min(parseInt(throttle) || 10, hostList.length) }, worker)
    await Promise.all(workers)

    res.json({ ok: true, results })
})


// ── RDP — mstsc+cmdkey si localhost, téléchargement .rdp sinon
app.get('/api/rdp', (req, res) => {
    const { ip, hostname, username, password } = req.query
    if (!ip && !hostname) return res.status(400).json({ error: 'IP ou hostname requis' })

    const target   = hostname || ip
    const clientIp = req.socket.remoteAddress || ''
    const isLocal  = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1'

    const rdpLines = [
        'screen mode id:i:2',
        'use multimon:i:0',
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
        'disable wallpaper:i:0',
        'disable full window drag:i:1',
        'disable menu anims:i:1',
    ].filter(l => l !== '').join('\r\n')

    if (isLocal) {
        const { spawn, execSync } = require('child_process')
        const tmpRdp = require('path').join(require('os').tmpdir(), `psm_${Date.now()}.rdp`)
        require('fs').writeFileSync(tmpRdp, rdpLines, 'utf-8')
        if (username && password) {
            try { execSync(`cmdkey /generic:${target} /user:${username} /pass:${password}`, { windowsHide: true }) } catch {}
        }
        spawn('mstsc.exe', [tmpRdp], { detached: true, windowsHide: false })
        setTimeout(() => {
            try { require('fs').unlinkSync(tmpRdp) } catch {}
            if (username) try { execSync(`cmdkey /delete:${target}`, { windowsHide: true }) } catch {}
        }, 10000)
        res.json({ ok: true, mode: 'mstsc' })
    } else {
        res.setHeader('Content-Type', 'application/x-rdp')
        res.setHeader('Content-Disposition', `attachment; filename="${hostname || target}.rdp"`)
        res.send(rdpLines)
    }
})


// ── Lancer PowerShell externe (fenêtre Windows Terminal)
app.post('/api/ps-external', (req, res) => {
    const { hostname, ip, username, password } = req.body
    if (!hostname || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })
    const target = hostname
    const { spawn } = require('child_process')
    const psCmd = `
$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
Enter-PSSession -ComputerName '${target}' -Credential $cred
`
    const tmpFile = require('path').join(require('os').tmpdir(), `pssession_${Date.now()}.ps1`)
    require('fs').writeFileSync(tmpFile, psCmd, 'utf-8')
    spawn('powershell', [
        '-NoExit',
        '-ExecutionPolicy', 'Bypass',
        '-File', tmpFile
    ], { detached: true, windowsHide: false })
    res.json({ ok: true })
})

// ── Terminal PS interactif (SSE streaming)
app.get('/api/ps-terminal', async (req, res) => {
    const { hostname, ip, username, password, command } = req.query
    if (!hostname || !username || !password || !command)
        return res.status(400).json({ error: 'Parametres manquants' })

    const target = hostname
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`)
    }

    const { spawn } = require('child_process')
    const psScript = `
$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)
try {
    $result = Invoke-Command -ComputerName '${target}' -Credential $cred -ScriptBlock {
        ${command}
    } -ErrorAction Stop
    $result | Out-String
} catch { Write-Error $_.Exception.Message }
`
    const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psScript],
        { windowsHide: true })
    let timer = setTimeout(() => { ps.kill(); send('error', 'TIMEOUT'); res.end() }, 60000)

    ps.stdout.on('data', d => send('stdout', d.toString()))
    ps.stderr.on('data', d => send('stderr', d.toString()))
    ps.on('close', code => {
        clearTimeout(timer)
        send('done', code === 0 ? 'OK' : `Exit ${code}`)
        res.end()
    })
    req.on('close', () => ps.kill())
})


// ── Colonnes disponibles
app.get('/api/report/cols', (req, res) => res.json(COL_DEFS))

// ── Génération rapport HTML
app.post('/api/report', (req, res) => {
    const { cols } = req.body
    if (!cols || !cols.length) return res.status(400).json({ error: 'Aucune colonne' })
    try {
        const html    = generateReport(PARC_FILE, LOG_BASE, cols)
        const outFile = require('path').join(require('path').dirname(PARC_FILE), 'inventaire_postes.html')
        require('fs').writeFileSync(outFile, html, 'utf-8')
        res.json({ ok: true, file: outFile })
    } catch(e) {
        res.status(500).json({ error: e.message })
    }
})

// ── Génération rapport CSV — séparateur ; + BOM UTF-8 pour Excel FR
app.post('/api/report/csv', (req, res) => {
    const { cols } = req.body
    if (!cols || !cols.length) return res.status(400).json({ error: 'Aucune colonne' })
    try {
        const { COL_DEFS } = require('./report')

        if (!fs.existsSync(PARC_FILE)) return res.status(404).json({ error: 'parc.txt introuvable' })
        const lines = fs.readFileSync(PARC_FILE, 'utf-8').split('\n').map(l => l.trim()).filter(l => l)
        if (!lines.length) return res.status(404).json({ error: 'parc.txt vide' })

        const pcs = lines.map(line => {
            const p = line.split('|')
            return {
                Hostname: p[0]  || '', IP:     p[1]  || '', Marque: p[2]  || '',
                Modele:   p[3]  || '', Serial: p[4]  || '', WinVer: p[5]  || '',
                RAM:      p[6]  || '', Disque: p[7]  || '', Type:   p[8]  || '',
                GPU:      p[9]  || '', Date:   p[10] || '', Bios:   p[11] || '',
                MAC:      p[12] || '', TypeRAM:p[13] || '', CPU:    p[14] || '',
            }
        })

        const headers = cols.map(k => {
            const def = COL_DEFS.find(c => c.key === k)
            return def ? def.label : k
        })

        const esc = v => {
            const s = String(v || '').replace(/"/g, '""')
            return s.includes(';') || s.includes('"') || s.includes('\n') ? `"${s}"` : s
        }

        const rows = pcs.map(pc => cols.map(k => {
            if (k === 'RAM')    return esc(pc.RAM    ? pc.RAM    + ' GB' : '')
            if (k === 'Disque') return esc(pc.Disque ? pc.Disque + ' GB' : '')
            return esc(pc[k] || '')
        }).join(';'))

        const csv = '\uFEFF' + [headers.join(';'), ...rows].join('\r\n')

        res.setHeader('Content-Type', 'text/csv; charset=utf-8')
        res.setHeader('Content-Disposition', 'attachment; filename="inventaire.csv"')
        res.send(csv)
    } catch(e) {
        res.status(500).json({ error: e.message })
    }
})

// ── Servir le rapport généré
app.get('/rapport', (req, res) => {
    const outFile = require('path').join(require('path').dirname(PARC_FILE), 'inventaire_postes.html')
    if (!require('fs').existsSync(outFile)) return res.status(404).send('Rapport non généré.')
    res.sendFile(outFile)
})


const LLDP_SCRIPT = `
#region PSDiscoveryProtocol Module Code

class DiscoveryProtocolPacket {
    [string]$MachineName
    [datetime]$TimeCreated
    [int]$FragmentSize
    [byte[]]$Fragment
    [int]$MiniportIfIndex
    [string]$Connection
    [string]$Interface

    DiscoveryProtocolPacket([PSCustomObject]$WinEvent) {
        $this.MachineName = $WinEvent.MachineName
        $this.TimeCreated = $WinEvent.TimeCreated
        $this.FragmentSize = $WinEvent.FragmentSize
        $this.Fragment = $WinEvent.Fragment
        $this.MiniportIfIndex = $WinEvent.MiniportIfIndex
        $this.Connection = $WinEvent.Connection
        $this.Interface = $WinEvent.Interface

        Add-Member -InputObject $this -MemberType ScriptProperty -Name IsDiscoveryProtocolPacket -Value {
            if (
                [UInt16]0x2000 -eq [BitConverter]::ToUInt16($this.Fragment[21..20], 0) -or
                [UInt16]0x88CC -eq [BitConverter]::ToUInt16($this.Fragment[13..12], 0)
            ) { return [bool]$true } else { return [bool]$false }
        }

        Add-Member -InputObject $this -MemberType ScriptProperty -Name DiscoveryProtocolType -Value {
            if ([UInt16]0x2000 -eq [BitConverter]::ToUInt16($this.Fragment[21..20], 0)) {
                return [string]'CDP'
            }
            elseif ([UInt16]0x88CC -eq [BitConverter]::ToUInt16($this.Fragment[13..12], 0)) {
                return [string]'LLDP'
            }
            else {
                return [string]::Empty
            }
        }

        Add-Member -InputObject $this -MemberType ScriptProperty -Name SourceAddress -Value {
            [PhysicalAddress]::new($this.Fragment[6..11]).ToString()
        }
    }
}

function Invoke-DiscoveryProtocolCapture {
    [CmdletBinding(DefaultParametersetName = 'LocalCapture')]
    [OutputType('DiscoveryProtocolPacket')]
    param(
        [Parameter(ParameterSetName = 'RemoteCapture', Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CN', 'Computer')]
        [String[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = 'LocalCapture', Position = 0)]
        [Parameter(ParameterSetName = 'RemoteCapture', Position = 1)]
        [Int16]$Duration = $(if ($Type -eq 'LLDP') { 32 } else { 62 }),

        [Parameter(ParameterSetName = 'LocalCapture', Position = 1)]
        [Parameter(ParameterSetName = 'RemoteCapture', Position = 2)]
        [ValidateSet('CDP', 'LLDP')]
        [String]$Type,

        [Parameter(ParameterSetName = 'RemoteCapture')]
        [ValidateNotNull()]
        [System.Management.Automation.Credential()]
        [PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
        [switch]$NoCleanup,

        [Parameter()]
        [switch]$Force
    )

    begin {
        if ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
            $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal $Identity
            if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                throw 'Invoke-DiscoveryProtocolCapture requires elevation. Please run PowerShell as administrator.'
            }
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            if ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
                $CimSession = @{}
                $PSSession = @{}
            }

            $ETLFilePath = Invoke-Command @PSSession -ScriptBlock {
                $TempFile = New-TemporaryFile
                $ETLFile = Rename-Item -Path $TempFile.FullName -NewName $TempFile.FullName.Replace('.tmp', '.etl') -PassThru
                $ETLFile.FullName
            }

            $Adapters = Get-NetAdapter @CimSession | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceType -eq 6 } | Select-Object Name, MacAddress, InterfaceDescription, InterfaceIndex

            if ($Adapters) {
                $MACAddresses = $Adapters.MacAddress.ForEach({ [PhysicalAddress]::Parse($_).ToString() })
                $SessionName = 'Capture-{0}' -f (Get-Date).ToString('s')

                if ($Force.IsPresent) {
                    Get-NetEventSession @CimSession | ForEach-Object {
                        if ($_.SessionStatus -eq 'Running') {
                            $_ | Stop-NetEventSession @CimSession
                        }
                        $_ | Remove-NetEventSession @CimSession
                    }
                }

                try {
                    New-NetEventSession -Name $SessionName -LocalFilePath $ETLFilePath -CaptureMode SaveToFile @CimSession -ErrorAction Stop | Out-Null
                }
                catch [Microsoft.Management.Infrastructure.CimException] {
                    if ($_.Exception.NativeErrorCode -eq 'AlreadyExists') {
                        $Message = "Another NetEventSession already exists. Run with -Force to remove existing NetEventSessions."
                        Write-Error -Message $Message
                    }
                    else {
                        Write-Error -ErrorRecord $_ 
                    }
                    continue
                }

                $LinkLayerAddress = switch ($Type) {
                    'CDP' { '01-00-0c-cc-cc-cc' }
                    'LLDP' { '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                    Default { '01-00-0c-cc-cc-cc', '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                }

                $PacketCaptureParams = @{
                    SessionName      = $SessionName
                    TruncationLength = 0
                    CaptureType      = 'Physical'
                    LinkLayerAddress = $LinkLayerAddress
                }

                Add-NetEventPacketCaptureProvider @PacketCaptureParams @CimSession | Out-Null

                foreach ($Adapter in $Adapters) {
                    Add-NetEventNetworkAdapter -Name $Adapter.Name -PromiscuousMode $True @CimSession | Out-Null
                }

                Start-NetEventSession -Name $SessionName @CimSession

                $Seconds = $Duration
                $End = (Get-Date).AddSeconds($Seconds)
                while ($End -gt (Get-Date)) {
                    $SecondsLeft = $End.Subtract((Get-Date)).TotalSeconds
                    $Percent = ($Seconds - $SecondsLeft) / $Seconds * 100
                    Write-Progress -Activity "Discovery Protocol Packet Capture" -Status "Capturing on $Computer..." -SecondsRemaining $SecondsLeft -PercentComplete $Percent
                    [System.Threading.Thread]::Sleep(500)
                }

                Stop-NetEventSession -Name $SessionName @CimSession

                $Events = Invoke-Command @PSSession -ScriptBlock {
                    param($ETLFilePath)

                    try {
                        $Events = Get-WinEvent -Path $ETLFilePath -Oldest -FilterXPath "*[System[EventID=1001]]" -ErrorAction Stop
                    }
                    catch {
                        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                            Write-Error -ErrorRecord $_ 
                        }
                    }

                    [string[]]$XpathQueries = @(
                        "Event/EventData/Data[@Name='FragmentSize']"
                        "Event/EventData/Data[@Name='Fragment']"
                        "Event/EventData/Data[@Name='MiniportIfIndex']"
                    )

                    $PropertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($XpathQueries)

                    foreach ($WinEvent in $Events) {
                        $EventData = $WinEvent | Select-Object MachineName, TimeCreated
                        $EventData | Add-Member -NotePropertyName FragmentSize -NotePropertyValue $null
                        $EventData | Add-Member -NotePropertyName Fragment -NotePropertyValue $null
                        $EventData | Add-Member -NotePropertyName MiniportIfIndex -NotePropertyValue $null
                        $EventData.FragmentSize, $EventData.Fragment, $EventData.MiniportIfIndex = $WinEvent.GetPropertyValues($PropertySelector)
                        $Adapter = @(Get-NetAdapter).Where({ $_.InterfaceIndex -eq $EventData.MiniportIfIndex })
                        $EventData | Add-Member -NotePropertyName Connection -NotePropertyValue $Adapter.Name
                        $EventData | Add-Member -NotePropertyName Interface -NotePropertyValue $Adapter.InterfaceDescription
                        $EventData
                    }
                } -ArgumentList $ETLFilePath

                $FoundPackets = $Events -as [DiscoveryProtocolPacket[]] | Where-Object {
                    $_.IsDiscoveryProtocolPacket -and $_.SourceAddress -notin $MACAddresses
                } | Group-Object MiniportIfIndex | ForEach-Object {
                    $_.Group | Select-Object -First 1
                }

                Remove-NetEventSession -Name $SessionName @CimSession

                if (-not $NoCleanup.IsPresent) {
                    Invoke-Command @PSSession -ScriptBlock {
                        param($ETLFilePath)
                        Remove-Item -Path $ETLFilePath -Force
                    } -ArgumentList $ETLFilePath
                }

                if ($FoundPackets) {
                    $FoundPackets
                }
                else {
                    Write-Warning "No discovery protocol packets captured on $Computer in $Seconds seconds."
                    return
                }
            }
            else {
                Write-Warning "Unable to find a connected wired adapter on $Computer."
                return
            }
        }
    }
}

function Get-DiscoveryProtocolData {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [DiscoveryProtocolPacket[]]$Packet
    )

    process {
        foreach ($Item in $Packet) {
            switch ($Item.DiscoveryProtocolType) {
                'CDP' { $PacketData = ConvertFrom-CDPPacket -Packet $Item.Fragment }
                'LLDP' { $PacketData = ConvertFrom-LLDPPacket -Packet $Item.Fragment }
                Default { throw 'No valid CDP or LLDP found in $Packet' }
            }

            $PacketData | Add-Member -NotePropertyName Computer -NotePropertyValue $Item.MachineName
            $PacketData | Add-Member -NotePropertyName Connection -NotePropertyValue $Item.Connection
            $PacketData | Add-Member -NotePropertyName Interface -NotePropertyValue $Item.Interface
            $PacketData | Add-Member -NotePropertyName Type -NotePropertyValue $Item.DiscoveryProtocolType
            $PacketData
        }
    }
}

function ConvertFrom-LLDPPacket {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [byte[]]$Packet
    )

    begin {
        $TlvType = @{
            EndOfLLDPDU          = 0
            ChassisId            = 1
            PortId               = 2
            TimeToLive           = 3
            PortDescription      = 4
            SystemName           = 5
            SystemDescription    = 6
            ManagementAddress    = 8
            OrganizationSpecific = 127
        }
    }

    process {
        $Offset = 14
        $Mask = 0x01FF
        $Hash = @{}

        while ($Offset -lt $Packet.Length) {
            $Type = $Packet[$Offset] -shr 1
            $Length = [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0) -band $Mask
            $Offset += 2

            switch ($Type) {
                $TlvType.ChassisId {
                    $Subtype = $Packet[($Offset)]
                    if ($SubType -in (1, 2, 3, 6, 7)) {
                        $Hash.Add('ChassisId', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }
                    if ($Subtype -eq 4) {
                        $Hash.Add('ChassisId', [PhysicalAddress]::new($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }
                    $Offset += $Length
                    break
                }

                $TlvType.PortId {
                    $Subtype = $Packet[($Offset)]
                    if ($SubType -in (1, 2, 5, 6, 7)) {
                        $Hash.Add('Port', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }
                    if ($Subtype -eq 3) {
                        $Hash.Add('Port', [PhysicalAddress]::new($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }
                    $Offset += $Length
                    break
                }

                $TlvType.TimeToLive {
                    $Hash.Add('TimeToLive', [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0))
                    $Offset += $Length
                    break
                }

                $TlvType.PortDescription {
                    $Hash.Add('PortDescription', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.SystemName {
                    $Hash.Add('Device', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.SystemDescription {
                    $Hash.Add('SystemDescription', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.ManagementAddress {
                    $AddrLen = $Packet[($Offset)]
                    $Subtype = $Packet[($Offset + 1)]

                    if (-not $Hash.ContainsKey('IPAddress') -and $Subtype -in 1, 2) {
                        $Addresses = New-Object System.Collections.Generic.List[String]
                        $Hash.Add('IPAddress', $Addresses)
                    }

                    if ($Subtype -in 1, 2) {
                        $Addresses.Add(([System.Net.IPAddress][byte[]]$Packet[($Offset + 2)..($Offset + $AddrLen)]).IPAddressToString)
                    }
                    $Offset += $Length
                    break
                }

                $TlvType.OrganizationSpecific {
                    $OUI = [System.BitConverter]::ToString($Packet[($Offset)..($Offset + 2)])
                    $Subtype = $Packet[($Offset + 3)]

                    if ($OUI -eq '00-12-BB' -and $Subtype -eq 10) {
                        $Hash.Add('Model', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 4)..($Offset + $Length - 1)]))
                    }

                    if ($OUI -eq '00-80-C2' -and $Subtype -eq 1) {
                        $Hash.Add('VLAN', [BitConverter]::ToUInt16($Packet[($Offset + 5)..($Offset + 4)], 0))
                    }

                    $Offset += $Length
                    break
                }

                default {
                    $Offset += $Length
                    break
                }
            }
        }
        [PSCustomObject]$Hash
    }
}

#endregion

# ── Appel principal ──
$Packet = Invoke-DiscoveryProtocolCapture -Type LLDP -Force
if ($Packet) {
    $data = Get-DiscoveryProtocolData -Packet $Packet
    $switch = if ($data.Device)      { $data.Device }      else { 'N/A' }
    $port   = if ($data.Port)        { $data.Port }        else { 'N/A' }
    $vlan   = if ($data.VLAN)        { $data.VLAN }        else { 'N/A' }
    $ip     = if ($data.IPAddress)   { $data.IPAddress -join ', ' } else { 'N/A' }
    $desc   = if ($data.SystemDescription) { $data.SystemDescription.Trim() -replace '\s+', ' ' } else { 'N/A' }
    $iface  = if ($data.Connection)  { $data.Connection }  else { 'N/A' }
    Write-Output "LLDP_OK|$switch|$port|$vlan|$ip|$desc|$iface"
} else {
    Write-Output "LLDP_NONE"
}

`


// ── LLDP
app.post('/api/lldp', async (req, res) => {
    const { hostname, ip, username, password } = req.body
    if (!hostname || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })

    const target = hostname
    const { spawn } = require('child_process')
    const tmpFile  = require('path').join(require('os').tmpdir(), `lldp_${Date.now()}.ps1`)
    require('fs').writeFileSync(tmpFile, LLDP_SCRIPT, 'utf-8')

    const psCmd = `
$pw   = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
Invoke-Command -ComputerName '${target}' -Credential $cred -FilePath '${tmpFile.replace(/\\/g,'\\\\').replace(/'/g,"''")}' -ErrorAction Stop
`
    const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psCmd],
        { windowsHide: true })
    const stdoutBufs = [], stderrBufs = []
    let responded = false
    const timer = setTimeout(() => { if (!responded) { responded = true; ps.kill(); res.json({ ok: false, error: 'TIMEOUT' }) } }, 90000)

    ps.stdout.on('data', d => stdoutBufs.push(d))
    ps.stderr.on('data', d => stderrBufs.push(d))
    ps.on('close', () => {
        clearTimeout(timer)
        if (responded) return
        responded = true
        try { require('fs').unlinkSync(tmpFile) } catch {}
        const iconv   = require('iconv-lite')
        const out     = iconv.decode(Buffer.concat(stdoutBufs), 'cp850')
        const err     = iconv.decode(Buffer.concat(stderrBufs), 'cp850')
        const okLine  = out.split('\n').find(l => l.trim().startsWith('LLDP_OK|'))
        const noneLine= out.split('\n').find(l => l.trim() === 'LLDP_NONE')
        const netErrs = ['cannot be reached','inaccessible','refused','winrm','wsman','access denied']
        if (netErrs.some(e => err.toLowerCase().includes(e)))
            return res.json({ ok: false, error: 'Poste hors ligne ou WinRM inactif' })
        if (okLine) {
            const p = okLine.trim().split('|')
            return res.json({ ok: true,
                switch: p[1]||'N/A', port: p[2]||'N/A', vlan: p[3]||'N/A',
                ip_sw:  p[4]||'N/A', desc: p[5]||'N/A', iface: p[6]||'N/A' })
        }
        if (noneLine) return res.json({ ok: false, error: 'Aucune trame LLDP détectée' })
        res.json({ ok: false, error: (err || out).slice(0, 150) || 'Erreur inconnue' })
    })
})


// ── Utilisation disque C: via WinRM
app.post('/api/disk', async (req, res) => {
    const { hostname, ip, username, password } = req.body
    if (!hostname || !username || !password)
        return res.status(400).json({ ok: false, error: 'Parametres manquants' })

    const target = hostname
    const { spawn } = require('child_process')

    const psCmd = `
$pw   = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    Invoke-Command -ComputerName '${target}' -Credential $cred -ScriptBlock {
        $d     = Get-PSDrive C
        $used  = [math]::Round($d.Used/1GB,1)
        $free  = [math]::Round($d.Free/1GB,1)
        $total = $used + $free
        Write-Output "$used|$free|$total"
    } -ErrorAction Stop
} catch { Write-Output "ERROR|$($_.Exception.Message)" }
`
    const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psCmd],
        { windowsHide: true })
    const bufs = []
    let responded = false
    const timer = setTimeout(() => { if (!responded) { responded = true; ps.kill(); res.json({ ok: false, error: 'TIMEOUT' }) } }, 12000)
    ps.stdout.on('data', d => bufs.push(d))
    ps.on('close', () => {
        clearTimeout(timer)
        if (responded) return
        responded = true
        const iconv = require('iconv-lite')
        const out   = iconv.decode(Buffer.concat(bufs), 'cp850')
        const line  = out.split('\n').map(l => l.trim()).find(l => {
            const p = l.split('|')
            return p.length === 3 && !isNaN(parseFloat(p[0]))
        })
        if (line) {
            const [used, free, total] = line.split('|').map(parseFloat)
            res.json({ ok: true, used, free, total })
        } else {
            res.json({ ok: false, error: out.slice(0, 100) })
        }
    })
})


// ── Liste logiciels depuis Logiciels\hostname.txt
app.get('/api/softs', (req, res) => {
    const { hostname } = req.query
    if (!hostname) return res.status(400).json({ ok: false, error: 'hostname requis' })
    const softFile = require('path').join(require('path').dirname(PARC_FILE), 'Logiciels', `${hostname}.txt`)
    try {
        if (!fs.existsSync(softFile)) return res.json({ ok: true, softs: [] })
        const lines = fs.readFileSync(softFile, 'utf-8')
            .split('\n').map(l => l.trim()).filter(l => l)
        const softs = lines.map(l => {
            const p = l.split('|')
            return { name: p[0] || '', version: p[1] || '' }
        })
        res.json({ ok: true, softs })
    } catch(e) {
        res.status(500).json({ ok: false, error: e.message })
    }
})


// ── Lancer mstsc.exe directement depuis le serveur Windows
app.get('/api/rdp-launch', (req, res) => {
    const { ip, hostname, username } = req.query
    if (!ip && !hostname) return res.status(400).json({ error: 'IP ou hostname requis' })

    const target = hostname
    const { spawn } = require('child_process')

    const rdpLines = [
        'screen mode id:i:2',
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
    ].filter(l => l !== '').join('\r\n')

    const tmpRdp = path.join(os.tmpdir(), `psm_${Date.now()}.rdp`)
    fs.writeFileSync(tmpRdp, rdpLines, 'utf-8')

    const password = req.query.password
    if (username && password) {
        const { execSync } = require('child_process')
        try {
            execSync(`cmdkey /generic:${target} /user:${username} /pass:${password}`, { windowsHide: true })
        } catch {}
    }

    spawn('mstsc.exe', [tmpRdp], { detached: true, windowsHide: false })

    setTimeout(() => {
        try { fs.unlinkSync(tmpRdp) } catch {}
        if (username) {
            try { require('child_process').execSync(`cmdkey /delete:${target}`, { windowsHide: true }) } catch {}
        }
    }, 10000)

    res.json({ ok: true })
})


// ── Résolution DNS hostname → IP réelle
const dns = require('dns')

function resolveHostname(hostname) {
    return new Promise(resolve => {
        dns.lookup(hostname, { family: 4 }, (err, address) => {
            resolve(err ? null : address)
        })
    })
}

function updateParcIp(hostname, ip) {
    try {
        const lines = fs.readFileSync(PARC_FILE, 'utf-8')
            .split('\n').map(l => l.trim()).filter(l => l)
        const idx = lines.findIndex(l => l.startsWith(hostname + '|'))
        if (idx >= 0) {
            const parts = lines[idx].split('|')
            if (parts[1] !== ip) {
                parts[1] = ip
                lines[idx] = parts.join('|')
                fs.writeFileSync(PARC_FILE, lines.join('\n'), 'utf-8')
                return true
            }
        }
        return false
    } catch { return false }
}

app.get('/api/resolve', async (req, res) => {
    const { hostname } = req.query
    if (!hostname) return res.status(400).json({ error: 'hostname requis' })
    const ip = await resolveHostname(hostname)
    if (!ip) return res.json({ ok: false, error: 'Résolution impossible' })
    const changed = updateParcIp(hostname, ip)
    res.json({ ok: true, ip, changed })
})


// ── Résolution DNS batch + écriture unique parc.txt
app.post('/api/resolve-batch', async (req, res) => {
    const { hostnames } = req.body
    if (!hostnames || !hostnames.length) return res.json({ results: [] })

    const results = await Promise.all(
        hostnames.map(hostname =>
            resolveHostname(hostname)
                .then(ip => ({ hostname, ok: !!ip, ip: ip || '' }))
        )
    )

    try {
        let lines = fs.readFileSync(PARC_FILE, 'utf-8')
            .split('\n').map(l => l.trim()).filter(l => l)
        let updated = false
        for (const { hostname, ok, ip } of results) {
            if (!ok) continue
            const idx = lines.findIndex(l => l.startsWith(hostname + '|'))
            if (idx >= 0) {
                const parts = lines[idx].split('|')
                if (parts[1] !== ip) { parts[1] = ip; lines[idx] = parts.join('|'); updated = true }
            }
        }
        if (updated) fs.writeFileSync(PARC_FILE, lines.join('\n'), 'utf-8')
    } catch(e) { console.error('resolve-batch parc.txt:', e.message) }

    res.json({ results })
})

// ══ REGISTRE ══════════════════════════════════════════════════════════════════

function regPs(psScript, timeout = 30000) {
    return new Promise(resolve => {
        const { spawn } = require('child_process')
        const tmp = require('path').join(os.tmpdir(), `reg_${Date.now()}.ps1`)
        fs.writeFileSync(tmp, '\uFEFF' + psScript, 'utf-8')
        const ps = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmp], { windowsHide: true })
        const bufs = [], errs = []
        const timer = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, error: 'TIMEOUT' }) }, timeout)
        ps.stdout.on('data', d => bufs.push(d))
        ps.stderr.on('data', d => errs.push(d))
        ps.on('close', () => {
            clearTimeout(timer); cleanup()
            resolve({ ok: true, out: Buffer.concat(bufs).toString('utf-8').trim() })
        })
        function cleanup() { try { fs.unlinkSync(tmp) } catch {} }
    })
}

const REG_DRIVES = `
        if (!(Test-Path 'HKLM:')) { New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE | Out-Null }
        if (!(Test-Path 'HKCR:')) { New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null }
        if (!(Test-Path 'HKU:'))  { New-PSDrive -Name HKU  -PSProvider Registry -Root HKEY_USERS | Out-Null }
        if (!(Test-Path 'HKCC:')) { New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG | Out-Null }`

const REG_CONV = `$kpPs = $kp -replace '^HKEY_LOCAL_MACHINE','HKLM:' -replace '^HKEY_CURRENT_USER','HKCU:' -replace '^HKEY_CLASSES_ROOT','HKCR:' -replace '^HKEY_USERS','HKU:' -replace '^HKEY_CURRENT_CONFIG','HKCC:'`

app.post('/api/reg-list', async (req, res) => {
    const { hostname, username, password, keyPath } = req.body
    if (!hostname || !username || !password || !keyPath) return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    const esc = s => s.replace(/'/g, "''")
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    $result = Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp)
        ${REG_CONV}
        ${REG_DRIVES}
        $out = @{ subkeys = @(); values = @() }
        try {
            $names = @(Get-ChildItem -Path $kpPs -ErrorAction Stop | ForEach-Object { [string]$_.PSChildName }) | Select-Object -First 500
            $out.subkeys = $names
        } catch {}
        try {
            $item = Get-Item -Path $kpPs -ErrorAction Stop
            foreach ($name in $item.GetValueNames()) {
                $kind = $item.GetValueKind($name).ToString()
                $val  = $item.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
                $out.values += @{ name = $name; kind = $kind; value = "$val" }
            }
        } catch {}
        $out | ConvertTo-Json -Depth 3
    } -ArgumentList '${esc(keyPath)}'
    Write-Output $result
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    try {
        const data    = JSON.parse(out)
        const subkeys = Array.isArray(data.subkeys) ? data.subkeys : (data.subkeys ? [data.subkeys] : [])
        const values  = Array.isArray(data.values)  ? data.values  : (data.values  ? [data.values]  : [])
        res.json({ ok: true, subkeys, values })
    } catch { res.json({ ok: false, error: 'Parse error: ' + out.slice(0, 200) }) }
})

app.post('/api/reg-set', async (req, res) => {
    const { hostname, username, password, keyPath, name, kind, value } = req.body
    if (!hostname || !username || !password || !keyPath || name === undefined) return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    const esc = s => s.replace(/'/g, "''")
    const kindMap = { String:'String', ExpandString:'ExpandString', Binary:'Binary', DWord:'DWord', QWord:'QWord', MultiString:'MultiString' }
    const psKind  = kindMap[kind] || 'String'
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp, $n, $k, $v)
        ${REG_CONV}
        ${REG_DRIVES}
        if (!(Test-Path $kpPs)) { New-Item -Path $kpPs -Force | Out-Null }
        $existing = (Get-Item $kpPs).GetValueNames()
        if ($existing -contains $n) { Set-ItemProperty -Path $kpPs -Name $n -Value $v }
        else { New-ItemProperty -Path $kpPs -Name $n -PropertyType $k -Value $v -Force | Out-Null }
        Write-Output 'OK'
    } -ArgumentList '${esc(keyPath)}','${esc(name)}','${psKind}','${esc(String(value))}'
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    res.json({ ok: out.includes('OK') })
})

app.post('/api/reg-delete-value', async (req, res) => {
    const { hostname, username, password, keyPath, name } = req.body
    const esc = s => s.replace(/'/g, "''")
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp, $n)
        ${REG_CONV}
        ${REG_DRIVES}
        Remove-ItemProperty -Path $kpPs -Name $n -Force -ErrorAction Stop
        Write-Output 'OK'
    } -ArgumentList '${esc(keyPath)}','${esc(name)}'
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    res.json({ ok: out.includes('OK') })
})

app.post('/api/reg-delete-key', async (req, res) => {
    const { hostname, username, password, keyPath } = req.body
    const esc = s => s.replace(/'/g, "''")
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp)
        ${REG_CONV}
        ${REG_DRIVES}
        Remove-Item -Path $kpPs -Recurse -Force -ErrorAction Stop
        Write-Output 'OK'
    } -ArgumentList '${esc(keyPath)}'
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    res.json({ ok: out.includes('OK') })
})

app.post('/api/reg-create-key', async (req, res) => {
    const { hostname, username, password, keyPath } = req.body
    const esc = s => s.replace(/'/g, "''")
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp)
        ${REG_CONV}
        ${REG_DRIVES}
        New-Item -Path $kpPs -Force | Out-Null
        Write-Output 'OK'
    } -ArgumentList '${esc(keyPath)}'
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    res.json({ ok: out.includes('OK') })
})

// ── Garantie Lenovo via API publique pcsupport.lenovo.com
app.get('/api/warranty', async (req, res) => {
    const { serial } = req.query
    if (!serial) return res.status(400).json({ ok: false, error: 'serial requis' })

    const https = require('https')

    function httpGet(url, headers = {}) {
        return new Promise((resolve, reject) => {
            const opts = { headers: { 'User-Agent': 'Mozilla/5.0', ...headers } }
            https.get(url, opts, r => {
                let data = ''
                r.on('data', c => data += c)
                r.on('end', () => resolve({ status: r.statusCode, body: data }))
            }).on('error', reject)
        })
    }

    try {
        // Étape 1 — identifier le produit
        const prod = await httpGet(`https://pcsupport.lenovo.com/us/en/api/v4/mse/getproducts?productId=${serial}`)
        let productId = null, productName = null
        try {
            const j = JSON.parse(prod.body)
            const p = Array.isArray(j) ? j[0] : j
            if (p && p.Id) { productId = p.Id; productName = p.Name }
        } catch {}

        if (!productId) return res.json({ ok: false, error: 'Produit non trouvé pour ce S/N' })

        // Étape 2 — page warranty + extraction regex
        const wp = await httpGet(
            `https://pcsupport.lenovo.com/us/en/products/${productId}/warranty`,
            { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        )
        const content = wp.body

        const patterns = [
            /"Start"\s*:\s*"(\d{4}-\d{2}-\d{2})".*?"End"\s*:\s*"(\d{4}-\d{2}-\d{2})"/gs,
            /"warstart"\s*:\s*"([^"]+)".*?"wed"\s*:\s*"([^"]+)"/gs,
            /"warrantyStartDate"\s*:\s*"([^"]+)".*?"warrantyEndDate"\s*:\s*"([^"]+)"/gs,
        ]

        let bestStart = null, bestEnd = null
        for (const pattern of patterns) {
            let m
            while ((m = pattern.exec(content)) !== null) {
                try {
                    const s = new Date(m[1]), e = new Date(m[2])
                    if (!bestEnd || e > bestEnd) { bestStart = s; bestEnd = e }
                } catch {}
            }
            if (bestEnd) break
        }

        // Méthode 2 — API support sans clé
        if (!bestEnd) {
            try {
                const api = await httpGet(`http://supportapi.lenovo.com/V2.5/Warranty?Serial=${serial}`)
                const j   = JSON.parse(api.body)
                if (j.Warranty) {
                    for (const w of j.Warranty) {
                        const e = w.End ? new Date(w.End) : null
                        const s = w.Start ? new Date(w.Start) : null
                        if (e && (!bestEnd || e > bestEnd)) { bestEnd = e; bestStart = s }
                    }
                }
            } catch {}
        }

        if (!bestEnd) {
            return res.json({
                ok: false,
                error: 'Données non disponibles',
                url: `https://pcsupport.lenovo.com/us/en/products/${productId}/warranty`
            })
        }

        const now    = new Date()
        const active = bestEnd >= now
        const fmt    = d => d ? `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}/${d.getFullYear()}` : '—'

        res.json({
            ok: true,
            productName,
            active,
            start : fmt(bestStart),
            end   : fmt(bestEnd),
            url   : `https://pcsupport.lenovo.com/us/en/products/${productId}/warranty`
        })
    } catch(e) {
        res.json({ ok: false, error: e.message })
    }
})

// ── Routes administration ──

app.get('/api/admin/users', (req, res) => {
    res.json(Object.keys(loadUsers()))
})

app.post('/api/admin/users', (req, res) => {
    const { username, password } = req.body
    if (!username || !password) return res.json({ ok: false, error: 'Champs manquants' })
    const name = username.toLowerCase().trim()
    if (!/^[a-z0-9._-]{2,32}$/.test(name)) return res.json({ ok: false, error: 'Nom d\'utilisateur invalide' })
    const users = loadUsers()
    if (users[name]) return res.json({ ok: false, error: 'Utilisateur déjà existant' })
    users[name] = crypto.createHash('sha256').update(password, 'utf8').digest('hex')
    saveUsers(users)
    res.json({ ok: true })
})

app.delete('/api/admin/users/:username', (req, res) => {
    const name = req.params.username.toLowerCase()
    const users = loadUsers()
    if (!users[name]) return res.json({ ok: false, error: 'Utilisateur introuvable' })
    if (Object.keys(users).length <= 1) return res.json({ ok: false, error: 'Impossible de supprimer le dernier compte' })
    delete users[name]
    saveUsers(users)
    res.json({ ok: true })
})

app.get('/api/admin/autostart', (req, res) => {
    const { execFile } = require('child_process')
    execFile('schtasks', ['/query', '/tn', 'PSManager'], err => {
        res.json({ enabled: !err })
    })
})

app.post('/api/admin/autostart', (req, res) => {
    const { enabled } = req.body
    const { execFile } = require('child_process')
    if (enabled) {
        const nodePath   = process.execPath
        const scriptPath = path.join(__dirname, 'server.js')
        const tr         = `"${nodePath}" "${scriptPath}"`
        execFile('schtasks', ['/create', '/tn', 'PSManager', '/tr', tr, '/sc', 'onstart', '/ru', 'SYSTEM', '/rl', 'HIGHEST', '/f'],
            (err, stdout, stderr) => res.json({ ok: !err, error: err ? (stderr || err.message) : undefined }))
    } else {
        execFile('schtasks', ['/delete', '/tn', 'PSManager', '/f'],
            (err, stdout, stderr) => res.json({ ok: !err, error: err ? (stderr || err.message) : undefined }))
    }
})

app.post('/api/admin/shutdown', (req, res) => {
    res.json({ ok: true })
    setTimeout(() => process.exit(0), 300)
})

app.post('/api/admin/restart', (req, res) => {
    res.json({ ok: true })
    setTimeout(() => {
        const { spawn } = require('child_process')
        spawn(process.execPath, [path.join(__dirname, 'server.js')], {
            detached: true, stdio: 'ignore', cwd: __dirname
        }).unref()
        process.exit(0)
    }, 300)
})

// ── Serveur HTTP partagé Express + WebSocket (node-pty terminal PS)
const http = require('http')
const server = http.createServer(app)

try {
    const WebSocket = require('ws')
    const pty       = require('node-pty')
    const wss       = new WebSocket.Server({ server })

    const ptySessions = new Map()

    wss.on('connection', (ws, req) => {
        let ptyProcess = null

        ws.on('message', raw => {
            let msg
            try { msg = JSON.parse(raw) } catch { msg = null }

            if (msg && msg.type === 'init') {
                const { hostname, username, password } = msg
                const psCmd = `$secPass = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass); Enter-PSSession -ComputerName '${hostname}' -Credential $cred`

                ptyProcess = pty.spawn('powershell.exe', ['-NoExit', '-Command', psCmd], {
                    name: 'xterm-color',
                    cols: msg.cols || 120,
                    rows: msg.rows || 30,
                    env: process.env
                })

                ptySessions.set(ws, ptyProcess)

                ptyProcess.onData(data => {
                    if (ws.readyState === WebSocket.OPEN) ws.send(data)
                })

                ptyProcess.onExit(() => {
                    if (ws.readyState === WebSocket.OPEN) ws.send('\r\n[Session terminée]\r\n')
                    ptySessions.delete(ws)
                })

            } else if (msg && msg.type === 'resize' && ptyProcess) {
                ptyProcess.resize(msg.cols, msg.rows)

            } else if (typeof raw === 'string' && ptyProcess) {
                ptyProcess.write(raw)

            } else if (ptyProcess) {
                ptyProcess.write(raw.toString())
            }
        })

        ws.on('close', () => {
            if (ptyProcess) { try { ptyProcess.kill() } catch {} }
            ptySessions.delete(ws)
        })
    })

    console.log('✔ WebSocket terminal PS actif')
} catch(e) {
    console.warn('node-pty ou ws non installé — terminal interactif désactivé:', e.message)
}

// ── Historique des logins ────────────────────────────────────────────────
app.post('/api/login-history', (req, res) => {
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
        $ignoredUsers = @('SYSTEM','SERVICE LOCAL','LOCAL SERVICE','SERVICE RESEAU','NETWORK SERVICE','ANONYMOUS LOGON')
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
        } | Sort-Object sortKey -Descending)
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
        if (!responded) { responded = true; try { ps.kill() } catch {} ; res.json({ ok: false, error: 'TIMEOUT — journal trop volumineux ?' }) }
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

// ── PLANIFICATION ─────────────────────────────────────────────────────────

// Chiffrement des mots de passe dans schedules.json
const KEY_FILE = path.join(__dirname, '.schedule.key')
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
    if (!stored.startsWith('enc:')) return stored  // rétrocompat entrée en clair
    try {
        const parts  = stored.split(':')
        const iv     = Buffer.from(parts[1], 'hex')
        const enc    = Buffer.from(parts[2], 'hex')
        const decipher = crypto.createDecipheriv('aes-256-cbc', _getSchedKey(), iv)
        return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf-8')
    } catch { return null }
}

const nodeSchedule   = require('node-schedule')
const SCHEDULES_FILE = path.join(__dirname, 'schedules.json')
const scheduledJobs  = new Map()   // id → { task, job }

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
                const scriptPath = path.join(SCRIPTS_DIR, script)
                if (fs.existsSync(scriptPath))
                    await runOneScript(scriptPath, hostname, hostname, username, password).catch(() => {})
            } else {
                const psCmd = type === 'reboot'
                    ? `Restart-Computer -ComputerName '${hostname}' -Credential $cred -Force`
                    : `Stop-Computer -ComputerName '${hostname}' -Credential $cred -Force`
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

function scheduleTask(task) {
    const date = new Date(task.at)
    const job  = nodeSchedule.scheduleJob(task.id, date, async () => {
        await executeScheduledTask(task).catch(e => console.error('Erreur tâche planifiée:', e.message))
        scheduledJobs.delete(task.id)
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
            if (new Date(task.at) > new Date()) { scheduleTask(task); restored++ }
        }
        if (restored) console.log(`✔ ${restored} tâche(s) planifiée(s) restaurée(s)`)
    } catch(e) { console.warn('Erreur chargement schedules.json:', e.message) }
}

loadSchedules()

app.post('/api/schedule', (req, res) => {
    const { type, script, targets, at, username, password, label, throttle } = req.body
    if (!type || !targets || !targets.length || !at)
        return res.status(400).json({ error: 'Paramètres manquants' })
    if (['script', 'reboot', 'shutdown'].includes(type) && (!username || !password))
        return res.status(400).json({ error: 'Identifiants requis' })
    if (type === 'script' && !script)
        return res.status(400).json({ error: 'Script requis' })
    const date = new Date(at)
    if (isNaN(date.getTime()) || date <= new Date())
        return res.status(400).json({ error: 'Date invalide ou passée' })
    const id   = `sched_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`
    const task = { id, type, script: script || null, targets, at, username: username || null, password: encryptSchedPassword(password || null), label: label || '', throttle: parseInt(throttle) || 10, createdAt: new Date().toISOString() }
    scheduleTask(task)
    persistSchedules()
    res.json({ ok: true, id })
})

app.get('/api/schedules', (req, res) => {
    const list = [...scheduledJobs.values()].map(({ task }) => ({
        id: task.id, type: task.type, script: task.script,
        targets: task.targets, at: task.at, label: task.label, createdAt: task.createdAt
    }))
    list.sort((a, b) => new Date(a.at) - new Date(b.at))
    res.json(list)
})

app.delete('/api/schedule/:id', (req, res) => {
    const entry = scheduledJobs.get(req.params.id)
    if (!entry) return res.status(404).json({ error: 'Tâche introuvable' })
    entry.job.cancel()
    scheduledJobs.delete(req.params.id)
    persistSchedules()
    res.json({ ok: true })
})

server.listen(PORT, '0.0.0.0', () => {
    console.log(`PS Manager Node — http://localhost:${PORT}`)
})
