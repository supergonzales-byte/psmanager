const { spawn } = require('child_process')
const { checkPort5985 } = require('./scan')
const fs        = require('fs')
const path      = require('path')
const os        = require('os')

function normalizeTarget(target) {
    return typeof target === 'string'
        ? { hostname: target, ip: '' }
        : { hostname: target.hostname, ip: target.ip || '' }
}

/**
 * Copie un fichier local vers un ou plusieurs postes distants via WinRM
 * Utilise Copy-Item -ToSession (pas de limite de taille contrairement à Invoke-Command)
 */
async function copyFileToHosts({ filePath, fileName, relPath, destination, targets, username, password, concurrency = 5, isCancelled, onProgress }) {
    const dest         = destination || 'C:\\Windows\\Temp'
    const safeFileName = fileName.replace(/'/g, "''")

    let done = 0, okCount = 0, errCount = 0, index = 0
    const results = []

    async function worker() {
        while (index < targets.length) {
            if (isCancelled && isCancelled()) return
            const { hostname, ip } = normalizeTarget(targets[index++])
            const res = await copyOneFile({ hostname, ip, filePath, fileName: safeFileName, relPath, destination: dest, username, password })
            done++
            if (res.ok) okCount++; else errCount++
            results.push(res)
            onProgress({ done, total: targets.length, ok: okCount, err: errCount, result: res })
        }
    }

    const workers = Array.from({ length: Math.min(concurrency, targets.length) }, worker)
    await Promise.all(workers)
    return { ok: okCount, err: errCount, results }
}

function copyOneFile({ hostname, ip, filePath, fileName, relPath, destination, username, password }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, hostname, error: 'Poste éteint ou WinRM inaccessible' })

        const escapedPw   = password.replace(/'/g, "''")
        const escapedHost = hostname.replace(/'/g, "''")

        const relDir    = relPath ? path.posix.dirname(relPath).replace(/\//g, '\\') : ''
        const remoteDir = (relDir === '' || relDir === '.')
            ? destination
            : path.join(destination, relDir)

        const remoteDirEsc  = remoteDir.replace(/\\/g, '\\\\').replace(/'/g, "''")
        const remoteDestEsc = path.join(remoteDir, fileName).replace(/\\/g, '\\\\').replace(/'/g, "''")
        const srcEsc        = filePath.replace(/\\/g, '\\\\')

        const tmpScript = path.join(os.tmpdir(), `copy_${Date.now()}_${Math.random().toString(36).slice(2)}.ps1`)

        const psScript = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    $sess = New-PSSession -ComputerName '${escapedHost}' -Credential $cred -ErrorAction Stop
    Invoke-Command -Session $sess -ScriptBlock {
        param($d) if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    } -ArgumentList '${remoteDirEsc}'
    Copy-Item -Path '${srcEsc}' -Destination '${remoteDestEsc}' -ToSession $sess -Force -ErrorAction Stop
    Remove-PSSession $sess
    Write-Output "OK|${remoteDestEsc}"
} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
    try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {}
}
`
        fs.writeFileSync(tmpScript, '\uFEFF' + psScript, 'utf-8')

        const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const bufs = [], errBufs = []
        const timer = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, hostname, error: 'TIMEOUT (>60min)' }) }, 3600000)

        ps.stdout.on('data', d => bufs.push(d))
        ps.stderr.on('data', d => errBufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanup()
            const out   = Buffer.concat(bufs).toString('utf8').trim()
            const err   = Buffer.concat(errBufs).toString('utf8').trim()
            const lines = out.split('\n').map(l => l.trim())
            const okLine  = lines.find(l => l.startsWith('OK|'))
            const errLine = lines.find(l => l.startsWith('ERROR|'))
            if (okLine) {
                resolve({ ok: true, hostname, path: okLine.replace('OK|', '') })
            } else {
                const rawErr = errLine ? errLine.replace('ERROR|', '') : (err || out)
                let msg = rawErr.slice(0, 200) || 'Erreur inconnue'
                if (/12152|réponse non valide|invalid response/i.test(msg))       msg = 'WinRM instable (HTTP 12152)'
                else if (/accès refusé|access.?denied|autorisation/i.test(msg))   msg = 'Accès refusé — identifiants invalides'
                else if (/winrm|wsman/i.test(msg))                                msg = 'WinRM non configuré sur ce poste'
                else if (msg.length > 80)                                          msg = msg.slice(0, 80) + '…'
                resolve({ ok: false, hostname, error: msg })
            }
        })

        function cleanup() { try { fs.unlinkSync(tmpScript) } catch {} }
    })
}

/**
 * Aspire les drivers d'un poste distant et les copie dans
 * C:\ps-manager\Drivers\<modele>\ sur le serveur Node
 */
function collectDrivers({ hostname, ip, modele, username, password, driversBase, onProgress }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, hostname, error: 'Poste éteint ou WinRM inaccessible' })

        const escapedPw  = password.replace(/'/g, "''")
        const destOnHost = `C:\\Windows\\Temp\\PSM_Drivers_${hostname}`
        const destEsc    = destOnHost.replace(/\\/g, '\\\\')
        const localDest  = path.join(driversBase, modele)
        const tmpScript  = path.join(os.tmpdir(), `drv_${Date.now()}.ps1`)

        const psScript = `
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock {
        param($dest)
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
        New-Item -Path $dest -ItemType Directory -Force | Out-Null
        Export-WindowsDriver -Online -Destination $dest -ErrorAction Stop | Out-Null
        $files = Get-ChildItem $dest -Recurse -File
        Write-Output "COUNT|$($files.Count)"
        foreach ($f in $files) {
            $rel   = $f.FullName.Substring($dest.Length).TrimStart('\\')
            $bytes = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($f.FullName))
            Write-Output "FILE|$rel|$bytes"
        }
        Write-Output "DONE"
        Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
    } -ArgumentList '${destEsc}' -ErrorAction Stop
} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
}
`
        fs.writeFileSync(tmpScript, psScript, 'utf-8')
        fs.mkdirSync(localDest, { recursive: true })

        const ps    = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const errBufs = []
        const timer   = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, hostname, error: 'TIMEOUT (>60min)' }) }, 3600000)

        let stdoutBuf = '', fileCount = 0, filesDone = 0, writtenCount = 0, hasError = false, errorMsg = ''

        ps.stdout.on('data', d => {
            stdoutBuf += d.toString()
            let nl
            while ((nl = stdoutBuf.indexOf('\n')) !== -1) {
                const line = stdoutBuf.slice(0, nl).trim()
                stdoutBuf  = stdoutBuf.slice(nl + 1)
                if (line.startsWith('COUNT|')) {
                    const m = line.match(/COUNT\|(\d+)/)
                    if (m) { fileCount = parseInt(m[1]); onProgress && onProgress({ current: 0, total: fileCount, message: `${fileCount} fichier(s) à transférer` }) }
                } else if (line.startsWith('ERROR|')) {
                    hasError = true; errorMsg = line.replace('ERROR|', '')
                } else if (line.startsWith('FILE|')) {
                    const firstPipe  = line.indexOf('|')
                    const secondPipe = line.indexOf('|', firstPipe + 1)
                    if (secondPipe === -1) return
                    const relPath = line.slice(firstPipe + 1, secondPipe).replace(/\\/g, path.sep)
                    const base64  = line.slice(secondPipe + 1)
                    try {
                        const outPath = path.join(localDest, relPath)
                        fs.mkdirSync(path.dirname(outPath), { recursive: true })
                        fs.writeFileSync(outPath, Buffer.from(base64, 'base64'))
                        writtenCount++; filesDone++
                        onProgress && onProgress({ current: filesDone, total: fileCount, message: `Transfert ${filesDone}/${fileCount}` })
                    } catch(e) {}
                }
            }
        })
        ps.stderr.on('data', d => errBufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanup()
            if (hasError) {
                let msg = errorMsg.slice(0, 200)
                if (/accès refusé|access.?denied/i.test(msg)) msg = 'Accès refusé — identifiants invalides'
                else if (msg.length > 100)                     msg = msg.slice(0, 100) + '…'
                return resolve({ ok: false, hostname, error: msg })
            }
            if (writtenCount === 0) {
                const iconv  = require('iconv-lite')
                const rawErr = iconv.decode(Buffer.concat(errBufs), 'cp850').slice(0, 200)
                return resolve({ ok: false, hostname, error: rawErr || 'Aucun fichier écrit' })
            }
            resolve({ ok: true, hostname, modele, localDest, fileCount: writtenCount })
        })

        function cleanup() { try { fs.unlinkSync(tmpScript) } catch {} }
    })
}


/**
 * Déploie les drivers d'un dossier local (serveur Node) vers des postes distants
 */
async function deployDrivers({ modelePath, targets, username, password, concurrency = 3, isCancelled, onProgress }) {
    if (!fs.existsSync(modelePath)) throw new Error(`Dossier introuvable : ${modelePath}`)

    const allFiles = []
    function walk(dir) {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name)
            if (entry.isDirectory()) walk(full)
            else allFiles.push(full)
        }
    }
    walk(modelePath)
    if (!allFiles.length) throw new Error('Aucun fichier driver trouvé dans le dossier')

    const destOnHost = 'C:\\Windows\\Temp\\PSM_Deploy_Drivers'
    let done = 0, okCount = 0, errCount = 0, index = 0

    async function worker() {
        while (index < targets.length) {
            if (isCancelled && isCancelled()) return
            const { hostname, ip } = normalizeTarget(targets[index++])
            const res = await deployOneHost({ hostname, ip, allFiles, modelePath, destOnHost, username, password,
                onFileProgress: data => onProgress({ done, total: targets.length, ok: okCount, err: errCount, fileProgress: { ...data, hostname }, result: null })
            })
            done++
            if (res.ok) okCount++; else errCount++
            onProgress({ done, total: targets.length, ok: okCount, err: errCount, result: res })
        }
    }

    const workers = Array.from({ length: Math.min(concurrency, targets.length) }, worker)
    await Promise.all(workers)
    return { ok: okCount, err: errCount }
}

function deployOneHost({ hostname, ip, allFiles, modelePath, destOnHost, username, password, onFileProgress }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, hostname, error: 'Poste éteint ou WinRM inaccessible' })

        const escapedPw  = password.replace(/'/g, "''")
        const escapedHost= hostname.replace(/'/g, "''")
        const destEsc    = destOnHost.replace(/\\/g, '\\\\')
        const tmpDir     = path.join(os.tmpdir(), `deploy_${Date.now()}_${Math.random().toString(36).slice(2)}`)
        fs.mkdirSync(tmpDir, { recursive: true })

        const total = allFiles.length
        onFileProgress && onFileProgress({ current: 0, total, phase: 'init', message: `Connexion à ${hostname}...` })

        let psScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    $sess = New-PSSession -ComputerName '${escapedHost}' -Credential $cred -ErrorAction Stop

    Invoke-Command -Session $sess -ScriptBlock {
        param($dest)
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
        New-Item -Path $dest -ItemType Directory -Force | Out-Null
    } -ArgumentList '${destEsc}'
    Write-Host "SESS_OK"

`
        for (let i = 0; i < allFiles.length; i++) {
            const filePath = allFiles[i]
            const relPath  = path.relative(modelePath, filePath)
            const relEsc   = relPath.split(path.sep).join('\\\\')
            const srcEsc   = filePath.replace(/\\/g, '\\\\')
            const dirDest  = path.dirname(path.join(destOnHost, relPath)).replace(/\\/g, '\\\\')

            psScript += `
    Invoke-Command -Session $sess -ScriptBlock {
        param($d) if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    } -ArgumentList '${dirDest}'
    Copy-Item -Path '${srcEsc}' -Destination '${destEsc}\\${relEsc}' -ToSession $sess -Force -ErrorAction Stop
    Write-Host "FILE_OK|${i + 1}|${total}|${relEsc}"
`
        }

        psScript += `
    Write-Host "PHASE|pnputil"
    $pnp = Invoke-Command -Session $sess -ScriptBlock {
        param($dest)
        $out = & pnputil.exe /add-driver "$dest\\*.inf" /subdirs /install 2>&1 | Out-String
        $out
    } -ArgumentList '${destEsc}'
    Write-Host "PNPUTIL_OK|$pnp"

    Write-Host "PHASE|reenum"
    Invoke-Command -Session $sess -ScriptBlock {
        $devices = Get-PnpDevice | Where-Object { $_.Status -eq 'Error' -or $_.Status -eq 'Unknown' }
        foreach ($dev in $devices) {
            try {
                Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                Enable-PnpDevice  -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-Host "REENUM_OK|$($devices.Count)"
    }
    Write-Host "REENUM_DONE"

    Invoke-Command -Session $sess -ScriptBlock {
        param($dest) Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
    } -ArgumentList '${destEsc}'
    Remove-PSSession $sess

} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
    try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {}
}
`
        const tmpScript = path.join(tmpDir, 'deploy.ps1')
        fs.writeFileSync(tmpScript, psScript, 'utf-8')

        const ps      = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const errBufs = []
        const timer   = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, hostname, error: 'TIMEOUT (>60min)' }) }, 3600000)

        let stdoutBuf = '', hasError = false, errorMsg = ''

        ps.stdout.on('data', d => {
            stdoutBuf += d.toString()
            let nl
            while ((nl = stdoutBuf.indexOf('\n')) !== -1) {
                const line = stdoutBuf.slice(0, nl).trim()
                stdoutBuf  = stdoutBuf.slice(nl + 1)
                if (!line) continue

                if (line === 'SESS_OK') {
                    onFileProgress && onFileProgress({ current: 0, total, phase: 'copy', message: `Connexion OK — copie des fichiers (0/${total})` })
                } else if (line.startsWith('FILE_OK|')) {
                    const p = line.split('|')
                    const current = parseInt(p[1]), tot = parseInt(p[2]), name = p[3] || ''
                    onFileProgress && onFileProgress({ current, total: tot, phase: 'copy', message: `Copie ${current}/${tot} — ${name}` })
                } else if (line.startsWith('PHASE|pnputil')) {
                    onFileProgress && onFileProgress({ current: total, total, phase: 'pnputil', message: 'Installation des drivers via pnputil...' })
                } else if (line.startsWith('PHASE|reenum')) {
                    onFileProgress && onFileProgress({ current: total, total, phase: 'reenum', message: 'Réénumération des périphériques...' })
                } else if (line.startsWith('REENUM_OK|')) {
                    const count = line.split('|')[1] || '0'
                    onFileProgress && onFileProgress({ current: total, total, phase: 'reenum_done', message: `Réénumération terminée — ${count} périphérique(s) traité(s)` })
                } else if (line.startsWith('ERROR|')) {
                    hasError = true; errorMsg = line.replace('ERROR|', '')
                }
            }
        })
        ps.stderr.on('data', d => errBufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanup()
            if (hasError) {
                let msg = errorMsg
                if (/10485760|10572800|désérialisé|MaximumReceivedObjectSize/i.test(msg)) msg = 'Objet trop volumineux pour WinRM'
                else if (/12152|réponse non valide/i.test(msg))                           msg = 'WinRM instable (HTTP 12152)'
                else if (/accès refusé|access.?denied/i.test(msg))                        msg = 'Accès refusé — identifiants invalides'
                else if (msg.length > 120)                                                 msg = msg.slice(0, 120) + '…'
                return resolve({ ok: false, hostname, error: msg })
            }
            resolve({ ok: true, hostname, detail: 'Drivers installés avec succès' })
        })

        function cleanup() {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }) } catch {}
        }
    })
}


// ════════════════════════════════════════════════════════════════
//  EXPLORATEUR DE FICHIERS DISTANT
// ════════════════════════════════════════════════════════════════

/**
 * Liste le contenu d'un dossier distant via WinRM
 * Renvoie { ok, items: [{ isDir, name, size, modified, attributes }] }
 */
function listDirectory({ hostname, ip, username, password, remotePath }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, error: 'Poste éteint ou WinRM inaccessible' })

        const escapedPw   = password.replace(/'/g, "''")
        const escapedHost = hostname.replace(/'/g, "''")
        const escapedPath = remotePath.replace(/'/g, "''")
        const tmpScript   = path.join(os.tmpdir(), `ls_${Date.now()}.ps1`)

        const psScript = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    $items = Invoke-Command -ComputerName '${escapedHost}' -Credential $cred -ScriptBlock {
        param($p)
        if (-not (Test-Path $p)) { Write-Output "ERROR|Chemin introuvable : $p"; exit }
        Get-ChildItem -Path $p -Force -ErrorAction Stop | ForEach-Object {
            "$($_.PSIsContainer)|$($_.Name)|$($_.Length)|$($_.LastWriteTime.ToString('dd/MM/yyyy HH:mm'))|$($_.Attributes)"
        }
    } -ArgumentList '${escapedPath}' -ErrorAction Stop
    foreach ($line in $items) { Write-Output "ITEM|$line" }
    Write-Output "DONE"
} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
}
`
        fs.writeFileSync(tmpScript, '\uFEFF' + psScript, 'utf-8')
        const ps    = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const bufs  = []
        const timer = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, error: 'TIMEOUT' }) }, 15000)

        ps.stdout.on('data', d => bufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanup()
            const out   = Buffer.concat(bufs).toString('utf8')
            const lines = out.split('\n').map(l => l.trim()).filter(l => l)
            const errLine = lines.find(l => l.startsWith('ERROR|'))
            if (errLine) return resolve({ ok: false, error: errLine.replace('ERROR|', '') })
            const items = lines
                .filter(l => l.startsWith('ITEM|'))
                .map(l => {
                    const p = l.replace('ITEM|', '').split('|')
                    return {
                        isDir    : p[0] === 'True',
                        name     : p[1] || '',
                        size     : parseInt(p[2]) || 0,
                        modified : p[3] || '',
                        attr     : p[4] || ''
                    }
                })
                .sort((a, b) => {
                    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1
                    return a.name.localeCompare(b.name)
                })
            resolve({ ok: true, items })
        })

        function cleanup() { try { fs.unlinkSync(tmpScript) } catch {} }
    })
}


/**
 * Télécharge un fichier distant vers le serveur Node (tmp) via Copy-Item -FromSession
 * Renvoie { ok, localPath, fileName } — le serveur Node streame ensuite localPath vers le navigateur
 */
function downloadFile({ hostname, ip, username, password, remotePath }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, error: 'Poste éteint ou WinRM inaccessible' })

        const escapedPw   = password.replace(/'/g, "''")
        const escapedHost = hostname.replace(/'/g, "''")
        const escapedSrc  = remotePath.replace(/'/g, "''")
        const fileName    = path.basename(remotePath)
        const localTmp    = path.join(os.tmpdir(), `psmdl_${Date.now()}_${fileName}`)
        const localTmpEsc = localTmp.replace(/\\/g, '\\\\')
        const tmpScript   = path.join(os.tmpdir(), `dl_${Date.now()}.ps1`)

        const psScript = `
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    $sess = New-PSSession -ComputerName '${escapedHost}' -Credential $cred -ErrorAction Stop
    Copy-Item -Path '${escapedSrc}' -Destination '${localTmpEsc}' -FromSession $sess -Force -ErrorAction Stop
    Remove-PSSession $sess
    Write-Output "OK"
} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
    try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {}
}
`
        fs.writeFileSync(tmpScript, '\uFEFF' + psScript, 'utf-8')
        const ps    = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const bufs  = []
        // Pas de limite de timeout pour les gros fichiers — on laisse tourner
        const timer = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, error: 'TIMEOUT (>60min)' }) }, 3600000)

        ps.stdout.on('data', d => bufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanup()
            const out   = Buffer.concat(bufs).toString('utf8').trim()
            if (out === 'OK') {
                resolve({ ok: true, localPath: localTmp, fileName })
            } else {
                const errLine = out.split('\n').find(l => l.startsWith('ERROR|'))
                let msg = errLine ? errLine.replace('ERROR|', '') : out
                if (/accès refusé|access.?denied/i.test(msg)) msg = 'Accès refusé — identifiants invalides'
                else if (msg.length > 150) msg = msg.slice(0, 150) + '…'
                resolve({ ok: false, error: msg })
            }
        })

        function cleanup() { try { fs.unlinkSync(tmpScript) } catch {} }
    })
}


/**
 * Supprime un fichier ou dossier sur un poste distant
 */
function deleteRemote({ hostname, ip, username, password, remotePath, isDir }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, error: 'Poste éteint ou WinRM inaccessible' })

        const escapedPw   = password.replace(/'/g, "''")
        const escapedHost = hostname.replace(/'/g, "''")
        const escapedPath = remotePath.replace(/'/g, "''")
        const removeCmd   = isDir
            ? `Remove-Item -Path '${escapedPath}' -Recurse -Force -ErrorAction Stop`
            : `Remove-Item -Path '${escapedPath}' -Force -ErrorAction Stop`

        const tmpScript = path.join(os.tmpdir(), `rm_${Date.now()}.ps1`)
        const psScript  = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    Invoke-Command -ComputerName '${escapedHost}' -Credential $cred -ScriptBlock {
        param($p, $isDir)
        if ($isDir) { Remove-Item -Path $p -Recurse -Force -ErrorAction Stop }
        else        { Remove-Item -Path $p -Force -ErrorAction Stop }
    } -ArgumentList '${escapedPath}', $${isDir ? 'true' : 'false'} -ErrorAction Stop
    Write-Output "OK"
} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
}
`
        fs.writeFileSync(tmpScript, '\uFEFF' + psScript, 'utf-8')
        const ps    = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const bufs  = []
        const timer = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, error: 'TIMEOUT' }) }, 30000)

        ps.stdout.on('data', d => bufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanup()
            const out   = Buffer.concat(bufs).toString('utf8').trim()
            if (out === 'OK') return resolve({ ok: true })
            const errLine = out.split('\n').find(l => l.startsWith('ERROR|'))
            let msg = errLine ? errLine.replace('ERROR|', '') : out
            if (/accès refusé|access.?denied/i.test(msg)) msg = 'Accès refusé — identifiants invalides'
            else if (msg.length > 150) msg = msg.slice(0, 150) + '…'
            resolve({ ok: false, error: msg })
        })

        function cleanup() { try { fs.unlinkSync(tmpScript) } catch {} }
    })
}


/**
 * Crée un dossier sur un poste distant
 */
function mkdirRemote({ hostname, ip, username, password, remotePath }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, error: 'Poste éteint ou WinRM inaccessible' })

        const escapedPw   = password.replace(/'/g, "''")
        const escapedHost = hostname.replace(/'/g, "''")
        const escapedPath = remotePath.replace(/'/g, "''")
        const tmpScript   = path.join(os.tmpdir(), `mkdir_${Date.now()}.ps1`)

        const psScript = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    Invoke-Command -ComputerName '${escapedHost}' -Credential $cred -ScriptBlock {
        param($p)
        if (Test-Path $p) { Write-Output "ERROR|Le dossier existe déjà" }
        else { New-Item -Path $p -ItemType Directory -Force | Out-Null; Write-Output "OK" }
    } -ArgumentList '${escapedPath}' -ErrorAction Stop
} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
}
`
        fs.writeFileSync(tmpScript, '\uFEFF' + psScript, 'utf-8')
        const ps    = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const bufs  = []
        const timer = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, error: 'TIMEOUT' }) }, 15000)

        ps.stdout.on('data', d => bufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanup()
            const out   = Buffer.concat(bufs).toString('utf8').trim()
            const lines = out.split('\n').map(l => l.trim())
            const okLine  = lines.find(l => l === 'OK')
            const errLine = lines.find(l => l.startsWith('ERROR|'))
            if (okLine) return resolve({ ok: true })
            let msg = errLine ? errLine.replace('ERROR|', '') : out
            if (msg.length > 150) msg = msg.slice(0, 150) + '…'
            resolve({ ok: false, error: msg })
        })

        function cleanup() { try { fs.unlinkSync(tmpScript) } catch {} }
    })
}


/**
 * Upload un fichier local (sur le serveur Node) vers un dossier distant
 * Réutilise Copy-Item -ToSession — aucune limite de taille
 */
function uploadToRemote({ hostname, ip, username, password, localPath, remotePath, fileName }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, error: 'Poste éteint ou WinRM inaccessible' })

        const escapedPw   = password.replace(/'/g, "''")
        const escapedHost = hostname.replace(/'/g, "''")

        // Nom de fichier final sur le poste distant — utilise fileName si fourni, sinon basename du localPath
        const destFileName  = fileName || path.basename(localPath)
        const remoteDir     = remotePath.replace(/\\+$/, '')
        const remoteFile    = remoteDir + '\\' + destFileName

        const escapedDir  = remoteDir.replace(/'/g, "''").replace(/\\/g, '\\\\')
        const escapedFile = remoteFile.replace(/'/g, "''").replace(/\\/g, '\\\\')
        const escapedSrc  = localPath.replace(/\\/g, '\\\\')
        const tmpScript   = path.join(os.tmpdir(), `ul_${Date.now()}.ps1`)

        const psScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    $sess = New-PSSession -ComputerName '${escapedHost}' -Credential $cred -ErrorAction Stop
    Invoke-Command -Session $sess -ScriptBlock {
        param($d) if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    } -ArgumentList '${escapedDir}'
    Copy-Item -Path '${escapedSrc}' -Destination '${escapedFile}' -ToSession $sess -Force -ErrorAction Stop
    Remove-PSSession $sess
    Write-Output "OK"
} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
    try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {}
}
`
        fs.writeFileSync(tmpScript, '\uFEFF' + psScript, 'utf8')
        const ps    = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const bufs  = []
        const timer = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, error: 'TIMEOUT (>60min)' }) }, 3600000)

        ps.stdout.on('data', d => bufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanup()
            const out   = Buffer.concat(bufs).toString('utf8').trim()
            if (out === 'OK') return resolve({ ok: true })
            const errLine = out.split('\n').find(l => l.startsWith('ERROR|'))
            let msg = errLine ? errLine.replace('ERROR|', '') : out
            if (/accès refusé|access.?denied/i.test(msg)) msg = 'Accès refusé — identifiants invalides'
            else if (msg.length > 150) msg = msg.slice(0, 150) + '…'
            resolve({ ok: false, error: msg })
        })

        function cleanup() { try { fs.unlinkSync(tmpScript) } catch {} }
    })
}


/**
 * Télécharge un dossier distant vers le serveur Node (tmp) via Copy-Item -FromSession -Recurse
 * Zippe le résultat avec archiver, retourne { ok, localPath, fileName }
 * Le zip tmp est nettoyé par le caller après stream
 */
function downloadDirectory({ hostname, ip, username, password, remotePath }) {
    return new Promise(async resolve => {
        const alive = await checkPort5985(ip || hostname, 1500).catch(() => false)
        if (!alive) return resolve({ ok: false, error: 'Poste éteint ou WinRM inaccessible' })

        const dirName   = path.basename(remotePath)
        const tmpDir    = path.join(os.tmpdir(), `psmdldir_${Date.now()}_${dirName}`)
        const tmpZip    = path.join(os.tmpdir(), `psmdlzip_${Date.now()}_${dirName}.zip`)
        const tmpDirEsc = tmpDir.replace(/\\/g, '\\\\')
        const tmpScript = path.join(os.tmpdir(), `dldir_${Date.now()}.ps1`)

        const escapedPw   = password.replace(/'/g, "''")
        const escapedHost = hostname.replace(/'/g, "''")
        const escapedSrc  = remotePath.replace(/'/g, "''")

        const psScript = `
$pw   = ConvertTo-SecureString '${escapedPw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    $sess = New-PSSession -ComputerName '${escapedHost}' -Credential $cred -ErrorAction Stop
    Copy-Item -Path '${escapedSrc}' -Destination '${tmpDirEsc}' -FromSession $sess -Recurse -Force -ErrorAction Stop
    Remove-PSSession $sess
    Write-Output "OK"
} catch {
    Write-Output "ERROR|$($_.Exception.Message)"
    try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {}
}
`
        fs.writeFileSync(tmpScript, '\uFEFF' + psScript, 'utf-8')
        const ps    = spawn('powershell', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmpScript], { windowsHide: true })
        const bufs  = []
        const timer = setTimeout(() => { ps.kill(); cleanupScript(); resolve({ ok: false, error: 'TIMEOUT (>60min)' }) }, 3600000)

        ps.stdout.on('data', d => bufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            cleanupScript()
            const out = Buffer.concat(bufs).toString('utf8').trim()
            if (out !== 'OK') {
                const errLine = out.split('\n').find(l => l.startsWith('ERROR|'))
                let msg = errLine ? errLine.replace('ERROR|', '') : out
                if (/accès refusé|access.?denied/i.test(msg)) msg = 'Accès refusé — identifiants invalides'
                else if (msg.length > 150) msg = msg.slice(0, 150) + '…'
                return resolve({ ok: false, error: msg })
            }

            const archiver = require('archiver')
            const output   = fs.createWriteStream(tmpZip)
            const archive  = archiver('zip', { zlib: { level: 6 } })

            output.on('close', () => {
                cleanupTmpDir()
                resolve({ ok: true, localPath: tmpZip, fileName: dirName + '.zip', isZip: true })
            })
            archive.on('error', err => {
                cleanupTmpDir()
                resolve({ ok: false, error: err.message })
            })

            archive.pipe(output)
            archive.directory(tmpDir, dirName)
            archive.finalize()
        })

        function cleanupScript()  { try { fs.unlinkSync(tmpScript) } catch {} }
        function cleanupTmpDir()  { try { fs.rmSync(tmpDir, { recursive: true, force: true }) } catch {} }
    })
}


module.exports = { copyFileToHosts, collectDrivers, deployDrivers, listDirectory, downloadFile, downloadDirectory, deleteRemote, mkdirRemote, uploadToRemote }
