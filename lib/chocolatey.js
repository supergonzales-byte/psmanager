const https = require('https')
const http  = require('http')
const path  = require('path')
const fs    = require('fs')

const LOG = (...args) => console.log('[choco]', ...args)

function httpFetch(url, binary = false, timeoutMs = 30000, depth = 0) {
    const t0 = Date.now()
    LOG(`httpFetch → ${url} (binary=${binary}, timeout=${timeoutMs/1000}s, redirect#${depth})`)
    return new Promise((resolve, reject) => {
        const mod = url.startsWith('https') ? https : http
        let settled = false
        const settle = (fn, val) => { if (!settled) { settled = true; fn(val) } }

        const agent = new mod.Agent({ keepAlive: false, timeout: timeoutMs, family: 4 })
        const req = mod.get(url, {
            headers: { 'User-Agent': 'psmanager-choco/1.0' },
            timeout: timeoutMs,
            family: 4,
            agent
        }, res => {
            const dt = Date.now() - t0
            LOG(`httpFetch ← ${url} : HTTP ${res.statusCode} (${dt}ms)`)
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                LOG(`httpFetch ↻ redirect → ${res.headers.location}`)
                res.resume() // drain
                settle(resolve, null) // marquer settled avant de chaîner
                settled = true
                return httpFetch(res.headers.location, binary, timeoutMs, depth + 1).then(resolve).catch(reject)
            }
            if (binary) {
                const chunks = []
                let bytes = 0
                res.on('data', c => { chunks.push(c); bytes += c.length })
                res.on('end', () => {
                    LOG(`httpFetch ✓ ${url} : ${bytes} octets reçus en ${Date.now()-t0}ms`)
                    settle(resolve, { status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers })
                })
            } else {
                let body = ''
                res.on('data', c => body += c.toString())
                res.on('end', () => {
                    LOG(`httpFetch ✓ ${url} : ${body.length} chars reçus en ${Date.now()-t0}ms`)
                    settle(resolve, { status: res.statusCode, body, headers: res.headers })
                })
            }
            res.on('error', e => {
                LOG(`httpFetch ✗ res.error : ${e.code} ${e.message}`)
                settle(reject, e)
            })
        })
        req.on('socket', socket => {
            LOG(`httpFetch — socket assigné, timeout=${socket.timeout}ms`)
            socket.on('lookup', (err, addr, fam) => LOG(`httpFetch — DNS lookup → ${err ? err.message : addr + ' (IPv' + fam + ')'} après ${Date.now()-t0}ms`))
            socket.on('timeout', () => LOG(`httpFetch — socket TIMEOUT event (après ${Date.now()-t0}ms)`))
            socket.on('connect', () => LOG(`httpFetch — socket CONNECT vers ${socket.remoteAddress}:${socket.remotePort} (après ${Date.now()-t0}ms)`))
            socket.on('secureConnect', () => LOG(`httpFetch — socket SECURE CONNECT (après ${Date.now()-t0}ms)`))
            socket.on('close', had => LOG(`httpFetch — socket CLOSE hadError=${had} (après ${Date.now()-t0}ms)`))
        })
        req.on('error', e => {
            LOG(`httpFetch ✗ req.error : ${e.code} ${e.message} (après ${Date.now()-t0}ms)`)
            settle(reject, e)
        })
        req.on('timeout', () => {
            LOG(`httpFetch ⏱ req TIMEOUT event après ${Date.now()-t0}ms (limite ${timeoutMs}ms)`)
            req.destroy(new Error(`Timeout (${timeoutMs / 1000}s)`))
            settle(reject, new Error(`Timeout (${timeoutMs / 1000}s)`))
        })
    })
}

function getRedirectUrl(url, retries = 2) {
    const t0 = Date.now()
    LOG(`getRedirectUrl → ${url} (retries restants : ${retries})`)
    return new Promise((resolve, reject) => {
        const { spawn } = require('child_process')
        const safeUrl = url.replace(/'/g, "''")
        const script = `
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $req = [System.Net.HttpWebRequest]::Create('${safeUrl}')
    $req.Method = 'GET'
    $req.AllowAutoRedirect = $false
    $req.UserAgent = 'psmanager-choco/1.0'
    $req.Timeout = 30000
    $resp = $req.GetResponse()
    Write-Output ('STATUS=' + [int]$resp.StatusCode)
    Write-Output ('LOCATION=' + $resp.Headers['Location'])
    $resp.Close()
} catch {
    if ($_.Exception.Response) {
        $resp = $_.Exception.Response
        Write-Output ('STATUS=' + [int]$resp.StatusCode)
        Write-Output ('LOCATION=' + $resp.Headers['Location'])
        $resp.Close()
    } else {
        Write-Output ('ERR=' + ($_.Exception.Message -replace "[\\r\\n]+"," "))
    }
}
`.trim()
        const ps = spawn('powershell.exe', [
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script
        ], { windowsHide: true })
        let out = '', err = ''
        ps.stdout.on('data', d => out += d.toString())
        ps.stderr.on('data', d => err += d.toString())
        ps.on('close', () => {
            const dt = Date.now() - t0
            const status = out.match(/^STATUS=(\d+)/m)
            const location = out.match(/^LOCATION=(.+)$/m)
            const perr = out.match(/^ERR=(.+)$/m)
            if (status && location && parseInt(status[1], 10) >= 300 && parseInt(status[1], 10) < 400) {
                LOG(`getRedirectUrl ← HTTP ${status[1]} en ${dt}ms, location=${location[1].trim()}`)
                resolve(location[1].trim())
                return
            }
            const msg = perr ? perr[1].trim() : (err.trim() || `Redirection attendue, sortie PowerShell invalide`)
            LOG(`getRedirectUrl ✗ ${msg} (après ${dt}ms)`)
            if (retries > 0) {
                LOG(`getRedirectUrl ↻ retry (${retries-1} restants)`)
                getRedirectUrl(url, retries - 1).then(resolve).catch(reject)
            } else {
                reject(new Error(msg))
            }
        })
        ps.on('error', e => {
            LOG(`getRedirectUrl ✗ spawn ${e.message} (après ${Date.now()-t0}ms)`)
            if (retries > 0) {
                LOG(`getRedirectUrl ↻ retry (${retries-1} restants)`)
                getRedirectUrl(url, retries - 1).then(resolve).catch(reject)
            } else {
                reject(e)
            }
        })
    })
}

async function getLatestNupkgUrl(chocoId) {
    const url = `https://community.chocolatey.org/api/v2/package/${encodeURIComponent(chocoId)}`
    try {
        const result = await getRedirectUrl(url)
        LOG(`getLatestNupkgUrl ✓ ${chocoId} → ${result}`)
        return result
    } catch(e) {
        LOG(`getLatestNupkgUrl ✗ ${chocoId} : ${e.code || ''} ${e.message}`)
        throw new Error(`Package "${chocoId}" non trouvé sur Chocolatey`)
    }
}

async function getVersionNupkgUrl(chocoId, version) {
    const url = `https://community.chocolatey.org/api/v2/package/${encodeURIComponent(chocoId)}/${encodeURIComponent(version)}`
    try {
        const result = await getRedirectUrl(url)
        LOG(`getVersionNupkgUrl ✓ ${chocoId}@${version} → ${result}`)
        return result
    } catch(e) {
        LOG(`getVersionNupkgUrl ✗ ${chocoId}@${version} : ${e.code || ''} ${e.message}`)
        throw new Error(`Version "${version}" introuvable pour le package "${chocoId}"`)
    }
}

function extractVersionFromNupkgUrl(chocoId, nupkgUrl) {
    const filename = decodeURIComponent((nupkgUrl.split('?')[0] || '').split('/').pop() || '')
    const prefixRe = new RegExp(`^${chocoId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\.`, 'i')
    const version = filename.replace(prefixRe, '').replace(/\.nupkg$/i, '')
    if (!version || version === filename) {
        throw new Error(`Version introuvable dans l'URL : ${nupkgUrl}`)
    }
    return version
}

function collectScriptStringVars(ps1) {
    const vars = {}
    const re = /^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['"])(.*?)\2(?:\s*#.*)?\s*$/gm
    let m
    while ((m = re.exec(ps1))) vars[m[1].toLowerCase()] = m[3]
    return vars
}

function substituteScriptVars(str, vars) {
    return str.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (full, braced, plain) => {
        const key = (braced || plain || '').toLowerCase()
        return Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] : full
    })
}

function extractInstallerUrl(ps1) {
    const vars = collectScriptStringVars(ps1)
    const urlPatterns = [
        /(?:\$url64(?:bit)?|\bUrl64\b)\s*=\s*["']([^"'\r\n]+)["']/i,
        /(?:\$url(?:32)?|\bUrl\b)\s*=\s*["']([^"'\r\n]+)["']/i,
        /(?:\$fileUrl|\bFileUrl\b)\s*=\s*["']([^"'\r\n]+)["']/i,
        /(?:\$installerUrl|\bInstallerUrl\b)\s*=\s*["']([^"'\r\n]+)["']/i,
        /(?:\$downloadUrl|\bDownloadUrl\b)\s*=\s*["']([^"'\r\n]+)["']/i,
    ]

    for (const re of urlPatterns) {
        const m = ps1.match(re)
        if (!m) continue
        const resolved = substituteScriptVars(m[1], vars)
        if (/^https?:\/\//i.test(resolved)) return resolved
    }
    return null
}

function extractEmbeddedInstallerRef(ps1) {
    const vars = collectScriptStringVars(ps1)
    const filePatterns = [
        /\bfile64\s*=\s*["']([^"'\r\n]+)["']/i,
        /\bfile\s*=\s*["']([^"'\r\n]+)["']/i,
        /(?:\$file64(?:bit)?|\$file)\s*=\s*["']([^"'\r\n]+)["']/i,
        /Get-Item\s+([^\r\n;]+?\.(?:exe|msi))/i,
    ]

    for (const re of filePatterns) {
        const m = ps1.match(re)
        if (!m) continue
        const resolved = substituteScriptVars(m[1], vars)
            .trim()
            .replace(/^["']|["']$/g, '')
            .replace(/\\/g, '/')
        if (/\.(exe|msi)$/i.test(resolved)) return resolved
    }
    return null
}

function wildcardToRegExp(pattern) {
    const escaped = String(pattern || '')
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.')
    return new RegExp(`^${escaped}$`, 'i')
}

function extractNuspecText(zip) {
    const nuspecEntry = zip.getEntries().find(e => e.entryName.toLowerCase().endsWith('.nuspec'))
    if (!nuspecEntry) return null
    return nuspecEntry.getData().toString('utf8')
}

function decodeXml(str) {
    return String(str || '')
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')
}

function extractInstallDependency(nuspecText) {
    if (!nuspecText) return null
    const depRe = /<dependency\b[^>]*\bid="([^"]+)"[^>]*\bversion="([^"]+)"[^>]*\/?>/ig
    let m
    while ((m = depRe.exec(nuspecText))) {
        const id = decodeXml(m[1]).trim()
        const versionSpec = decodeXml(m[2]).trim()
        if (!/\.install$/i.test(id)) continue
        const versionMatch = versionSpec.match(/(\d+(?:\.\d+)+)/)
        return { id, version: versionMatch ? versionMatch[1] : null }
    }
    return null
}

function ensureFilenameHasVersion(filename, version) {
    if (!filename || !version) return filename
    if (/(\d+(?:\.\d+)+)/.test(filename)) return filename
    const ext = path.extname(filename)
    const base = ext ? filename.slice(0, -ext.length) : filename
    return `${base}-${version}${ext}`
}

// Interroge l'API OData Chocolatey via PowerShell (WinHTTP — respecte les proxies Windows)
function getLatestVersionPS(chocoId) {
    const t0 = Date.now()
    LOG(`getLatestVersionPS('${chocoId}') — DÉBUT`)
    return new Promise((resolve, reject) => {
        const { spawn } = require('child_process')
        const safeId = chocoId.replace(/'/g, "''")
        const script = `
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $url = "https://community.chocolatey.org/api/v2/FindPackagesById()?id='${safeId}'&\`$filter=IsLatestVersion+eq+true&\`$top=1"
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30
    if ($r.Content -match '<d:Version[^>]*>([^<]+)</d:Version>') {
        Write-Output "OK:$($Matches[1])"
    } else {
        Write-Output 'ERR:Version non trouvee dans la reponse XML'
    }
} catch {
    Write-Output ("ERR:" + ($_.Exception.Message -replace "[\r\n]+"," "))
}`.trim()
        const ps = spawn('powershell.exe', [
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script
        ], { windowsHide: true })
        let out = '', err = ''
        ps.stdout.on('data', d => out += d.toString())
        ps.stderr.on('data', d => err += d.toString())
        ps.on('close', () => {
            const dt = Date.now() - t0
            const okMatch  = out.match(/^OK:(.+)/m)
            const errMatch = out.match(/^ERR:(.+)/m)
            if (okMatch) {
                LOG(`getLatestVersionPS ✓ ${chocoId} → ${okMatch[1].trim()} (${dt}ms)`)
                resolve(okMatch[1].trim())
            } else {
                const msg = errMatch ? errMatch[1].trim() : (err.trim() || `PowerShell exit sans résultat`)
                LOG(`getLatestVersionPS ✗ ${chocoId} : ${msg} (${dt}ms)`)
                reject(new Error(msg))
            }
        })
        ps.on('error', e => reject(e))
    })
}

async function getLatestVersion(chocoId) {
    LOG(`getLatestVersion('${chocoId}') — DÉBUT`)
    try {
        const nupkgUrl = await getLatestNupkgUrl(chocoId)
        const version = extractVersionFromNupkgUrl(chocoId, nupkgUrl)
        LOG(`getLatestVersion('${chocoId}') → ${version} (Node.js)`)
        return version
    } catch(nodeErr) {
        LOG(`getLatestVersion Node.js échoué (${nodeErr.message}), fallback PowerShell…`)
        const version = await getLatestVersionPS(chocoId)
        LOG(`getLatestVersion('${chocoId}') → ${version} (PS)`)
        return version
    }
}

// Téléchargement via PowerShell (WinHTTP natif — contourne les bugs réseau Node)
function psDownload(url, destFile, timeoutSec = 300) {
    return new Promise((resolve, reject) => {
        const { spawn } = require('child_process')
        const t0 = Date.now()
        LOG(`psDownload → ${url}`)
        LOG(`            → ${destFile}`)

        const script = `
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Invoke-WebRequest -Uri '${url.replace(/'/g, "''")}' -OutFile '${destFile.replace(/'/g, "''")}' -UseBasicParsing -TimeoutSec ${timeoutSec}
    $sz = (Get-Item -LiteralPath '${destFile.replace(/'/g, "''")}').Length
    Write-Output "OK:$sz"
} catch {
    Write-Output ("ERR:" + ($_.Exception.Message -replace "\`r?\`n"," "))
}
`.trim()

        const ps = spawn('powershell.exe', [
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script
        ], { windowsHide: true })

        let out = '', err = ''
        ps.stdout.on('data', d => out += d.toString())
        ps.stderr.on('data', d => err += d.toString())
        ps.on('close', code => {
            const ok  = out.match(/OK:(\d+)/)
            const kerr = out.match(/ERR:(.+)/)
            if (ok) {
                LOG(`psDownload ✓ ${ok[1]} octets en ${Date.now()-t0}ms`)
                resolve(parseInt(ok[1]))
            } else {
                const msg = kerr ? kerr[1].trim() : (err.trim() || `PowerShell exit ${code}`)
                LOG(`psDownload ✗ ${msg}`)
                reject(new Error(msg))
            }
        })
        ps.on('error', e => { LOG(`psDownload ✗ spawn ${e.message}`); reject(e) })
    })
}

async function downloadInstaller(chocoId, version, destDir, seen = new Set()) {
    LOG(`downloadInstaller('${chocoId}', '${version}', '${destDir}') — DÉBUT`)
    const os     = require('os')
    const AdmZip = require('adm-zip')
    const visitKey = `${String(chocoId).toLowerCase()}@${String(version).toLowerCase()}`
    if (seen.has(visitKey)) throw new Error(`Boucle de dépendance Chocolatey détectée sur ${chocoId}@${version}`)
    seen.add(visitKey)

    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true })

    // 1. Télécharger le .nupkg via PowerShell → fichier temporaire
    const nupkgUrl = await getVersionNupkgUrl(chocoId, version)
    const tmpNupkg = path.join(os.tmpdir(), `psm-${chocoId}-${version}-${Date.now()}.nupkg`)
    LOG(`étape 1/4 — .nupkg`)
    await psDownload(nupkgUrl, tmpNupkg, 120)

    // 2. Lire le script chocolateyInstall.ps1 dans le ZIP
    LOG(`étape 2/4 — parsing ZIP`)
    const zip = new AdmZip(tmpNupkg)
    const ps1Entry = zip.getEntries().find(e =>
        e.entryName.toLowerCase().endsWith('chocolateyinstall.ps1'))
    if (!ps1Entry) {
        const nuspecText = extractNuspecText(zip)
        const dep = extractInstallDependency(nuspecText)
        try { fs.unlinkSync(tmpNupkg) } catch {}
        if (dep && dep.id && dep.version) {
            LOG(`étape 2/4 — package meta détecté, fallback vers dépendance ${dep.id}@${dep.version}`)
            return downloadInstaller(dep.id, dep.version, destDir, seen)
        }
        throw new Error('Script chocolateyInstall.ps1 introuvable dans le package')
    }
    let ps1 = ps1Entry.getData().toString('utf8')
    ps1 = ps1.replace(/\$\{?packageVersion\}?/gi, version)
    ps1 = ps1.replace(/\$env:packageVersion/gi, version)

    // 3. Extraire l'URL de l'installeur (prefer 64-bit)
    LOG(`étape 3/4 — recherche URL installeur`)
    const installerUrl = extractInstallerUrl(ps1)
    if (installerUrl) {
        try { fs.unlinkSync(tmpNupkg) } catch {}
        LOG(`étape 3/4 ✓ URL : ${installerUrl}`)

        // 4. Télécharger le vrai installeur via PowerShell
        const urlPath = installerUrl.split('?')[0]
        let filename = decodeURIComponent(path.basename(urlPath))
        if (!/\.(exe|msi)$/i.test(filename)) filename = `${chocoId}-${version}.exe`
        filename = ensureFilenameHasVersion(filename, version)
        const finalPath = path.join(destDir, filename)

        LOG(`étape 4/4 — installeur → ${filename}`)
        await psDownload(installerUrl, finalPath, 600)
        LOG(`✓ TERMINÉ → ${filename}`)
        return filename
    }

    const embeddedRef = extractEmbeddedInstallerRef(ps1)
    if (!embeddedRef) {
        try { fs.unlinkSync(tmpNupkg) } catch {}
        throw new Error('URL installeur introuvable dans le script Chocolatey')
    }

    const embeddedName = path.basename(embeddedRef)
    const embeddedEntry = embeddedName.includes('*') || embeddedName.includes('?')
        ? zip.getEntries().find(e => wildcardToRegExp(embeddedName).test(path.basename(e.entryName.replace(/\\/g, '/'))))
        : zip.getEntries().find(e => e.entryName.replace(/\\/g, '/').toLowerCase().endsWith('/' + embeddedName.toLowerCase()) || e.entryName.replace(/\\/g, '/').toLowerCase() === embeddedName.toLowerCase())
    if (!embeddedEntry) {
        try { fs.unlinkSync(tmpNupkg) } catch {}
        throw new Error(`Installeur embarqué introuvable dans le package : ${embeddedName}`)
    }

    const finalName = ensureFilenameHasVersion(path.basename(embeddedEntry.entryName.replace(/\\/g, '/')), version)
    const finalPath = path.join(destDir, finalName)
    LOG(`étape 3/4 ✓ installeur embarqué : ${embeddedEntry.entryName}`)
    LOG(`étape 4/4 — extraction installeur → ${finalName}`)
    fs.writeFileSync(finalPath, embeddedEntry.getData())
    try { fs.unlinkSync(tmpNupkg) } catch {}
    LOG(`✓ TERMINÉ → ${finalName}`)
    return finalName
}

module.exports = { getLatestVersion, downloadInstaller }
