'use strict'
const https  = require('https')
const http   = require('http')
const path   = require('path')
const fs     = require('fs')
const crypto = require('crypto')
const { spawn } = require('child_process')

const WINGET_REPO  = 'microsoft/winget-pkgs'
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || ''
const ARCH_PREF    = ['x64', 'x86_64', 'x86', 'neutral', 'arm64']

// ── HTTP GET avec suivi de redirections ──────────────────────────────────────

function httpFetch(url, opts = {}, depth = 0) {
    if (depth > 5) return Promise.reject(new Error('Trop de redirections'))
    const { timeoutMs = 30000, headers = {} } = opts
    return new Promise((resolve, reject) => {
        const mod = url.startsWith('https') ? https : http
        const req = mod.get(url, { headers, timeout: timeoutMs, family: 4 }, res => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                res.resume()
                return httpFetch(res.headers.location, opts, depth + 1).then(resolve).catch(reject)
            }
            const chunks = []
            res.on('data', c => chunks.push(c))
            res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }))
            res.on('error', reject)
        })
        req.on('error', reject)
        req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout (${timeoutMs / 1000}s)`)) })
    })
}

// ── GitHub API ───────────────────────────────────────────────────────────────

function githubGet(apiPath) {
    const url = `https://api.github.com/repos/${WINGET_REPO}/contents/${apiPath}`

    const headers = { 'User-Agent': 'psmanager/1.0', 'Accept': 'application/vnd.github.v3+json' }
    if (GITHUB_TOKEN) headers['Authorization'] = `Bearer ${GITHUB_TOKEN}`
    return httpFetch(url, { headers }).then(r => {
        if (r.status === 404) throw new Error(`Package introuvable dans winget-pkgs : ${apiPath}`)
        if (r.status === 403) throw new Error('Limite de taux GitHub atteinte — définissez la variable GITHUB_TOKEN')
        if (r.status !== 200) throw new Error(`GitHub API HTTP ${r.status} pour : ${apiPath}`)
        return JSON.parse(r.body)
    })
}

function fetchRaw(rawUrl) {
    const headers = { 'User-Agent': 'psmanager/1.0' }
    if (GITHUB_TOKEN) headers['Authorization'] = `Bearer ${GITHUB_TOKEN}`
    return httpFetch(rawUrl, { headers }).then(r => {
        if (r.status !== 200) throw new Error(`Impossible de récupérer le manifest : HTTP ${r.status}`)
        return r.body
    })
}

// ── ID Winget → chemin manifest ──────────────────────────────────────────────
// "Google.Chrome" → "manifests/g/Google/Chrome"
// "Mozilla.Firefox" → "manifests/m/Mozilla/Firefox"

function idToManifestPath(packageId) {
    const parts = packageId.trim().split('.')
    if (parts.length < 2 || !parts[0]) {
        throw new Error(`ID Winget invalide : "${packageId}" — format attendu : Publisher.AppName (ex : Google.Chrome)`)
    }
    const letter = parts[0][0].toLowerCase()
    return `manifests/${letter}/${parts.join('/')}`
}

// ── Comparaison de versions (numérique segment par segment) ──────────────────

function cmpVersions(a, b) {
    const pa = String(a).split('.').map(s => parseInt(s, 10) || 0)
    const pb = String(b).split('.').map(s => parseInt(s, 10) || 0)
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const d = (pa[i] || 0) - (pb[i] || 0)
        if (d) return d
    }
    return 0
}

// ── getLatestVersion ─────────────────────────────────────────────────────────

async function getLatestVersion(packageId) {
    const entries  = await githubGet(idToManifestPath(packageId))
    const versions = entries
        .filter(e => e.type === 'dir' && /^\d/.test(e.name))
        .map(e => e.name)
    if (!versions.length) throw new Error(`Aucune version trouvée pour "${packageId}"`)
    versions.sort(cmpVersions)
    const latest = versions[versions.length - 1]
    return latest
}

// ── Parseur YAML installer ───────────────────────────────────────────────────
// Parse la section Installers: du manifest .installer.yaml de winget-pkgs.
// Seules les propriétés au niveau d'indentation direct (2 espaces) sont lues.
// Les blocs imbriqués (InstallerSwitches, AppsAndFeaturesEntries…) sont ignorés.

function parsePropInto(text, obj) {
    const colon = text.indexOf(':')
    if (colon < 0) return
    const key = text.slice(0, colon).trim()
    const val = text.slice(colon + 1).trim().replace(/^['"]|['"]$/g, '')
    if (key && val) obj[key] = val
}

function parseInstallerYaml(text) {
    const installers = []
    let current      = null
    let inInstallers = false

    for (const rawLine of text.split('\n')) {
        const line = rawLine.replace(/\r$/, '')

        if (/^Installers:\s*$/.test(line)) { inInstallers = true; continue }
        if (!inInstallers) continue

        // Clé non indentée = fin de la section Installers
        if (/^\w/.test(line)) {
            if (current) installers.push(current)
            break
        }

        // Nouvel installeur (liste au niveau 0)
        if (/^- /.test(line)) {
            if (current) installers.push(current)
            current = {}
            parsePropInto(line.slice(2), current)
            continue
        }

        if (!current) continue

        // Propriétés directes de l'installeur = 2 espaces d'indentation exactement
        const indent = (line.match(/^( *)/) || ['', ''])[1].length
        if (indent !== 2) continue  // contenu imbriqué, on ignore
        const prop = line.trimStart()
        if (prop.startsWith('- ')) continue  // liste imbriquée
        parsePropInto(prop, current)
    }
    if (current) installers.push(current)
    return installers
}

function pickBestInstaller(installers) {
    for (const arch of ARCH_PREF) {
        const found = installers.find(i =>
            (i.Architecture || '').toLowerCase() === arch.toLowerCase() && i.InstallerUrl)
        if (found) return found
    }
    return installers.find(i => i.InstallerUrl) || null
}

// ── Vérification SHA256 ──────────────────────────────────────────────────────

function verifySha256(filePath, expected) {
    return new Promise((resolve, reject) => {
        const hash   = crypto.createHash('sha256')
        const stream = fs.createReadStream(filePath)
        stream.on('data', chunk => hash.update(chunk))
        stream.on('end', () => {
            const actual = hash.digest('hex')
            if (actual.toLowerCase() === expected.toLowerCase()) return resolve()
            try { fs.unlinkSync(filePath) } catch {}
            reject(new Error(`SHA256 invalide — attendu : ${expected.slice(0, 16)}…, obtenu : ${actual.slice(0, 16)}…`))
        })
        stream.on('error', reject)
    })
}

// ── Téléchargement via PowerShell (WinHTTP, respecte les proxies Windows) ────

function psDownload(url, destFile, timeoutSec = 300) {
    return new Promise((resolve, reject) => {
        const t0 = Date.now()
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
}`.trim()
        const ps = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { windowsHide: true })
        let out = '', err = ''
        ps.stdout.on('data', d => out += d)
        ps.stderr.on('data', d => err += d)
        ps.on('close', code => {
            const ok   = out.match(/OK:(\d+)/)
            const kerr = out.match(/ERR:(.+)/)
            if (ok) {
                resolve(parseInt(ok[1]))
            } else {
                const msg = kerr ? kerr[1].trim() : (err.trim() || `PowerShell exit ${code}`)
                reject(new Error(msg))
            }
        })
        ps.on('error', reject)
    })
}

// ── Injection de version dans le nom de fichier si absent ────────────────────

function ensureFilenameHasVersion(filename, version) {
    if (!filename || !version) return filename
    if (/\d+(?:\.\d+)+/.test(filename)) return filename
    const ext  = path.extname(filename)
    const base = ext ? filename.slice(0, -ext.length) : filename
    return `${base}-${version}${ext}`
}

// ── downloadInstaller ────────────────────────────────────────────────────────

async function downloadInstaller(packageId, version, destDir) {
    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true })

    const versionPath = `${idToManifestPath(packageId)}/${version}`
    const entries = await githubGet(versionPath)

    const installerEntry = entries.find(e =>
        e.type === 'file' && e.name.toLowerCase().endsWith('.installer.yaml'))
    if (!installerEntry) throw new Error(`Fichier installer.yaml introuvable pour ${packageId}@${version}`)

    const yamlText   = await fetchRaw(installerEntry.download_url)
    const installers = parseInstallerYaml(yamlText)
    if (!installers.length) throw new Error(`Aucun installeur dans le manifest de ${packageId}@${version}`)

    const best = pickBestInstaller(installers)
    if (!best) throw new Error(`Aucun installeur avec URL valide pour ${packageId}@${version}`)

    const urlClean = (best.InstallerUrl || '').split('?')[0]
    const ext      = (best.InstallerType || '').toLowerCase() === 'msi' ? '.msi' : '.exe'
    let   filename = decodeURIComponent(path.basename(urlClean))
    if (!/(\.exe|\.msi)$/i.test(filename)) filename = `${packageId.replace(/\./g, '-')}-${version}${ext}`
    filename = ensureFilenameHasVersion(filename, version)
    const finalPath = path.join(destDir, filename)

    await psDownload(best.InstallerUrl, finalPath, 600)

    if (best.InstallerSha256) await verifySha256(finalPath, best.InstallerSha256)

    return filename
}

module.exports = { getLatestVersion, downloadInstaller }
