const https = require('https')
const http  = require('http')
const path  = require('path')
const fs    = require('fs')

function httpFetch(url, binary = false, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
        const mod = url.startsWith('https') ? https : http
        const req = mod.get(url, { headers: { 'User-Agent': 'psmanager-choco/1.0' } }, res => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                req.destroy()
                return httpFetch(res.headers.location, binary, timeoutMs).then(resolve).catch(reject)
            }
            if (binary) {
                const chunks = []
                res.on('data', c => chunks.push(c))
                res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks), headers: res.headers }))
            } else {
                let body = ''
                res.on('data', c => body += c.toString())
                res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }))
            }
            res.on('error', reject)
        })
        req.on('error', reject)
        req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error(`Timeout (${timeoutMs / 1000}s)`)) })
    })
}

async function getLatestVersion(chocoId) {
    const url = `https://community.chocolatey.org/api/v2/Packages()?$filter=tolower(Id)+eq+'${chocoId.toLowerCase()}'+and+IsLatestVersion+eq+true`
    const { body, status } = await httpFetch(url, false, 15000)
    if (status !== 200) throw new Error(`Chocolatey API HTTP ${status}`)
    const m = body.match(/<[a-z]+:Version[^>]*>([^<]+)<\/[a-z]+:Version>/i)
    if (!m) throw new Error(`Package "${chocoId}" non trouvé sur Chocolatey`)
    return m[1].trim()
}

async function downloadInstaller(chocoId, version, destDir) {
    const AdmZip = require('adm-zip')

    // 1. Download .nupkg (follow redirects, 60s timeout)
    const nupkgUrl = `https://community.chocolatey.org/api/v2/package/${chocoId}/${version}`
    const { body: nupkgBuf, status } = await httpFetch(nupkgUrl, true, 60000)
    if (status !== 200) throw new Error(`Téléchargement .nupkg échoué (HTTP ${status})`)

    // 2. Extract chocolateyInstall.ps1 from the .nupkg (ZIP)
    const zip = new AdmZip(nupkgBuf)
    const ps1Entry = zip.getEntries().find(e =>
        e.entryName.toLowerCase().endsWith('chocolateyinstall.ps1'))
    if (!ps1Entry) throw new Error('Script chocolateyInstall.ps1 introuvable dans le package')

    let ps1 = ps1Entry.getData().toString('utf8')
    // Substitute $packageVersion placeholders
    ps1 = ps1.replace(/\$\{?packageVersion\}?/gi, version)
    ps1 = ps1.replace(/\$env:packageVersion/gi, version)

    // 3. Extract installer URL — prefer 64-bit
    const urlPatterns = [
        /\$url64\s*=\s*["']([^"'\r\n]+)["']/i,
        /\$url\s*=\s*["']([^"'\r\n]+)["']/i,
        /\$fileUrl\s*=\s*["']([^"'\r\n]+)["']/i,
        /\$installerUrl\s*=\s*["']([^"'\r\n]+)["']/i,
        /\$downloadUrl\s*=\s*["']([^"'\r\n]+)["']/i,
    ]
    let installerUrl = null
    for (const pattern of urlPatterns) {
        const m = ps1.match(pattern)
        if (m && /^https?:\/\//i.test(m[1])) { installerUrl = m[1]; break }
    }
    if (!installerUrl) throw new Error('URL installeur introuvable dans le script Chocolatey')

    // 4. Download actual installer (5 min timeout for large files)
    const { body: installerBuf, status: dlStatus } = await httpFetch(installerUrl, true, 300000)
    if (dlStatus !== 200) throw new Error(`Téléchargement installeur échoué (HTTP ${dlStatus})`)

    // 5. Determine filename from URL (decode %XX, strip query string)
    const urlPath = installerUrl.split('?')[0]
    let filename = decodeURIComponent(path.basename(urlPath))
    if (!/\.(exe|msi)$/i.test(filename)) filename = `${chocoId}-${version}.exe`

    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true })
    fs.writeFileSync(path.join(destDir, filename), installerBuf)
    return filename
}

module.exports = { getLatestVersion, downloadInstaller }
