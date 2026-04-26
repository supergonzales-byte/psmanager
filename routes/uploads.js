const express = require('express')
const fs      = require('fs')
const path    = require('path')
const { upload }                          = require('../lib/multer')
const { SCRIPTS_DIR, INSTALLERS_DIR, INSTALLER_ARGS_FILE, INSTALLER_META_FILE } = require('../lib/constants')

const router = express.Router()

router.post('/scripts/upload', upload.single('file'), (req, res) => {
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

router.get('/installers', (req, res) => {
    try {
        if (!fs.existsSync(INSTALLERS_DIR)) return res.json([])
        res.json(fs.readdirSync(INSTALLERS_DIR).filter(f => /\.(exe|msi)$/i.test(f)))
    } catch { res.json([]) }
})

router.post('/installers/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ ok: false, error: 'Fichier manquant' })
        const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8')
        if (!/\.(exe|msi)$/i.test(originalName))
            return res.status(400).json({ ok: false, error: 'Seuls les fichiers .exe et .msi sont acceptés' })
        if (!fs.existsSync(INSTALLERS_DIR)) fs.mkdirSync(INSTALLERS_DIR, { recursive: true })
        const dest = path.join(INSTALLERS_DIR, originalName)
        try { fs.renameSync(req.file.path, dest) }
        catch { fs.copyFileSync(req.file.path, dest); fs.unlinkSync(req.file.path) }
        res.json({ ok: true, name: originalName })
    } catch(e) {
        res.status(500).json({ ok: false, error: e.message })
    }
})

router.post('/installers/add-winget', async (req, res) => {
    const winget_id = String((req.body || {}).winget_id || '').trim()
    if (!winget_id) return res.status(400).json({ ok: false, error: 'winget_id requis' })
    const t0 = Date.now()
    console.log('[installers/add-winget] DÉBUT winget_id=%s', winget_id)
    try {
        const { getLatestVersion, downloadInstaller } = require('../lib/winget')
        if (!fs.existsSync(INSTALLERS_DIR)) fs.mkdirSync(INSTALLERS_DIR, { recursive: true })

        const version = await getLatestVersion(winget_id)
        console.log('[installers/add-winget] version=%s', version)
        const filename = await downloadInstaller(winget_id, version, INSTALLERS_DIR)
        console.log('[installers/add-winget] fichier=%s', filename)

        let meta = {}
        try { meta = JSON.parse(fs.readFileSync(INSTALLER_META_FILE, 'utf8')) } catch {}
        meta[filename] = Object.assign(meta[filename] || {}, { winget_id })
        fs.writeFileSync(INSTALLER_META_FILE, JSON.stringify(meta, null, 2))

        console.log('[installers/add-winget] ✓ TERMINÉ en %dms', Date.now()-t0)
        res.json({ ok: true, filename, version, winget_id })
    } catch(e) {
        console.error('[installers/add-winget] ✗ ERREUR après %dms :', Date.now()-t0, e.message)
        console.error(e.stack)
        res.status(500).json({ ok: false, error: e.message })
    }
})

router.get('/installer-args', (req, res) => {
    try {
        if (!fs.existsSync(INSTALLER_ARGS_FILE)) return res.json({})
        res.json(JSON.parse(fs.readFileSync(INSTALLER_ARGS_FILE, 'utf8')))
    } catch { res.json({}) }
})

router.post('/installer-args', (req, res) => {
    const { name, args } = req.body
    if (!name) return res.status(400).json({ ok: false, error: 'Nom requis' })
    try {
        let data = {}
        try { data = JSON.parse(fs.readFileSync(INSTALLER_ARGS_FILE, 'utf8')) } catch {}
        data[name] = args || ''
        fs.writeFileSync(INSTALLER_ARGS_FILE, JSON.stringify(data, null, 2))
        res.json({ ok: true })
    } catch(e) {
        res.status(500).json({ ok: false, error: e.message })
    }
})

// ── Métadonnées installeurs (winget_id, …) ────────────────────────────────

router.get('/installer-meta', (req, res) => {
    try {
        if (!fs.existsSync(INSTALLER_META_FILE)) return res.json({})
        res.json(JSON.parse(fs.readFileSync(INSTALLER_META_FILE, 'utf8')))
    } catch { res.json({}) }
})

router.post('/installer-meta', (req, res) => {
    const { name, winget_id } = req.body
    if (!name) return res.status(400).json({ ok: false, error: 'Nom requis' })
    try {
        let data = {}
        try { data = JSON.parse(fs.readFileSync(INSTALLER_META_FILE, 'utf8')) } catch {}
        if (winget_id) {
            data[name] = Object.assign(data[name] || {}, { winget_id })
        } else {
            if (data[name]) delete data[name].winget_id
            if (data[name] && !Object.keys(data[name]).length) delete data[name]
        }
        fs.writeFileSync(INSTALLER_META_FILE, JSON.stringify(data, null, 2))
        res.json({ ok: true })
    } catch(e) {
        res.status(500).json({ ok: false, error: e.message })
    }
})

// ── Vérification version Winget ───────────────────────────────────────────

router.get('/installer-version-check', async (req, res) => {
    const { id } = req.query
    if (!id) return res.status(400).json({ ok: false, error: 'id requis' })
    const t0 = Date.now()
    console.log('[installer-version-check] DÉBUT id=%s', id)
    try {
        const { getLatestVersion } = require('../lib/winget')
        const version = await getLatestVersion(id)
        console.log('[installer-version-check] ✓ id=%s → %s (%dms)', id, version, Date.now()-t0)
        res.json({ ok: true, version })
    } catch(e) {
        console.error('[installer-version-check] ✗ id=%s après %dms :', id, Date.now()-t0, e.message)
        res.json({ ok: false, error: e.message })
    }
})

// ── Mise à jour automatique depuis Winget ─────────────────────────────────

router.post('/installer-update', async (req, res) => {
    const { filename, winget_id, version: clientVersion } = req.body
    console.log('[installer-update] DÉBUT — filename=%s, winget_id=%s, clientVersion=%s', filename, winget_id, clientVersion)
    if (!filename || !winget_id) return res.status(400).json({ ok: false, error: 'filename et winget_id requis' })
    const t0 = Date.now()
    try {
        const { getLatestVersion, downloadInstaller } = require('../lib/winget')

        const version     = clientVersion || await getLatestVersion(winget_id)
        console.log('[installer-update] version utilisée =', version)
        const newFilename = await downloadInstaller(winget_id, version, INSTALLERS_DIR)
        console.log('[installer-update] fichier téléchargé :', newFilename)

        // Transférer les args sur le nouveau nom de fichier
        let args = {}
        try { args = JSON.parse(fs.readFileSync(INSTALLER_ARGS_FILE, 'utf8')) } catch {}
        if (args[filename] !== undefined) {
            args[newFilename] = args[filename]
            if (filename !== newFilename) delete args[filename]
            fs.writeFileSync(INSTALLER_ARGS_FILE, JSON.stringify(args, null, 2))
        }

        // Transférer les métadonnées
        let meta = {}
        try { meta = JSON.parse(fs.readFileSync(INSTALLER_META_FILE, 'utf8')) } catch {}
        meta[newFilename] = Object.assign(meta[filename] || {}, { winget_id })
        if (filename !== newFilename) delete meta[filename]
        fs.writeFileSync(INSTALLER_META_FILE, JSON.stringify(meta, null, 2))

        // Supprimer l'ancien fichier si le nom a changé
        if (filename !== newFilename) {
            const oldPath = path.join(INSTALLERS_DIR, filename)
            try { if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath) } catch {}
        }

        console.log('[installer-update] ✓ TERMINÉ en %dms', Date.now()-t0)
        res.json({ ok: true, filename: newFilename, version })
    } catch(e) {
        console.error('[installer-update] ✗ ERREUR après %dms :', Date.now()-t0, e.message)
        console.error(e.stack)
        res.status(500).json({ ok: false, error: e.message })
    }
})

module.exports = router
