const express = require('express')
const fs      = require('fs')
const path    = require('path')
const { upload }                                    = require('../lib/multer')
const { DRIVERS_BASE, SCRIPTS_DIR }                 = require('../lib/constants')
const { copyFileToHosts, collectDrivers, deployDrivers } = require('../actions')

const router = express.Router()

let _driversCancelled = false

router.post('/drivers-cancel', (req, res) => {
    _driversCancelled = true
    res.json({ ok: true })
})

router.post('/copy-files', upload.array('files', 500), async (req, res) => {
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
    const dest = destination || 'C:\\Windows\\Temp'

    send('start', { total: hostList.length, fileCount: req.files.length, destination: dest })

    _driversCancelled = false
    const isCancelled = () => _driversCancelled

    let totalOk = 0, totalErr = 0
    for (let i = 0; i < req.files.length; i++) {
        if (isCancelled()) { try { fs.unlinkSync(req.files[i].path) } catch {} ; break }
        const file         = req.files[i]
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8')
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
                isCancelled,
                onProgress : ({ done, total, ok, err, result }) => {
                    send('progress', { done, total, ok, err, pct: Math.round(done / total * 100) })
                    if (result.ok) send('ok',  { hostname: result.hostname, path: result.path })
                    else           send('err', { hostname: result.hostname, error: result.error })
                }
            })
            totalOk  += ok
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

router.post('/collect-drivers', async (req, res) => {
    const { hostname, ip, modele, username, password } = req.body
    if (!hostname || !modele || !username || !password)
        return res.status(400).json({ error: 'Paramètres manquants' })

    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')

    const send = (type, data) => { if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, data })}\n\n`) }
    send('start', { hostname, modele, dest: path.join(DRIVERS_BASE, modele) })

    try {
        const result = await collectDrivers({
            hostname, ip, modele, username, password,
            driversBase: DRIVERS_BASE,
            onProgress : data => send('progress', typeof data === 'object' ? data : { message: data })
        })
        if (result.ok) send('done', { ok: true,  hostname, modele, localDest: result.localDest, fileCount: result.fileCount })
        else           send('done', { ok: false, hostname, error: result.error })
    } catch(e) {
        send('done', { ok: false, hostname, error: e.message })
    } finally { res.end() }
})

router.post('/deploy-drivers', async (req, res) => {
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

    _driversCancelled = false
    const isCancelled = () => _driversCancelled

    try {
        const { ok, err } = await deployDrivers({
            modelePath,
            targets    : hostList,
            username, password,
            concurrency: parseInt(concurrency) || 3,
            isCancelled,
            onProgress : ({ done, total, ok, err, result, fileProgress }) => {
                if (fileProgress) send('file_progress', fileProgress)
                else {
                    send('progress', { done, total, ok, err, pct: Math.round(done / total * 100) })
                    if (result && result.ok)  send('ok',  { hostname: result.hostname, detail: result.detail })
                    else if (result)          send('err', { hostname: result.hostname, error: result.error })
                }
            }
        })
        send('done', { ok, err })
    } catch(e) {
        send('error', { message: e.message })
    } finally { res.end() }
})

router.get('/drivers-models', (req, res) => {
    try {
        if (!fs.existsSync(DRIVERS_BASE)) return res.json([])
        const models = fs.readdirSync(DRIVERS_BASE, { withFileTypes: true })
            .filter(d => d.isDirectory()).map(d => d.name)
        res.json(models)
    } catch { res.json([]) }
})

module.exports = router
