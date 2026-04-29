const express = require('express')
const fs      = require('fs')
const path    = require('path')
const os      = require('os')
const { multerFs }                                                        = require('../lib/multer')
const { listDirectory, downloadFile, downloadDirectory, deleteRemote, mkdirRemote, uploadToRemote } = require('../actions')

const router = express.Router()

router.post('/fs/list', async (req, res) => {
    const { hostname, ip, username, password, path: remotePath } = req.body
    if (!hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    const result = await listDirectory({ hostname, ip, username, password, remotePath })
    res.json(result)
})

router.post('/fs/download', async (req, res) => {
    const { hostname, ip, username, password, path: remotePath, isDir } = req.body
    if (!hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })

    const result = isDir === 'true'
        ? await downloadDirectory({ hostname, ip, username, password, remotePath })
        : await downloadFile({ hostname, ip, username, password, remotePath })
    if (!result.ok) return res.status(500).json({ ok: false, error: result.error })

    const encoded = encodeURIComponent(result.fileName)
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encoded}`)
    res.setHeader('Content-Type', 'application/octet-stream')
    const stream = fs.createReadStream(result.localPath)
    stream.pipe(res)
    stream.on('end',   () => { try { fs.unlinkSync(result.localPath) } catch {} })
    stream.on('error', () => { try { fs.unlinkSync(result.localPath) } catch {} })
})

router.post('/fs/upload', multerFs.single('file'), async (req, res) => {
    const { hostname, ip, username, password, remotePath } = req.body
    if (!req.file || !hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })

    const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8')
    const tmpOriginal  = path.join(os.tmpdir(), `fsul_${Date.now()}_${req.file.filename}`)
    try { fs.renameSync(req.file.path, tmpOriginal) }
    catch { fs.copyFileSync(req.file.path, tmpOriginal); fs.unlinkSync(req.file.path) }

    const result = await uploadToRemote({ hostname, ip, username, password, localPath: tmpOriginal, remotePath, fileName: originalName })
    try { fs.unlinkSync(tmpOriginal) } catch {}
    res.json(result)
})

router.post('/fs/delete', async (req, res) => {
    const { hostname, ip, username, password, path: remotePath, isDir } = req.body
    if (!hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    const result = await deleteRemote({ hostname, ip, username, password, remotePath, isDir: isDir === true || isDir === 'true' })
    res.json(result)
})

router.post('/fs/mkdir', async (req, res) => {
    const { hostname, ip, username, password, remotePath } = req.body
    if (!hostname || !username || !password || !remotePath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    const result = await mkdirRemote({ hostname, ip, username, password, remotePath })
    res.json(result)
})

module.exports = router
