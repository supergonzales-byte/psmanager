const express = require('express')
const fs      = require('fs')
const path    = require('path')
const { PARC_FILE, LOG_BASE }      = require('../lib/constants')
const { generateReport, COL_DEFS } = require('../report')

const router = express.Router()

router.get('/report/cols', (req, res) => res.json(COL_DEFS))

router.post('/report', (req, res) => {
    const { cols } = req.body
    if (!cols || !cols.length) return res.status(400).json({ error: 'Aucune colonne' })
    try {
        const html    = generateReport(PARC_FILE, LOG_BASE, cols)
        const outFile = path.join(path.dirname(PARC_FILE), 'inventaire_postes.html')
        fs.writeFileSync(outFile, html, 'utf-8')
        res.json({ ok: true, file: outFile })
    } catch(e) { res.status(500).json({ error: e.message }) }
})

router.post('/report/csv', (req, res) => {
    const { cols } = req.body
    if (!cols || !cols.length) return res.status(400).json({ error: 'Aucune colonne' })
    try {
        if (!fs.existsSync(PARC_FILE)) return res.status(404).json({ error: 'parc.txt introuvable' })
        const lines = fs.readFileSync(PARC_FILE, 'utf-8').split('\n').map(l => l.trim()).filter(l => l)
        if (!lines.length) return res.status(404).json({ error: 'parc.txt vide' })

        const pcs = lines.map(line => {
            const p = line.split('|')
            return {
                Hostname: p[0]  || '', IP:      p[1]  || '', Marque:  p[2]  || '',
                Modele:   p[3]  || '', Serial:  p[4]  || '', WinVer:  p[5]  || '',
                RAM:      p[6]  || '', Disque:  p[7]  || '', Type:    p[8]  || '',
                GPU:      p[9]  || '', Date:    p[10] || '', Bios:    p[11] || '',
                MAC:      p[12] || '', TypeRAM: p[13] || '', CPU:     p[14] || '',
            }
        })

        const headers = cols.map(k => { const def = COL_DEFS.find(c => c.key === k); return def ? def.label : k })
        const esc = v => { const s = String(v || '').replace(/"/g, '""'); return s.includes(';') || s.includes('"') || s.includes('\n') ? `"${s}"` : s }
        const rows = pcs.map(pc => cols.map(k => {
            if (k === 'RAM')    return esc(pc.RAM    ? pc.RAM    + ' GB' : '')
            if (k === 'Disque') return esc(pc.Disque ? pc.Disque + ' GB' : '')
            return esc(pc[k] || '')
        }).join(';'))

        const csv = '\uFEFF' + [headers.join(';'), ...rows].join('\r\n')
        res.setHeader('Content-Type', 'text/csv; charset=utf-8')
        res.setHeader('Content-Disposition', 'attachment; filename="inventaire.csv"')
        res.send(csv)
    } catch(e) { res.status(500).json({ error: e.message }) }
})

router.get('/rapport', (req, res) => {
    const outFile = path.join(path.dirname(PARC_FILE), 'inventaire_postes.html')
    if (!fs.existsSync(outFile)) return res.status(404).send('Rapport non généré.')
    res.sendFile(outFile)
})

module.exports = router
