const express = require('express')
const https   = require('https')

const router = express.Router()

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

router.get('/warranty', async (req, res) => {
    const { serial } = req.query
    if (!serial) return res.status(400).json({ ok: false, error: 'serial requis' })

    try {
        const prod = await httpGet(`https://pcsupport.lenovo.com/us/en/api/v4/mse/getproducts?productId=${serial}`)
        let productId = null, productName = null
        try {
            const j = JSON.parse(prod.body)
            const p = Array.isArray(j) ? j[0] : j
            if (p && p.Id) { productId = p.Id; productName = p.Name }
        } catch {}

        if (!productId) return res.json({ ok: false, error: 'Produit non trouvé pour ce S/N' })

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

module.exports = router
