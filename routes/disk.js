const express = require('express')
const fs      = require('fs')
const path    = require('path')
const { PARC_FILE } = require('../lib/constants')

const router = express.Router()

router.post('/disk', async (req, res) => {
    const { hostname, username, password } = req.body
    if (!hostname || !username || !password)
        return res.status(400).json({ ok: false, error: 'Parametres manquants' })

    const { spawn } = require('child_process')
    const psCmd = `
$pw   = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
try {
    Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock {
        $d     = Get-PSDrive C
        $used  = [math]::Round($d.Used/1GB,1)
        $free  = [math]::Round($d.Free/1GB,1)
        $total = $used + $free
        Write-Output "$used|$free|$total"
    } -ErrorAction Stop
} catch { Write-Output "ERROR|$($_.Exception.Message)" }
`
    const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psCmd], { windowsHide: true })
    const bufs = []
    let responded = false
    const timer = setTimeout(() => {
        if (!responded) { responded = true; ps.kill(); res.json({ ok: false, error: 'TIMEOUT' }) }
    }, 12000)
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

router.get('/softs', (req, res) => {
    const { hostname } = req.query
    if (!hostname) return res.status(400).json({ ok: false, error: 'hostname requis' })
    const softFile = path.join(path.dirname(PARC_FILE), 'Logiciels', `${hostname}.txt`)
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

module.exports = router
