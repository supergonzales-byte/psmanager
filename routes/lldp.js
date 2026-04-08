const express = require('express')
const fs      = require('fs')
const path    = require('path')

const router      = express.Router()
const LLDP_SCRIPT = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'lldp-capture.ps1'), 'utf8')

router.post('/lldp', async (req, res) => {
    const { hostname, username, password } = req.body
    if (!hostname || !username || !password)
        return res.status(400).json({ error: 'Parametres manquants' })

    const { spawn } = require('child_process')

    const psCmd = `
$pw   = ConvertTo-SecureString '${password.replace(/'/g,"''")}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${username}', $pw)
$sb   = [scriptblock]::Create(@'
${LLDP_SCRIPT}
'@)
Invoke-Command -ComputerName '${hostname}' -Credential $cred -ScriptBlock $sb -ErrorAction Stop
`
    const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', psCmd], { windowsHide: true })
    const stdoutBufs = [], stderrBufs = []
    let responded = false
    const timer = setTimeout(() => {
        if (!responded) { responded = true; ps.kill(); res.json({ ok: false, error: 'TIMEOUT' }) }
    }, 90000)

    ps.stdout.on('data', d => stdoutBufs.push(d))
    ps.stderr.on('data', d => stderrBufs.push(d))
    ps.on('close', () => {
        clearTimeout(timer)
        if (responded) return
        responded = true
        // pas de fichier temporaire à supprimer
        const iconv   = require('iconv-lite')
        const out     = iconv.decode(Buffer.concat(stdoutBufs), 'cp850')
        const err     = iconv.decode(Buffer.concat(stderrBufs), 'cp850')
        const okLine  = out.split('\n').find(l => l.trim().startsWith('LLDP_OK|'))
        const noneLine= out.split('\n').find(l => l.trim() === 'LLDP_NONE')
        const netErrs = ['cannot be reached','inaccessible','refused','winrm','wsman','access denied']
        if (netErrs.some(e => err.toLowerCase().includes(e)))
            return res.json({ ok: false, error: 'Poste hors ligne ou WinRM inactif' })
        if (okLine) {
            const p = okLine.trim().split('|')
            return res.json({ ok: true,
                switch: p[1]||'N/A', port: p[2]||'N/A', vlan: p[3]||'N/A',
                ip_sw:  p[4]||'N/A', desc: p[5]||'N/A', iface: p[6]||'N/A' })
        }
        if (noneLine) return res.json({ ok: false, error: 'Aucune trame LLDP détectée' })
        res.json({ ok: false, error: (err || out).slice(0, 150) || 'Erreur inconnue' })
    })
})

module.exports = router
