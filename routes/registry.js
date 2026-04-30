const express = require('express')
const fs      = require('fs')
const os      = require('os')
const path    = require('path')
const { checkPort5985 } = require('../scan')

const router = express.Router()

const REG_DRIVES = `
        if (!(Test-Path 'HKLM:')) { New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE | Out-Null }
        if (!(Test-Path 'HKCR:')) { New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null }
        if (!(Test-Path 'HKU:'))  { New-PSDrive -Name HKU  -PSProvider Registry -Root HKEY_USERS | Out-Null }
        if (!(Test-Path 'HKCC:')) { New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG | Out-Null }`

const REG_CONV = `$kpPs = $kp -replace '^HKEY_LOCAL_MACHINE','HKLM:' -replace '^HKEY_CURRENT_USER','HKCU:' -replace '^HKEY_CLASSES_ROOT','HKCR:' -replace '^HKEY_USERS','HKU:' -replace '^HKEY_CURRENT_CONFIG','HKCC:'`

function regPs(psScript, timeout = 30000) {
    return new Promise(resolve => {
        const { spawn } = require('child_process')
        const tmp = path.join(os.tmpdir(), `reg_${Date.now()}.ps1`)
        fs.writeFileSync(tmp, '\uFEFF' + psScript, 'utf-8')
        const ps = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', tmp], { windowsHide: true })
        const bufs = [], errs = []
        const timer = setTimeout(() => { ps.kill(); cleanup(); resolve({ ok: false, error: 'TIMEOUT' }) }, timeout)
        ps.stdout.on('data', d => bufs.push(d))
        ps.stderr.on('data', d => errs.push(d))
        ps.on('close', () => {
            clearTimeout(timer); cleanup()
            resolve({ ok: true, out: Buffer.concat(bufs).toString('utf-8').trim() })
        })
        function cleanup() { try { fs.unlinkSync(tmp) } catch {} }
    })
}

async function isReachable(hostname, ip) {
    return checkPort5985(ip || hostname, 5000).catch(() => false)
}

router.post('/reg-list', async (req, res) => {
    const { hostname, ip, username, password, keyPath } = req.body
    if (!hostname || !username || !password || !keyPath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    if (!await isReachable(hostname, ip))
        return res.json({ ok: false, error: 'Poste éteint ou port 5985 fermé' })
    const esc = s => s.replace(/'/g, "''")
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    $result = Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp)
        ${REG_CONV}
        ${REG_DRIVES}
        $out = @{ subkeys = @(); values = @() }
        try {
            $names = @(Get-ChildItem -Path $kpPs -ErrorAction Stop | ForEach-Object { [string]$_.PSChildName }) | Select-Object -First 500
            $out.subkeys = $names
        } catch {}
        try {
            $item = Get-Item -Path $kpPs -ErrorAction Stop
            foreach ($name in $item.GetValueNames()) {
                $kind = $item.GetValueKind($name).ToString()
                $val  = $item.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
                $out.values += @{ name = $name; kind = $kind; value = "$val" }
            }
        } catch {}
        $out | ConvertTo-Json -Depth 3
    } -ArgumentList '${esc(keyPath)}'
    Write-Output $result
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    try {
        const data    = JSON.parse(out)
        const subkeys = Array.isArray(data.subkeys) ? data.subkeys : (data.subkeys ? [data.subkeys] : [])
        const values  = Array.isArray(data.values)  ? data.values  : (data.values  ? [data.values]  : [])
        res.json({ ok: true, subkeys, values })
    } catch { res.json({ ok: false, error: 'Parse error: ' + out.slice(0, 200) }) }
})

router.post('/reg-set', async (req, res) => {
    const { hostname, ip, username, password, keyPath, name, kind, value } = req.body
    if (!hostname || !username || !password || !keyPath || name === undefined)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    if (!await isReachable(hostname, ip))
        return res.json({ ok: false, error: 'Poste éteint ou port 5985 fermé' })
    const esc = s => s.replace(/'/g, "''")
    const kindMap = { String:'String', ExpandString:'ExpandString', Binary:'Binary', DWord:'DWord', QWord:'QWord', MultiString:'MultiString' }
    const psKind  = kindMap[kind] || 'String'
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp, $n, $k, $v)
        ${REG_CONV}
        ${REG_DRIVES}
        if (!(Test-Path $kpPs)) { New-Item -Path $kpPs -Force | Out-Null }
        $existing = (Get-Item $kpPs).GetValueNames()
        if ($existing -contains $n) { Set-ItemProperty -Path $kpPs -Name $n -Value $v }
        else { New-ItemProperty -Path $kpPs -Name $n -PropertyType $k -Value $v -Force | Out-Null }
        Write-Output 'OK'
    } -ArgumentList '${esc(keyPath)}','${esc(name)}','${psKind}','${esc(String(value))}'
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    res.json({ ok: out.includes('OK') })
})

router.post('/reg-delete-value', async (req, res) => {
    const { hostname, ip, username, password, keyPath, name } = req.body
    if (!hostname || !username || !password || !keyPath || name === undefined)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    if (!await isReachable(hostname, ip))
        return res.json({ ok: false, error: 'Poste éteint ou port 5985 fermé' })
    const esc = s => s.replace(/'/g, "''")
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp, $n)
        ${REG_CONV}
        ${REG_DRIVES}
        Remove-ItemProperty -Path $kpPs -Name $n -Force -ErrorAction Stop
        Write-Output 'OK'
    } -ArgumentList '${esc(keyPath)}','${esc(name)}'
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    res.json({ ok: out.includes('OK') })
})

router.post('/reg-delete-key', async (req, res) => {
    const { hostname, ip, username, password, keyPath } = req.body
    if (!hostname || !username || !password || !keyPath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    if (!await isReachable(hostname, ip))
        return res.json({ ok: false, error: 'Poste éteint ou port 5985 fermé' })
    const esc = s => s.replace(/'/g, "''")
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp)
        ${REG_CONV}
        ${REG_DRIVES}
        Remove-Item -Path $kpPs -Recurse -Force -ErrorAction Stop
        Write-Output 'OK'
    } -ArgumentList '${esc(keyPath)}'
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    res.json({ ok: out.includes('OK') })
})

router.post('/reg-create-key', async (req, res) => {
    const { hostname, ip, username, password, keyPath } = req.body
    if (!hostname || !username || !password || !keyPath)
        return res.status(400).json({ ok: false, error: 'Paramètres manquants' })
    if (!await isReachable(hostname, ip))
        return res.json({ ok: false, error: 'Poste éteint ou port 5985 fermé' })
    const esc = s => s.replace(/'/g, "''")
    const ps = `
$pw   = ConvertTo-SecureString '${esc(password)}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('${esc(username)}', $pw)
try {
    Invoke-Command -ComputerName '${esc(hostname)}' -Credential $cred -ScriptBlock {
        param($kp)
        ${REG_CONV}
        ${REG_DRIVES}
        New-Item -Path $kpPs -Force | Out-Null
        Write-Output 'OK'
    } -ArgumentList '${esc(keyPath)}'
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
`
    const { ok, out } = await regPs(ps)
    if (!ok) return res.json({ ok: false, error: 'Timeout' })
    if (out.startsWith('ERROR|')) return res.json({ ok: false, error: out.replace('ERROR|', '') })
    res.json({ ok: out.includes('OK') })
})

module.exports = router
