const { spawn } = require('child_process')
const fs        = require('fs')
const path      = require('path')
const os        = require('os')

// Script PowerShell embarqué — identique à psmanager.pyw
const INVENTORY_SCRIPT = `
param($targetComputer, $username, $password, $logBaseDir)

$secPass = ConvertTo-SecureString $password -AsPlainText -Force
$cred    = New-Object System.Management.Automation.PSCredential($username, $secPass)

function Get-Room {
    param([string]$hostname)
    if ($hostname -match "-([^-]+)-") { return $matches[1] }
    return "Inconnu"
}

try {
    $remoteData = Invoke-Command -ComputerName $targetComputer -Credential $cred -ScriptBlock {
        function Get-InstalledSoftwareFromRegistry {
            param([string]$registryPath)
            if (-not (Test-Path $registryPath)) { return @() }
            Get-ChildItem -Path $registryPath | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath
                [PSCustomObject]@{ Name = $props.DisplayName; Version = $props.DisplayVersion }
            } | Where-Object { $_.Name -and ($_.Name -notmatch "(?i)(update|hotfix|patch|security|KB\\d+)") }
        }
        $hostname  = $env:COMPUTERNAME
        $system    = Get-CimInstance Win32_ComputerSystem
        $product   = Get-CimInstance Win32_ComputerSystemProduct
        $isLenovo  = ($system.Manufacturer -like "*Lenovo*")
        $model     = if ($isLenovo -and $product.Version) { $product.Version } else { $system.Model }
        $ram       = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
        $ramInfo   = Get-CimInstance Win32_PhysicalMemory | Select-Object -First 1
        $ddrMap    = @{20="DDR"; 21="DDR2"; 24="DDR3"; 26="DDR4"; 34="DDR5"}
        $ramType   = if ($ddrMap.ContainsKey([int]$ramInfo.SMBIOSMemoryType)) { $ddrMap[[int]$ramInfo.SMBIOSMemoryType] } else { "DDR?" }
        $ramSpeed  = if ($ramInfo.Speed) { "$ramType $($ramInfo.Speed) MHz" } else { $ramType }
        $sysDrive  = (Get-WmiObject Win32_OperatingSystem).SystemDrive.TrimEnd(':')
        $disk      = Get-Partition -DriveLetter $sysDrive | Get-Disk
        $diskSize  = [math]::Round($disk.Size / 1GB, 2)
        $physDisk  = Get-PhysicalDisk | Where-Object { $_.DeviceID -eq $disk.Number }
        $diskType  = switch ($disk.BusType) {
            "NVMe" { "SSD NVMe" }
            "SATA" { if ($physDisk.MediaType -eq "HDD") { "HDD SATA" } else { "SSD SATA" } }
            default { if ($physDisk.SpindleSpeed -gt 0) { "HDD" } else { "SSD" } }
        }
        $gpus     = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
        $gpuList  = if ($gpus) { ($gpus -join "; ") } else { "Aucune" }
        $bios     = Get-CimInstance Win32_BIOS
        $biosVer  = if ($bios.SMBIOSBIOSVersion) { $bios.SMBIOSBIOSVersion } else { "Inconnu" }
        $os       = Get-CimInstance Win32_OperatingSystem
        $winVer   = "$($os.Caption) Build $($os.BuildNumber)"
        $activeNic = Get-CimInstance Win32_NetworkAdapterConfiguration |
            Where-Object { $_.IPEnabled -eq $true -and $_.DefaultIPGateway } | Select-Object -First 1
        $ipAddr    = if ($activeNic) {
            ($activeNic.IPAddress | Where-Object { $_ -notlike "*:*" }) | Select-Object -First 1
        } else { "Inconnu" }
        $macAddr   = if ($activeNic) { $activeNic.MACAddress } else { "" }
        $cpuName   = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()
        $installDt = (Get-CimInstance Win32_OperatingSystem).InstallDate
        $installDate = if ($installDt) { $installDt.ToString("dd/MM/yyyy") } else { "" }
        $regPaths  = @(
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        )
        $softList = @()
        foreach ($p in $regPaths) { $softList += Get-InstalledSoftwareFromRegistry -registryPath $p }
        $softList = $softList | Sort-Object Name, Version -Unique
        [PSCustomObject]@{
            Hostname = $hostname; Fabricant = $system.Manufacturer; Modele = $model
            Serial   = $product.IdentifyingNumber; WinVer = $winVer; RAM = $ram
            Disque   = $diskSize; TypeDisque = $diskType; GPU = $gpuList
            IP       = $ipAddr; MAC = $macAddr; Date = (Get-Date -Format "dd/MM/yyyy")
            BiosVersion = $biosVer; TypeRAM = $ramSpeed; CPU = $cpuName; InstallDate = $installDate; Logiciels = $softList
        }
    } -ErrorAction Stop

    if (-not $remoteData) { Write-Output "ERROR|Aucune donnee recue"; exit 1 }

    $d = $remoteData

    # Logiciels
    if (-not (Test-Path $logBaseDir)) { New-Item -Path $logBaseDir -ItemType Directory -Force | Out-Null }
    $softLines = $d.Logiciels | ForEach-Object { "$($_.Name)|$($_.Version)" }
    [System.IO.File]::WriteAllLines((Join-Path $logBaseDir "$($d.Hostname).txt"), $softLines, [System.Text.UTF8Encoding]::new($false))

    Write-Output "OK|$($d.Hostname)|$($d.WinVer)|$($d.Fabricant)|$($d.Modele)|$($d.RAM)GB|$($d.TypeDisque)|$($d.IP)|$($d.Serial)|$($d.Disque)|$($d.GPU)|$($d.Date)|$($d.BiosVersion)|$($d.MAC)|$($d.TypeRAM)|$($d.CPU)|$($d.InstallDate)"
}
catch {
    Write-Output "ERROR|$($_.Exception.Message)"
    exit 1
}
`

/**
 * Inventaire d'un seul poste via WinRM
 * Renvoie { ok, hostname, parcLine, display } ou { ok: false, error }
 */
function inventoryOne(addr, username, password, logBaseDir, scriptPath) {
    return new Promise(resolve => {
        const ps = spawn('powershell', [
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', scriptPath,
            '-targetComputer', addr,
            '-username', username,
            '-password', password,
            '-logBaseDir', logBaseDir
        ], { windowsHide: true })

        const timer = setTimeout(() => { ps.kill(); resolve({ ok: false, addr, error: 'TIMEOUT (>60s)' }) }, 60000)

        const stdoutBufs = [], stderrBufs = []
        ps.stdout.on('data', d => stdoutBufs.push(d))
        ps.stderr.on('data', d => stderrBufs.push(d))
        ps.on('close', () => {
            clearTimeout(timer)
            const iconv       = require('iconv-lite')
            const stdoutStr   = iconv.decode(Buffer.concat(stdoutBufs), 'cp850')
            const stderrStr   = iconv.decode(Buffer.concat(stderrBufs), 'cp850')
            const outputLines = stdoutStr.split('\n').map(l => l.trim()).filter(l => l)
            const okLine      = outputLines.find(l => l.startsWith('OK|'))
            if (okLine) {
                const parts    = okLine.split('|')
                const hostname = parts[1]  || addr
                const winver   = parts[2]  || '?'
                const fab      = parts[3]  || '?'
                const modele   = parts[4]  || '?'
                const ram      = parts[5]  || '?'
                const dtype    = parts[6]  || '?'
                const ip       = parts[7]  || addr
                const serial   = parts[8]  || '?'
                const disque   = parts[9]  || '?'
                const gpu      = parts[10] || '?'
                const date     = parts[11] || '?'
                const bios     = parts[12] || '?'
                const mac      = parts[13] || '?'
                const ramtype  = parts[14] || '?'
                const cpu      = parts[15] || '?'
                const installDate = parts[16] || ''
                const parcLine = `${hostname}|${ip}|${fab}|${modele}|${serial}|${winver}|${ram}|${disque}|${dtype}|${gpu}|${date}|${bios}|${mac}|${ramtype}|${cpu}|${installDate}`
                resolve({ ok: true, addr, hostname, parcLine,
                    display: `${hostname} (${ip}) — ${winver} — ${fab} ${modele} — ${ram} RAM — ${dtype}` })
            } else {
                const errLine = outputLines.find(l => l.startsWith('ERROR|'))
                const err     = errLine ? errLine.replace('ERROR|','') : outputLines.slice(0,3).join(' ') || stderrStr.trim().slice(0,150)
                resolve({ ok: false, addr, error: err || 'Erreur inconnue' })
            }
        })
    })
}

/**
 * Inventaire parallèle de plusieurs postes
 * Collecte TOUS les résultats en mémoire, écrit parc.txt UNE SEULE FOIS à la fin
 */
async function runInventory({ targets, username, password, parcFile, logBaseDir, concurrency, onProgress }) {
    // Écrire le script PS dans un fichier temporaire
    const tmpScript = path.join(os.tmpdir(), `psinv_${Date.now()}.ps1`)
    fs.writeFileSync(tmpScript, INVENTORY_SCRIPT, 'utf-8')

    const results  = []   // collecte en mémoire — PAS de touche à parc.txt ici
    let done       = 0
    let okCount    = 0
    let errCount   = 0
    let index      = 0

    async function worker() {
        while (index < targets.length) {
            const addr = targets[index++]
            const res  = await inventoryOne(addr, username, password, logBaseDir, tmpScript)
            done++
            if (res.ok) {
                okCount++
                results.push({ hostname: res.hostname, parcLine: res.parcLine })
            } else {
                errCount++
            }
            onProgress({ done, total: targets.length, ok: okCount, err: errCount, result: res })
        }
    }

    const workers = Array.from({ length: Math.min(concurrency, targets.length) }, worker)
    await Promise.all(workers)

    // ── Écriture UNIQUE de parc.txt après que TOUS les workers sont terminés ──
    try {
        let existing = []
        if (fs.existsSync(parcFile)) {
            existing = fs.readFileSync(parcFile, 'utf-8')
                .split('\n').map(l => l.trim()).filter(l => l)
        }
        for (const { hostname, parcLine } of results) {
            const idx = existing.findIndex(l => l.startsWith(hostname + '|'))
            if (idx >= 0) existing[idx] = parcLine
            else existing.push(parcLine)
        }
        fs.mkdirSync(path.dirname(parcFile), { recursive: true })
        fs.writeFileSync(parcFile, existing.join('\n'), 'utf-8')
    } catch(e) {
        console.error('Erreur écriture parc.txt :', e.message)
    }

    // Nettoyage script temporaire
    try { fs.unlinkSync(tmpScript) } catch {}

    return { ok: okCount, err: errCount }
}

module.exports = { runInventory }
