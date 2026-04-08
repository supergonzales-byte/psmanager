const { checkPort5985 } = require('../scan')

async function runOneScript(scriptPath, target, hostname, username, password) {
    const alive = await checkPort5985(target, 5000).catch(() => false)
    if (!alive) return { ok: false, hostname: hostname || target, output: '', error: 'ERR_OFFLINE: Poste éteint ou 5985 fermé' }

    return new Promise(resolve => {
        const { spawn } = require('child_process')

        const escapedPassword = password.replace(/'/g, "''")
        const escapedPath     = scriptPath.replace(/\\/g, '\\\\').replace(/'/g, "''")

        const psCmd = `
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            $ErrorActionPreference = 'Stop'

            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect('${target}', 5985, $null, $null)
                if (-not $connect.AsyncWaitHandle.WaitOne(5000, $false)) {
                    throw "OFFLINE"
                }
                $tcp.EndConnect($connect)
                $tcp.Close()

                $secPass = ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential('${username}', $secPass)

                $result = Invoke-Command -ComputerName '${target}' -Credential $cred -FilePath '${escapedPath}' -ErrorAction Stop

                if ($result) { $result | Out-String } else { "OK (Aucun retour)" }

            } catch {
                $m = $_.Exception.Message
                if ($m -eq "OFFLINE") {
                    "ERR_OFFLINE: Poste éteint ou 5985 fermé"
                }
                elseif ($m -like "*Accès refusé*" -or $m -like "*Access is denied*" -or $m -like "*Autorisation refusée*") {
                    "ERR_AUTH: Identifiants invalides"
                }
                elseif ($m -like "*12152*" -or $m -like "*non valide*") {
                    "ERR_WINRM: Service instable (Erreur HTTP 12152)"
                }
                elseif ($m -like "*WinRM*") {
                    "ERR_CONFIG: WinRM non configuré sur la cible"
                }
                else {
                    "ERR_GENERAL: " + $m.Split("\`n")[0].Trim()
                }
            }
        `

        const ps = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psCmd], { windowsHide: true })
        let stdout = '', stderr = ''

        ps.stdout.on('data', data => { stdout += data.toString() })
        ps.stderr.on('data', data => { stderr += data.toString() })
        ps.on('close', () => {
            const output = stdout.trim()
            if (output.startsWith('ERR_')) {
                resolve({ ok: false, hostname: hostname || target, output: '', error: output })
            } else if (output) {
                resolve({ ok: true, hostname: hostname || target, output, error: '' })
            } else {
                resolve({ ok: false, hostname: hostname || target, output: '', error: stderr.trim().substring(0, 100) || 'Délai d\'attente dépassé' })
            }
        })
    })
}

module.exports = { runOneScript }
