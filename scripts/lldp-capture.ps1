#region PSDiscoveryProtocol Module Code

class DiscoveryProtocolPacket {
    [string]$MachineName
    [datetime]$TimeCreated
    [int]$FragmentSize
    [byte[]]$Fragment
    [int]$MiniportIfIndex
    [string]$Connection
    [string]$Interface

    DiscoveryProtocolPacket([PSCustomObject]$WinEvent) {
        $this.MachineName = $WinEvent.MachineName
        $this.TimeCreated = $WinEvent.TimeCreated
        $this.FragmentSize = $WinEvent.FragmentSize
        $this.Fragment = $WinEvent.Fragment
        $this.MiniportIfIndex = $WinEvent.MiniportIfIndex
        $this.Connection = $WinEvent.Connection
        $this.Interface = $WinEvent.Interface

        Add-Member -InputObject $this -MemberType ScriptProperty -Name IsDiscoveryProtocolPacket -Value {
            if (
                [UInt16]0x2000 -eq [BitConverter]::ToUInt16($this.Fragment[21..20], 0) -or
                [UInt16]0x88CC -eq [BitConverter]::ToUInt16($this.Fragment[13..12], 0)
            ) { return [bool]$true } else { return [bool]$false }
        }

        Add-Member -InputObject $this -MemberType ScriptProperty -Name DiscoveryProtocolType -Value {
            if ([UInt16]0x2000 -eq [BitConverter]::ToUInt16($this.Fragment[21..20], 0)) {
                return [string]'CDP'
            }
            elseif ([UInt16]0x88CC -eq [BitConverter]::ToUInt16($this.Fragment[13..12], 0)) {
                return [string]'LLDP'
            }
            else {
                return [string]::Empty
            }
        }

        Add-Member -InputObject $this -MemberType ScriptProperty -Name SourceAddress -Value {
            [PhysicalAddress]::new($this.Fragment[6..11]).ToString()
        }
    }
}

function Invoke-DiscoveryProtocolCapture {
    [CmdletBinding(DefaultParametersetName = 'LocalCapture')]
    [OutputType('DiscoveryProtocolPacket')]
    param(
        [Parameter(ParameterSetName = 'RemoteCapture', Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CN', 'Computer')]
        [String[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = 'LocalCapture', Position = 0)]
        [Parameter(ParameterSetName = 'RemoteCapture', Position = 1)]
        [Int16]$Duration = $(if ($Type -eq 'LLDP') { 32 } else { 62 }),

        [Parameter(ParameterSetName = 'LocalCapture', Position = 1)]
        [Parameter(ParameterSetName = 'RemoteCapture', Position = 2)]
        [ValidateSet('CDP', 'LLDP')]
        [String]$Type,

        [Parameter(ParameterSetName = 'RemoteCapture')]
        [ValidateNotNull()]
        [System.Management.Automation.Credential()]
        [PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
        [switch]$NoCleanup,

        [Parameter()]
        [switch]$Force
    )

    begin {
        if ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
            $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal $Identity
            if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                throw 'Invoke-DiscoveryProtocolCapture requires elevation. Please run PowerShell as administrator.'
            }
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            if ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
                $CimSession = @{}
                $PSSession = @{}
            }

            $ETLFilePath = Invoke-Command @PSSession -ScriptBlock {
                $TempFile = New-TemporaryFile
                $ETLFile = Rename-Item -Path $TempFile.FullName -NewName $TempFile.FullName.Replace('.tmp', '.etl') -PassThru
                $ETLFile.FullName
            }

            $Adapters = Get-NetAdapter @CimSession | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceType -eq 6 } | Select-Object Name, MacAddress, InterfaceDescription, InterfaceIndex

            if ($Adapters) {
                $MACAddresses = $Adapters.MacAddress.ForEach({ [PhysicalAddress]::Parse($_).ToString() })
                $SessionName = 'Capture-{0}' -f (Get-Date).ToString('s')

                if ($Force.IsPresent) {
                    Get-NetEventSession @CimSession | ForEach-Object {
                        if ($_.SessionStatus -eq 'Running') {
                            $_ | Stop-NetEventSession @CimSession
                        }
                        $_ | Remove-NetEventSession @CimSession
                    }
                }

                try {
                    New-NetEventSession -Name $SessionName -LocalFilePath $ETLFilePath -CaptureMode SaveToFile @CimSession -ErrorAction Stop | Out-Null
                }
                catch [Microsoft.Management.Infrastructure.CimException] {
                    if ($_.Exception.NativeErrorCode -eq 'AlreadyExists') {
                        $Message = "Another NetEventSession already exists. Run with -Force to remove existing NetEventSessions."
                        Write-Error -Message $Message
                    }
                    else {
                        Write-Error -ErrorRecord $_ 
                    }
                    continue
                }

                $LinkLayerAddress = switch ($Type) {
                    'CDP' { '01-00-0c-cc-cc-cc' }
                    'LLDP' { '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                    Default { '01-00-0c-cc-cc-cc', '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                }

                $PacketCaptureParams = @{
                    SessionName      = $SessionName
                    TruncationLength = 0
                    CaptureType      = 'Physical'
                    LinkLayerAddress = $LinkLayerAddress
                }

                Add-NetEventPacketCaptureProvider @PacketCaptureParams @CimSession | Out-Null

                foreach ($Adapter in $Adapters) {
                    Add-NetEventNetworkAdapter -Name $Adapter.Name -PromiscuousMode $True @CimSession | Out-Null
                }

                Start-NetEventSession -Name $SessionName @CimSession

                $Seconds = $Duration
                $End = (Get-Date).AddSeconds($Seconds)
                while ($End -gt (Get-Date)) {
                    $SecondsLeft = $End.Subtract((Get-Date)).TotalSeconds
                    $Percent = ($Seconds - $SecondsLeft) / $Seconds * 100
                    Write-Progress -Activity "Discovery Protocol Packet Capture" -Status "Capturing on $Computer..." -SecondsRemaining $SecondsLeft -PercentComplete $Percent
                    [System.Threading.Thread]::Sleep(500)
                }

                Stop-NetEventSession -Name $SessionName @CimSession

                $Events = Invoke-Command @PSSession -ScriptBlock {
                    param($ETLFilePath)

                    try {
                        $Events = Get-WinEvent -Path $ETLFilePath -Oldest -FilterXPath "*[System[EventID=1001]]" -ErrorAction Stop
                    }
                    catch {
                        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                            Write-Error -ErrorRecord $_ 
                        }
                    }

                    [string[]]$XpathQueries = @(
                        "Event/EventData/Data[@Name='FragmentSize']"
                        "Event/EventData/Data[@Name='Fragment']"
                        "Event/EventData/Data[@Name='MiniportIfIndex']"
                    )

                    $PropertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($XpathQueries)

                    foreach ($WinEvent in $Events) {
                        $EventData = $WinEvent | Select-Object MachineName, TimeCreated
                        $EventData | Add-Member -NotePropertyName FragmentSize -NotePropertyValue $null
                        $EventData | Add-Member -NotePropertyName Fragment -NotePropertyValue $null
                        $EventData | Add-Member -NotePropertyName MiniportIfIndex -NotePropertyValue $null
                        $EventData.FragmentSize, $EventData.Fragment, $EventData.MiniportIfIndex = $WinEvent.GetPropertyValues($PropertySelector)
                        $Adapter = @(Get-NetAdapter).Where({ $_.InterfaceIndex -eq $EventData.MiniportIfIndex })
                        $EventData | Add-Member -NotePropertyName Connection -NotePropertyValue $Adapter.Name
                        $EventData | Add-Member -NotePropertyName Interface -NotePropertyValue $Adapter.InterfaceDescription
                        $EventData
                    }
                } -ArgumentList $ETLFilePath

                $FoundPackets = $Events -as [DiscoveryProtocolPacket[]] | Where-Object {
                    $_.IsDiscoveryProtocolPacket -and $_.SourceAddress -notin $MACAddresses
                } | Group-Object MiniportIfIndex | ForEach-Object {
                    $_.Group | Select-Object -First 1
                }

                Remove-NetEventSession -Name $SessionName @CimSession

                if (-not $NoCleanup.IsPresent) {
                    Invoke-Command @PSSession -ScriptBlock {
                        param($ETLFilePath)
                        Remove-Item -Path $ETLFilePath -Force
                    } -ArgumentList $ETLFilePath
                }

                if ($FoundPackets) {
                    $FoundPackets
                }
                else {
                    Write-Warning "No discovery protocol packets captured on $Computer in $Seconds seconds."
                    return
                }
            }
            else {
                Write-Warning "Unable to find a connected wired adapter on $Computer."
                return
            }
        }
    }
}

function Get-DiscoveryProtocolData {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [DiscoveryProtocolPacket[]]$Packet
    )

    process {
        foreach ($Item in $Packet) {
            switch ($Item.DiscoveryProtocolType) {
                'CDP' { $PacketData = ConvertFrom-CDPPacket -Packet $Item.Fragment }
                'LLDP' { $PacketData = ConvertFrom-LLDPPacket -Packet $Item.Fragment }
                Default { throw 'No valid CDP or LLDP found in $Packet' }
            }

            $PacketData | Add-Member -NotePropertyName Computer -NotePropertyValue $Item.MachineName
            $PacketData | Add-Member -NotePropertyName Connection -NotePropertyValue $Item.Connection
            $PacketData | Add-Member -NotePropertyName Interface -NotePropertyValue $Item.Interface
            $PacketData | Add-Member -NotePropertyName Type -NotePropertyValue $Item.DiscoveryProtocolType
            $PacketData
        }
    }
}

function ConvertFrom-LLDPPacket {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [byte[]]$Packet
    )

    begin {
        $TlvType = @{
            EndOfLLDPDU          = 0
            ChassisId            = 1
            PortId               = 2
            TimeToLive           = 3
            PortDescription      = 4
            SystemName           = 5
            SystemDescription    = 6
            ManagementAddress    = 8
            OrganizationSpecific = 127
        }
    }

    process {
        $Offset = 14
        $Mask = 0x01FF
        $Hash = @{}

        while ($Offset -lt $Packet.Length) {
            $Type = $Packet[$Offset] -shr 1
            $Length = [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0) -band $Mask
            $Offset += 2

            switch ($Type) {
                $TlvType.ChassisId {
                    $Subtype = $Packet[($Offset)]
                    if ($SubType -in (1, 2, 3, 6, 7)) {
                        $Hash.Add('ChassisId', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }
                    if ($Subtype -eq 4) {
                        $Hash.Add('ChassisId', [PhysicalAddress]::new($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }
                    $Offset += $Length
                    break
                }

                $TlvType.PortId {
                    $Subtype = $Packet[($Offset)]
                    if ($SubType -in (1, 2, 5, 6, 7)) {
                        $Hash.Add('Port', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }
                    if ($Subtype -eq 3) {
                        $Hash.Add('Port', [PhysicalAddress]::new($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }
                    $Offset += $Length
                    break
                }

                $TlvType.TimeToLive {
                    $Hash.Add('TimeToLive', [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0))
                    $Offset += $Length
                    break
                }

                $TlvType.PortDescription {
                    $Hash.Add('PortDescription', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.SystemName {
                    $Hash.Add('Device', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.SystemDescription {
                    $Hash.Add('SystemDescription', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.ManagementAddress {
                    $AddrLen = $Packet[($Offset)]
                    $Subtype = $Packet[($Offset + 1)]

                    if (-not $Hash.ContainsKey('IPAddress') -and $Subtype -in 1, 2) {
                        $Addresses = New-Object System.Collections.Generic.List[String]
                        $Hash.Add('IPAddress', $Addresses)
                    }

                    if ($Subtype -in 1, 2) {
                        $Addresses.Add(([System.Net.IPAddress][byte[]]$Packet[($Offset + 2)..($Offset + $AddrLen)]).IPAddressToString)
                    }
                    $Offset += $Length
                    break
                }

                $TlvType.OrganizationSpecific {
                    $OUI = [System.BitConverter]::ToString($Packet[($Offset)..($Offset + 2)])
                    $Subtype = $Packet[($Offset + 3)]

                    if ($OUI -eq '00-12-BB' -and $Subtype -eq 10) {
                        $Hash.Add('Model', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 4)..($Offset + $Length - 1)]))
                    }

                    if ($OUI -eq '00-80-C2' -and $Subtype -eq 1) {
                        $Hash.Add('VLAN', [BitConverter]::ToUInt16($Packet[($Offset + 5)..($Offset + 4)], 0))
                    }

                    $Offset += $Length
                    break
                }

                default {
                    $Offset += $Length
                    break
                }
            }
        }
        [PSCustomObject]$Hash
    }
}

#endregion

# ── Appel principal ──
$Packet = Invoke-DiscoveryProtocolCapture -Type LLDP -Force
if ($Packet) {
    $data = Get-DiscoveryProtocolData -Packet $Packet
    $switch = if ($data.Device)      { $data.Device }      else { 'N/A' }
    $port   = if ($data.Port)        { $data.Port }        else { 'N/A' }
    $vlan   = if ($data.VLAN)        { $data.VLAN }        else { 'N/A' }
    $ip     = if ($data.IPAddress)   { $data.IPAddress -join ', ' } else { 'N/A' }
    $desc   = if ($data.SystemDescription) { $data.SystemDescription.Trim() -replace '\s+', ' ' } else { 'N/A' }
    $iface  = if ($data.Connection)  { $data.Connection }  else { 'N/A' }
    Write-Output "LLDP_OK|$switch|$port|$vlan|$ip|$desc|$iface"
} else {
    Write-Output "LLDP_NONE"
}

