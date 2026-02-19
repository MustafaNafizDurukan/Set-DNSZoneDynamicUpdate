# Set-DNSZoneDynamicUpdate

Modify Active Directory-Integrated DNS Zone Dynamic Update settings via LDAP — no DNS admin privileges required.

## Overview

When a principal has **WriteProperty on dNSProperty** (or higher privileges such as GenericWrite, Full Control) on a DNS zone AD object, they can modify the zone's Dynamic Update setting by directly editing the `dNSProperty` binary attribute via LDAP.

This bypasses the DNS Server Management RPC interface (used by `Set-DnsServerPrimaryZone`), which requires DNS admin-level access even when the caller has full control over the zone object in Active Directory.

## Why This Matters

| Dynamic Update Setting | Value | Risk |
| --- | --- | --- |
| **None** | 0 | Dynamic updates disabled. No risk from DNS update abuse. |
| **Secure Only** | 2 | Only Kerberos-authenticated clients can update records. Default and recommended. |
| **Nonsecure and Secure** | 1 | ⚠️ **Anyone on the network can add/modify DNS records without authentication.** |

An attacker with write access to the zone object can downgrade the setting from `Secure Only` to `Nonsecure and Secure`, then perform:

- **ADIDNS Poisoning** — inject wildcard or targeted DNS records
- **Man-in-the-Middle** — redirect traffic by spoofing DNS responses
- **NTLM Relay** — coerce authentication to attacker-controlled hosts via DNS manipulation

## Attack Path

```
Principal with GenericWrite on DNS Zone object
    │
    ▼
Modify dNSProperty via LDAP (Secure Only → Nonsecure and Secure)
    │
    ▼
Inject malicious DNS records without authentication
    │
    ▼
MITM / NTLM Relay / Credential Theft
```

## Technical Details

The Dynamic Update setting is stored in the `dNSProperty` attribute on the DNS zone AD object located at:

```
DC=<zone>,CN=MicrosoftDNS,DC=DomainDnsZones,DC=<domain>,DC=<tld>
```

`dNSProperty` is a multi-valued binary attribute. Each value follows the `DNSPROPERTY` struct defined in [MS-DNSP 2.3.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/445c7843-e4a1-4222-8c0f-630c230a4c80):

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0 | 4 | DataLength | Length of the Data field |
| 4 | 4 | NameLength | Not used (always 0x01) |
| 8 | 4 | Flag | Reserved (0x00) |
| 12 | 4 | Version | Always 0x01 |
| 16 | 4 | Id | Property type identifier |
| 20 | var | Data | Property value |

The relevant property is **DSPROPERTY_ZONE_ALLOW_UPDATE** (`Id = 0x00000002`), with `Data` values defined in [DNS_ZONE_UPDATE (MS-DNSP 2.2.6.1.1)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d4b84209-f00c-478f-80d7-8dd0f1633d9e):

| Constant | Value | Meaning |
| --- | --- | --- |
| ZONE_UPDATE_OFF | 0 | No dynamic updates |
| ZONE_UPDATE_UNSECURE | 1 | Nonsecure and Secure |
| ZONE_UPDATE_SECURE | 2 | Secure Only |

## Usage

```powershell
# Import the function
. .\Set-DNSZoneDynamicUpdate.ps1

# Downgrade to Nonsecure and Secure (attack scenario)
Set-DNSZoneDynamicUpdate -ZoneName "corp.local" -UpdateType NonsecureAndSecure

# Revert to Secure Only
Set-DNSZoneDynamicUpdate -ZoneName "corp.local" -UpdateType SecureOnly

# Disable dynamic updates entirely
Set-DNSZoneDynamicUpdate -ZoneName "corp.local" -UpdateType None
```

### Output

```
[*] Zone DN: DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local
[*] Target : NonsecureAndSecure (1)
[*] dNSProperty value count: 12
[*] Found ALLOW_UPDATE at index 3
[*] Current: SecureOnly (2)
[+] Modified: SecureOnly (2) -> NonsecureAndSecure (1)
[+] CommitChanges() successful!
[!] DNS Server may need to reload zone or restart for change to take effect.
```

## Requirements

- Windows domain-joined machine
- PowerShell (no additional modules required — uses `System.DirectoryServices`)
- Principal with **GenericWrite**, **WriteProperty**, or **Full Control** on the target DNS zone AD object

## Detection

### What to Monitor

- **LDAP modifications** to objects under `CN=MicrosoftDNS,DC=DomainDnsZones` — specifically changes to the `dNSProperty` attribute
- **Event ID 5136** (Directory Service Changes audit) — tracks attribute-level modifications on AD objects
- **Unexpected Dynamic Update setting changes** — alert if a zone's update policy changes from `Secure Only` to `Nonsecure and Secure`

### Recommended Hardening

- Audit and restrict write permissions on DNS zone objects in Active Directory
- Enable **Directory Service Changes** auditing (`Audit Directory Service Changes` under Advanced Audit Policy)
- Monitor for `dNSProperty` attribute modifications on `dnsZone` objects
- Regularly validate that all zones are configured with `Secure Only` dynamic updates

## References

- [MS-DNSP: dnsProperty (2.3.2.1)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/445c7843-e4a1-4222-8c0f-630c230a4c80)
- [MS-DNSP: Property Id (2.3.2.1.1)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/3af63871-0cc4-4179-916c-5caade55a8f3)
- [MS-DNSP: DNS_ZONE_UPDATE (2.2.6.1.1)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d4b84209-f00c-478f-80d7-8dd0f1633d9e)
- [Powermad — DNS Exploit Tools](https://github.com/Kevin-Robertson/Powermad)
- [ADIDNS Poisoning — The Hacker Recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing)

## Disclaimer

This tool is intended for **authorized security testing and research only**. Use it only in environments where you have explicit permission. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.
