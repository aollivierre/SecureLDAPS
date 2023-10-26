# SecureLDAPS for FortiMail: A Comprehensive Wiki Guide

## Table of Contents
* [Overview](#overview)
* [Prerequisites](#prerequisites)
* [Scripts Description](#scripts-description)
    - [Local Account Management](#local-account-management)
    - [Domain Account Management](#domain-account-management)
    - [LDAP/LDAPS Configuration](#ldapldaps-configuration)
    - [Exchange Mailboxes](#exchange-mailboxes)
    - [Helper Scripts](#helper-scripts)

## Overview
The SecureLDAPS repository consists of PowerShell scripts that streamline the process of setting up secure LDAPS with FortiMail. The wiki will guide you through tasks such as creating admin accounts, enabling LDAPS, testing LDAPS connectivity, and setting up Exchange mailboxes.

## Prerequisites
Ensure the following are in place before you proceed:
- Windows Server with Active Directory Domain Services installed
- Exchange Server (needed for Exchange mailbox creation scripts)
- PowerShell 5.1 or later

## Scripts Description
A brief overview of the scripts available and their functionalities:

### Local Account Management
* `0-New-LocalAdmin.ps1`: Creates a new local admin account.
* `Get-LocalUser.ps1`: Fetches details about local users and exports them to a CSV file.

### Domain Account Management
* `0-New-DomainAdmin.ps1`: Scripts to set up a new domain admin account.

### LDAP/LDAPS Configuration
Various scripts that range from checking if LDAP ports are open, generating and accepting certificate requests for LDAPS, enabling LDAPS in AD, and testing LDAPS connectivity.

### Exchange Mailboxes
Scripts centered around creating, managing, and fetching details for Exchange mailboxes.

### Helper Scripts
Miscellaneous scripts that aid with tasks such as fetching the FQDN of the current host and checking firewall rules.

## Local Account Management
### Create a Local Administrator Account
```powershell
# Define variables
$userName = "localadmin" 
$password = ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force

# Create the local user account
New-LocalUser -Name $userName -Password $password -FullName "Local Admin" -Description "Local Administrator Account"

# Add the account to the Administrators group  
Add-LocalGroupMember -Group "Administrators" -Member $userName
```


# Set the Password to Never Expire
```powershell
Set-LocalUser -Name $userName -PasswordNeverExpires $true
```

# Domain Account Management

## Create a Domain Administrator Account

```powershell
# Define variables
$userName = "domainadmin"
$password = ConvertTo-SecureString "P@ssw0rd1" -AsPlainText -Force  

# Create the AD user account
New-ADUser -Name $userName -AccountPassword $password -Enabled $true 

# Add to Domain Admins group
Add-ADGroupMember -Identity "Domain Admins" -Members $userName
```

# LDAP/LDAPS Configuration

## Enable LDAP over SSL

To enable LDAPS on a Windows Server hosting AD DS, you'd need to:
1. Request a certificate from your internal CA or a public CA.
2. Import the certificate into the server's personal store.
3. Update AD DS settings with Enable-LDAPS.ps1.
4. Create firewall rules to allow TCP ports 389 and 636.

```powershell
# Import certificate 
Import-Certificate -FilePath C:\LDAPScert.cer -CertStoreLocation Cert:\LocalMachine\My

# Enable LDAPS with script
.\Enable-LDAPS.ps1

# Create firewall rules
New-NetFirewallRule -DisplayName "LDAP" -Direction Inbound -LocalPort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAPS" -Direction Inbound -LocalPort 636 -Protocol TCP -Action Allow
```

## Test LDAPS Connectivity

```powershell
$server = "dc01.contoso.com"
$ldap = [ADSI]"LDAP://$server" 
$ldaps = [ADSI]"LDAP://$server:636"

if($ldap.ProviderName -eq "ADsDSOObject") {
    "LDAP connection successful"
} else {
    "Error connecting to LDAP" 
}

if($ldaps.ProviderName -eq "ADsDSOObject") {
   "LDAPS connection successful"
} else {
   "Error connecting to LDAPS"
}
```

# Exchange Mailboxes

## Create Exchange Mailboxes

```powershell
# Connect to Exchange 
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline

# Create user mailbox
New-Mailbox -Name "Jane Doe" -DisplayName "Jane Doe" -Alias jdoe -UserPrincipalName jdoe@contoso.com -Database "Mailbox Database"

# Create shared mailbox
New-Mailbox -Shared -Name "Sales Department" -DisplayName "Sales Department" -Alias sales -UserPrincipalName sales@contoso.com
```

## Grant access to the shared mailbox

```powershell
Add-MailboxPermission -Identity "sales" -User jdoe -AccessRights FullAccess -InheritanceType All
```

# Local Account Management

- `0-New-LocalAdmin.ps1` - Creates a new local admin account
- `Get-LocalUser.ps1` - Gets details on local users and exports to CSV

# Domain Account Management

- `0-New-DomainAdmin.ps1` - Creates a new domain admin account

# LDAP/LDAPS Configuration

- `1-Check-LDAP_Port.ps1` - Checks if LDAP ports are open
- `2-Create-LDAP_Firewall.ps1` - Opens LDAP ports in firewall
- `OpenSSL_LDAP_SSO_DC2\5-CertReq.ps1` - Generates CSR for LDAPS certificate
- `OpenSSL_LDAP_SSO_DC2\7-CertReq_Accept.ps1` - Accepts/imports LDAPS certificate
- `OpenSSL_LDAP_SSO_DC2\9-Enable-LDAPS.ps1` - Enables LDAPS in Active Directory
- `OpenSSL_LDAP_SSO_DC2\11-Export-LDAPsPfx.ps1` - Exports LDAPS certificate
- `OpenSSL_LDAP_SSO_DC2\12-Test-LDAPS.ps1` - Tests LDAPS connectivity

# Exchange Mailboxes

- `Exchange\LDAP_FortiMail\14-Create-FortiMailTest.ps1` - Creates a test mailbox
- `Exchange\LDAP_FortiMail\15-GetUsersMailboxDB-info.ps1` - Gets all mailboxes and exports to CSV
- `Exchange\LDAP_FortiMail\16-Create-DMARC-SharedMailbox.ps1` - Creates a shared DMARC mailbox

# Helper Scripts

- `3-Find-FQDN.ps1` - Gets FQDN of current host
- `1.1-Check-FirewallRule.ps1` - Displays firewall rules (documentation example)


**Note:** This wiki is intended for technical users familiar with Windows administration, Active Directory, and PowerShell scripting. Always make sure to test scripts in a controlled environment before deploying in production.
