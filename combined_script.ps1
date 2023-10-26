
# Source: 0-New-DomainAdmin copy 3.ps1
# Load the required assembly for UserPrincipal
Add-Type -AssemblyName "System.DirectoryServices.AccountManagement"

# Import Active Directory module
Import-Module ActiveDirectory

# Define variables
$userName = "AOllivierre_Admin"
$password = ConvertTo-SecureString "ENTER your Password here" -AsPlainText -Force
$group = "Domain Admins"

# Create an Active Directory user account
New-ADUser -Name $userName -AccountPassword $password -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -DisplayName "Local Administrator Account" -Description "Domain admin account created by PowerShell script"

# Add the user to the specified group
try {
    Add-ADGroupMember -Identity $group -Members $userName
} catch {
    Write-Host "Error: Failed to add user to the $group group."
}





# Source: 1.1-Check-FirewallRule.ps1
<#
.SYNOPSIS
    A short one-line action-based description, e.g. 'Tests if a function is valid'
.DESCRIPTION
    A longer description of the function, its purpose, common use cases, etc.
.NOTES
    Information or caveats about the function e.g. 'This function is not supported in Linux'
.LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
    Test-MyTestFunction -Verbose
    Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines


    Name                DisplayName                                               DisplayGroup                     Protocol LocalPort RemotePort RemoteAddress Enabled Profile Direction Action
----                -----------                                               ------------                     -------- --------- ---------- ------------- ------- ------- --------- ------
ADDS-LDAPSEC-TCP-In Active Directory Domain Controller - Secure LDAP (TCP-In) Active Directory Domain Services TCP      636       Any        Any              True     Any   Inbound  Allow
ADDS-LDAP-TCP-In    Active Directory Domain Controller - LDAP (TCP-In)        Active Directory Domain Services TCP      389       Any        Any              True     Any   Inbound  Allow
ADDS-LDAP-UDP-In    Active Directory Domain Controller - LDAP (UDP-In)        Active Directory Domain Services UDP      389       Any        Any              True     Any   Inbound  Allow


    #>




$ldapPort = 389
$ldapsPort = 636

Get-NetFirewallRule -Direction Inbound |
Where-Object {($_ | Get-NetFirewallPortFilter).LocalPort -eq $ldapPort -or ($PSItem | Get-NetFirewallPortFilter).LocalPort -eq $ldapsPort} |
Format-Table -Property Name,
DisplayName,
DisplayGroup,
@{Name='Protocol';Expression={($_ | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($_ | Get-NetFirewallPortFilter).LocalPort}},
@{Name='RemotePort';Expression={($_ | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($_ | Get-NetFirewallAddressFilter).RemoteAddress}},
Enabled,
Profile,
Direction,
Action


# Source: OpenSSL_LDAP_SSO_DC2\11-Export-LDAPsPfx.ps1
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

function Export-LdapsPfx {
    param (
        [string]$thumbprint = 'Whatever Your Cert thumbprint Is',
        [string]$pfxFileName = 'LDAPS_PRIVATEKEY.pfx',
        [string]$password = 'Whatever Your Password is'
    )

    $pfxFilePath = Join-Path -Path $scriptDir -ChildPath $pfxFileName
    $pfxPass = (ConvertTo-SecureString -AsPlainText -Force -String $password)
    
    Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" | Export-PfxCertificate -FilePath $pfxFilePath -Password $pfxPass
}

Export-LdapsPfx



# Source: OpenSSL_LDAP_SSO_DC2\12-Test-LDAPS.ps1
##################
#### TEST ALL AD DCs for LDAPS
##################
$AllDCs = Get-ADDomainController -Filter * -Server CNA-AZR-DC2.cna-aiic.private | Select-Object Hostname
 foreach ($dc in $AllDCs) {
	$LDAPS = [ADSI]"LDAP://$($dc.hostname):636"
	#write-host $LDAPS
	try {
   	$Connection = [adsi]($LDAPS)
	} Catch {
	}
	If ($Connection.Path) {
   	Write-Host "Active Directory server correctly configured for SSL, test connection to $($LDAPS.Path) completed."
	} Else {
   	Write-Host "Active Directory server not configured for SSL, test connection to LDAP://$($dc.hostname):636 did not work."
	}
 }


# Source: Exchange\LDAP_FortiMail\14-Create-FortiMailTest.ps1
Get-MailboxDatabase | Format-Table -Auto Name, Server, EdbFilePath
$Database = (Get-MailboxDatabase "AGH-DB-01").Name



function Create-OnPremMailbox {
    param(
        [string]$UserPrincipalName = "FortiMailLDAPTest001@agh-fvm.com",
        [string]$Name = "FortiMailLDAPTest001",
        [string]$PasswordText = "Whatever Your Password is",
        [string]$OrganizationalUnit = "OU=Network_Services,OU=AGHUsers,DC=AGH,DC=com",
        [string]$Database = "AGH-DB-01"
    )

    # Helper function to write color-coded, timestamped messages
    function Write-TimestampedMessage {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Message,
            [Parameter(Mandatory = $false)]
            [ConsoleColor]$Color = 'White'
        )

        $timestamp = Get-Date -Format "HH:mm:ss"
        Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    }

    # Convert password to SecureString
    $Password = ConvertTo-SecureString -String $PasswordText -AsPlainText -Force

    # Load Exchange module - Only needed if you're not already in the Exchange Management Shell
    # Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1
    # Connect-ExchangeServer -auto

    # Try to create the mailbox
    try {
        Write-TimestampedMessage "Attempting to create mailbox: $UserPrincipalName..." -Color Cyan
        New-Mailbox -UserPrincipalName $UserPrincipalName -Name $Name -Password $Password -OrganizationalUnit $OrganizationalUnit -Database $Database

        # Confirm creation
        $mailbox = Get-Mailbox -Identity $UserPrincipalName
        if ($mailbox) {
            Write-TimestampedMessage "Successfully created mailbox: $UserPrincipalName." -Color Green
        } else {
            Write-TimestampedMessage "Failed to confirm creation of mailbox: $UserPrincipalName." -Color Red
        }
    } catch {
        Write-TimestampedMessage "Error: $_" -Color Red
    }
}

# Call the function
Create-OnPremMailbox



# Source: Exchange\LDAP_FortiMail\15-GetUsersMailboxDB-info.ps1
# Helper function to write color-coded, timestamped messages
function Write-TimestampedMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ConsoleColor]$Color = 'White'
    )

    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

# Load Exchange module - Only needed if you're not already in the Exchange Management Shell
# Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1
# Connect-ExchangeServer -auto

Write-TimestampedMessage "Retrieving all mailboxes and their databases..." -Color Cyan

$mailboxes = Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName, Database

# Export to CSV
$csvPath = "C:\Code\Exchange\Exports\all_mailboxes.csv" # Change path_to_save to your desired location

$mailboxes | Out-GridView
$mailboxes | Export-Csv $csvPath -NoTypeInformation

Write-TimestampedMessage "Data exported to $csvPath" -Color Green


# Source: Exchange\LDAP_FortiMail\16-Create-DMARC-SharedMailbox.ps1
Get-MailboxDatabase | Format-Table -Auto Name, Server, EdbFilePath
$Database = (Get-MailboxDatabase "AGH-DB-01").Name

function Create-OnPremSharedMailbox {
    param(
        [string]$SharedMailboxName = "dmarc@agh-fvm.com",
        [string]$UserToGrantPermissions = "FortiMailLDAPTest001@agh-fvm.com",
        [string]$Name = "DMARC",
        [string]$OrganizationalUnit = "OU=Network_Services,OU=AGHUsers,DC=AGH,DC=com",
        [string]$Database = "AGH-DB-01"
    )

    # Helper function to write color-coded, timestamped messages
    function Write-TimestampedMessage {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Message,
            [Parameter(Mandatory = $false)]
            [ConsoleColor]$Color = 'White'
        )

        $timestamp = Get-Date -Format "HH:mm:ss"
        Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    }

    # Try to create the shared mailbox
    try {
        Write-TimestampedMessage "Attempting to create shared mailbox: $SharedMailboxName..." -Color Cyan
        New-Mailbox -Shared -Name $Name -DisplayName $Name -UserPrincipalName $SharedMailboxName -OrganizationalUnit $OrganizationalUnit -Database $Database

        # Confirm creation
        $sharedMailbox = Get-Mailbox -Identity $SharedMailboxName
        if ($sharedMailbox) {
            Write-TimestampedMessage "Successfully created shared mailbox: $SharedMailboxName." -Color Green
        } else {
            Write-TimestampedMessage "Failed to confirm creation of shared mailbox: $SharedMailboxName." -Color Red
        }
    } catch {
        Write-TimestampedMessage "Error: $_" -Color Red
    }

    # Try to grant permissions to the mailbox
    try {
        Write-TimestampedMessage "Attempting to grant '$UserToGrantPermissions' permissions to: $SharedMailboxName..." -Color Cyan
        Add-MailboxPermission -Identity $SharedMailboxName -User $UserToGrantPermissions -AccessRights FullAccess -InheritanceType All

        # Confirm permission assignment
        $permissions = Get-MailboxPermission -Identity $SharedMailboxName | Where-Object { $_.User -like "*$UserToGrantPermissions*" -and $_.AccessRights -contains "FullAccess" }
        if ($permissions) {
            Write-TimestampedMessage "Successfully granted '$UserToGrantPermissions' permissions to: $SharedMailboxName." -Color Green
        } else {
            Write-TimestampedMessage "Failed to confirm permission grant for '$UserToGrantPermissions' to: $SharedMailboxName." -Color Red
        }
    } catch {
        Write-TimestampedMessage "Error: $_" -Color Red
    }
}

# Call the function
Create-OnPremSharedMailbox



# Source: 1-Check-LDAP_Port copy.ps1
# Import Active Directory module
Import-Module ActiveDirectory

# Get the closest domain controller
# $domainController = (Get-ADDomainController -Discover -NextClosestSite).HostName

#Using the Public IP of the domain controller (not the private IP)
# $domainController = "Whatever Your Domain controller Public IP Is"
$domainController = "Whatever Your Domain controller Public IP Is"
# $domainController = "Whatever Your Domain controller Private IP Is"

$ldapPort = 389
$ldapsPort = 636

# Check LDAP port
$ldapConnectionResult = Test-NetConnection -ComputerName $domainController -Port $ldapPort

if ($ldapConnectionResult.TcpTestSucceeded) {
    Write-Host "LDAP port ($ldapPort) is open on the domain controller ($domainController)."
} else {
    Write-Host "LDAP port ($ldapPort) is NOT open on the domain controller ($domainController)."
}

# Check LDAPS port
$ldapsConnectionResult = Test-NetConnection -ComputerName $domainController -Port $ldapsPort

if ($ldapsConnectionResult.TcpTestSucceeded) {
    Write-Host "LDAPS port ($ldapsPort) is open on the domain controller ($domainController)."
} else {
    Write-Host "LDAPS port ($ldapsPort) is NOT open on the domain controller ($domainController)."
}



# Source: 2-Create-LDAP_Firewall.ps1
$ldapPort = 389
$ldapsPort = 636

# Check for existing LDAP rule
$ldapRule = Get-NetFirewallRule -DisplayName "Allow LDAP Port" -ErrorAction SilentlyContinue

if ($null -eq $ldapRule) {
    # Create a firewall rule for the LDAP port
    New-NetFirewallRule -DisplayName "Allow LDAP Port" -Direction Inbound -LocalPort $ldapPort -Protocol TCP -Action Allow -Enabled True
    Write-Host "$(Get-Date) - Created a new rule to allow LDAP port ($ldapPort)." -ForegroundColor Green
} else {
    Write-Host "$(Get-Date) - An existing rule for LDAP port ($ldapPort) is already in place." -ForegroundColor Yellow
}

# Check for existing LDAPS rule
$ldapsRule = Get-NetFirewallRule -DisplayName "Allow LDAPS Port" -ErrorAction SilentlyContinue

if ($null -eq $ldapsRule) {
    # Create a firewall rule for the LDAPS port
    New-NetFirewallRule -DisplayName "Allow LDAPS Port" -Direction Inbound -LocalPort $ldapsPort -Protocol TCP -Action Allow -Enabled True
    Write-Host "$(Get-Date) - Created a new rule to allow LDAPS port ($ldapsPort)." -ForegroundColor Green
} else {
    Write-Host "$(Get-Date) - An existing rule for LDAPS port ($ldapsPort) is already in place." -ForegroundColor Yellow
}



# Source: 3-Find-FQDN.ps1
[System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName


# Source: OpenSSL_LDAP_SSO_DC2\5-CertReq.ps1
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
function New-ADCSR {
    $requestInfPath = Join-Path -Path $currentDir -ChildPath "request.inf"
    $adCsrPath = Join-Path -Path $currentDir -ChildPath "ad.csr"

    certreq -new $requestInfPath $adCsrPath
}

New-ADCSR


# Source: OpenSSL_LDAP_SSO_DC2\7-CertReq_Accept.ps1
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
function AcceptADCSR {
    $certpath = Join-Path -Path $currentDir -ChildPath "ad_ldaps_cert.crt"

    certreq -accept $certpath
}

AcceptADCSR


# Source: OpenSSL_LDAP_SSO_DC2\9-Enable-LDAPS.ps1
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
function Invoke-LdifdeImport {
    param (
        [string]$fileName = 'enable_ldaps.txt'
    )

    $filePath = Join-Path -Path $scriptDir -ChildPath $fileName

    ldifde -i -f $filePath
}

Invoke-LdifdeImport


# Source: Get-LocalUser.ps1
# Get all local users
$localUsers = Get-LocalUser

# Get the user details and sort by date created
$sortedUsers = $localUsers | ForEach-Object {
    $userDetails = [PSCustomObject]@{
        Name         = $_.Name
        Enabled      = $_.Enabled
        AccountExpires = $_.AccountExpires
        Description  = $_.Description
        FullName     = $_.FullName
        LastLogon    = $_.LastLogon
        PasswordChangeableDate = $_.PasswordChangeableDate
        PasswordExpires = $_.PasswordExpires
        PrincipalSource = $_.PrincipalSource
        SID          = $_.SID
        UserFlags    = $_.UserFlags
        Created      = $_.PasswordLastSet
    }
    $userDetails
} | Sort-Object Created

# Export the sorted data to a CSV file on the desktop
$csvPath = [Environment]::GetFolderPath("Desktop") + "\LocalUsers.csv"
$sortedUsers | Export-Csv -Path $csvPath -NoTypeInformation