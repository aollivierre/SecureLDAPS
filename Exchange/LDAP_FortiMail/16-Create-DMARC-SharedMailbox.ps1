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
