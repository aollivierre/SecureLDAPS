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
