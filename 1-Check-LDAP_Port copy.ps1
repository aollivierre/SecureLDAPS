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
