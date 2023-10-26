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