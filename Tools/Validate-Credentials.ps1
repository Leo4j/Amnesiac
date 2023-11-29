Add-Type -AssemblyName System.DirectoryServices.AccountManagement

function Validate-Credentials{
	Param
    (
		[string]
        $UserName,
		[string]
        $Password,
		[string]
        $Domain,
		[string]
        $DomainController
    )
	
	if(!$Domain){
		try{
			$RetrieveDomainFull = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$RetrieveDomain = $RetrieveDomainFull.Name
		}
		catch{$RetrieveDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		$Domain = $RetrieveDomain
	}
	
	if(!$DomainController){
		
		$DomainController = $RetrieveDomainFull.RidRoleOwner.Name
		
		if(!$DomainController){

			$result = nslookup -type=all "_ldap._tcp.dc._msdcs.$Domain" 2>$null

			# Filtering to find the line with 'svr hostname' and then split it to get the last part which is our DC name.
			$DomainController = ($result | Where-Object { $_ -like '*svr hostname*' } | Select-Object -First 1).Split('=')[-1].Trim()
		}
	}

	$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain, $DomainController)
	if($principalContext.ValidateCredentials($UserName, $Password)){"[+] Credentials Validation: Success"}
	else{"[-] Credentials Validation: Failed"}
}
