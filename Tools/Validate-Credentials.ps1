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
	    $Domain = $env:USERDNSDOMAIN
	    if(!$Domain){$Domain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
	    if(!$Domain){$Domain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
	}
	
	if(!$DomainController){
	    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)))
	    $domainControllers = $currentDomain.DomainControllers
	 	$DomainController = $domainControllers[0].Name
	  	if(!$DomainController){
	        	$DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().RidRoleOwner.Name
	    	}
	  	if(!$DomainController){
	        	$result = nslookup -type=all "_ldap._tcp.dc._msdcs.$Domain" 2>$null
	        	$DomainController = ($result | Where-Object { $_ -like '*svr hostname*' } | Select-Object -First 1).Split('=')[-1].Trim()
	  	}
	}

	$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain, $DomainController)
	if($principalContext.ValidateCredentials($UserName, $Password)){"[+] Credentials Validation: Success"}
	else{"[-] Credentials Validation: Failed"}
}
