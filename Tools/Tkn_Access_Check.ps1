function Access_Check {
	param(
 		[string]$Method,
   		[string]$Targets,
     		[string]$Command,
       		[string]$Domain,
       		[string]$DomainController,
       		[switch]$NoOutput
	 )

  	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	
	if ($Targets) {
		$Computers = $Targets
		$Computers = $Computers -split ","
		$Computers = $Computers | Sort-Object -Unique
	}
	
	else{
		$Computers = @()
        	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
			if($Domain){
				if($DomainController){
					$TempDomainName = "DC=" + $Domain.Split(".")
					$domainDN = $TempDomainName -replace " ", ",DC="
					$ldapPath = "LDAP://$DomainController/$domainDN"
					$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
				}
				else{$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")}
			}
			else{$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry}
        	$objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        	$objSearcher.PageSize = 1000
        	$Computers = $objSearcher.FindAll() | ForEach-Object { $_.properties.dnshostname }
		$Computers = $Computers | Sort-Object -Unique
	}
	
	$Computers = $Computers | Where-Object { $_ -and $_.trim() }
	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$TempHostname = $HostFQDN -replace '\..*', ''
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	$Computers = $Computers | Where-Object {$_ -ne "$TempHostname"}
	
	if($Method -eq "SMB"){$PortScan = 445;$Command = $null}
	elseif($Method -eq "PSRemoting"){$PortScan = 5985}
	
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()

	$scriptBlock = {
		param ($computer, $port)
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$asyncResult = $tcpClient.BeginConnect($computer, $port, $null, $null)
		$wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
		if ($wait) {
			try {
				$tcpClient.EndConnect($asyncResult)
				return $computer
			} catch {}
		}
		$tcpClient.Close()
		return $null
	}

	$runspaces = New-Object 'System.Collections.Generic.List[System.Object]'

	foreach ($computer in $Computers) {
		$powerShellInstance = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer).AddArgument($PortScan)
		$powerShellInstance.RunspacePool = $runspacePool
		$runspaces.Add([PSCustomObject]@{
			Instance = $powerShellInstance
			Status   = $powerShellInstance.BeginInvoke()
		})
	}

	$reachable_hosts = @()
	foreach ($runspace in $runspaces) {
		$result = $runspace.Instance.EndInvoke($runspace.Status)
		if ($result) {
			$reachable_hosts += $result
		}
	}

	$Computers = $reachable_hosts

	$runspacePool.Close()
	$runspacePool.Dispose()
	
	$ComputerAccess = @()
	
	if($Method -eq "PSRemoting"){
		$ComputerAccess = Invoke-Command -ScriptBlock { [System.Net.Dns]::GetHostByName(($env:computerName)).HostName } -ComputerName $Computers -ErrorAction SilentlyContinue
	}
	
	if($Method -eq "SMB"){
		foreach($Computer in $Computers){
			$Error.Clear()
			ls \\$Computer\c$ -ErrorAction SilentlyContinue > $null
			if($error[0] -eq $null) {
				$ComputerAccess += $Computer
			}
		}
	}
	if($Method -eq "SMB"){
		Write-Output ""
		Write-Output "[+] The current user has SMB Admin access on:"
		Write-Output ""
	}
	
	if($Method -eq "PSRemoting"){
		Write-Output ""
		Write-Output "[+] The current user has PSRemoting Admin access on:"
		Write-Output ""
	}

 	if($ComputerAccess){
  		$ComputerAccess = $ComputerAccess | Where-Object { $_ }
  		$ComputerAccess | ForEach-Object { Write-Output $_ }

    		if($Command){
			if($NoOutput){Invoke-Command -ScriptBlock { Invoke-Expression $Using:Command } -ComputerName $ComputerAccess -ErrorAction SilentlyContinue -AsJob > $null}
			else{Invoke-Command -ScriptBlock { Invoke-Expression $Using:Command } -ComputerName $ComputerAccess -ErrorAction SilentlyContinue}
		}
    	}
  	else{Write-Output "[-] No Access"}
}
