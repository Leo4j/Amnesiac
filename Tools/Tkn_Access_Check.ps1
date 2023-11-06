function Access_Check {
	param($Method, $Targets, $Command, [switch]$NoOutput)
	
	if ($Targets) {
		$Computers = $Targets
		$Computers = $Computers -split ","
		$Computers = $Computers | Sort-Object -Unique
	}
	
	else{
		$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
		$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
		$objSearcher.PageSize = 1000
		$objSearcher.Filter = "(&(sAMAccountType=805306369))"
		$Computers = $objSearcher.FindAll() | %{$_.properties.dnshostname}
	}
	
	if($Method -eq "SMB"){$Command = $null}
	
	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	
	if($Method -eq "SMB"){$PortScan = 445}
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
		$ComputerAccess
	}
	
	if($Method -eq "PSRemoting"){
		Write-Output ""
		Write-Output "[+] The current user has PSRemoting Admin access on:"
		Write-Output ""
		$ComputerAccess
	}
	
	if($Command){
		if($NoOutput){Invoke-Command -ScriptBlock { Invoke-Expression $Using:Command } -ComputerName $ComputerAccess -ErrorAction SilentlyContinue -AsJob > $null}
		else{Invoke-Command -ScriptBlock { Invoke-Expression $Using:Command } -ComputerName $ComputerAccess -ErrorAction SilentlyContinue}
	}
	
}
