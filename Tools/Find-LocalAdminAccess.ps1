function Find-LocalAdminAccess {
	
	<#

	.SYNOPSIS
	Find-LocalAdminAccess Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Find-LocalAdminAccess

	.DESCRIPTION
	Check the Domain for local Admin Access
	
	.PARAMETER Targets
	Specify a comma-separated list of targets, or the path to a file containing targets (one per line)
	
	.PARAMETER Method
	Provide a method to check for Admin Access (SMB, WMI, PSRemoting)
	
	.PARAMETER UserName
	UserName to check for Admin Access as (Works with WMI and PSRemoting only)
	
	.PARAMETER Password
	Password for the UserName (Works with WMI and PSRemoting only)
	
	.PARAMETER Command
	Command to execute on targets where we are admin (Works for all methods if Credentials are not provided, otherwise WMI and PSRemoting only)
	
	.PARAMETER NoOutput
	Won't wait for the command to complete and won't show output
	
	.PARAMETER scsafe
	Safe sc operations when method SMB is used

 	.PARAMETER SaveOutput
	Save tool output
	
	.EXAMPLE
	Find-LocalAdminAccess -Method SMB
	Find-LocalAdminAccess -Method WMI
	Find-LocalAdminAccess -Method PSRemoting
 	Find-LocalAdminAccess -Method WMI -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
	Find-LocalAdminAccess -Method PSRemoting -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
	
	#>
	
    	param (
        	[string]$Targets,
		[Parameter(Mandatory=$true)]
        	[string]$Method,
        	[string]$UserName,
        	[string]$Password,
		[string]$Command,
		[switch]$ShowErrors,
		[switch]$scsafe,
		[switch]$NoOutput,
  		[switch]$SaveOutput,
    		[switch]$InLine
    	)
	if(!$ShowErrors){
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
	}
	
	Set-Variable MaximumHistoryCount 32767

    	if (($UserName -OR $Password) -AND ($Method -eq "SMB")) {
        	Write-Output "Please use Method WMI or PSRemoting if you need to run as a different user"
        	return
    	}

    	if ($Targets) {
     		$TestPath = Test-Path $Targets
		
		if($TestPath){
			$Computers = Get-Content -Path $Targets
			$Computers = $Computers | Sort-Object -Unique
		}
		
		else{
			$Computers = $Targets
			$Computers = $Computers -split ","
			$Computers = $Computers | Sort-Object -Unique
		}
    	} else {
		$Computers = @()
        	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        	$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
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
	
	if($Method -eq "WMI"){$PortScan = 135}
	elseif($Method -eq "SMB"){$PortScan = 445}
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
	
	#$Computers = $Computers | Sort-Object -Unique

	$runspacePool.Close()
	$runspacePool.Dispose()
	
	if($UserName){
		Write-Output ""
		Write-Output "[+] $UserName has Local Admin access on:"
		Write-Output ""
	}
	else{
		Write-Output ""
		Write-Output "[+] The current user has Local Admin access on:"
		Write-Output ""
	}

    	$ScriptBlock = {
		param (
			$Computer,
			$Method,
			$UserName,
			$Password
		)
		
		if($UserName -AND $Password){
			$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
			$cred = New-Object System.Management.Automation.PSCredential($UserName, $SecPassword)
		}
		
		$Error.Clear()

		if ($UserName -AND $Password -AND ($Method -eq "WMI")) {Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction SilentlyContinue -Credential $cred}
  		elseif ($UserName -AND $Password -AND ($Method -eq "PSRemoting")) {Invoke-Command -ScriptBlock { hostname } -ComputerName $Computer -ErrorAction SilentlyContinue -Credential $cred}
    		elseif ($Method -eq "WMI") {Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction SilentlyContinue}
      		elseif ($Method -eq "PSRemoting") {Invoke-Command -ScriptBlock { hostname } -ComputerName $Computer -ErrorAction SilentlyContinue}
		elseif ($Method -eq "SMB") {ls \\$Computer\c$ -ErrorAction SilentlyContinue}
		if($error[0] -eq $null) {
			return @{
		    	Computer = $Computer
		    	Success  = $true
			}
	    } else {
			return @{
		    	Computer = $Computer
		    	Success  = $false
		    	Message  = $error[0].ToString()
			}
	    }
	}

    	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
    	$runspacePool.Open()
    	$runspaces = New-Object System.Collections.ArrayList

    	foreach ($Computer in $Computers) {
        	$runspace = [powershell]::Create().AddScript($ScriptBlock).AddArgument($Computer).AddArgument($Method).AddArgument($UserName).AddArgument($Password)
        	$runspace.RunspacePool = $runspacePool
        	$null = $runspaces.Add([PSCustomObject]@{
            		Pipe = $runspace
            		Status = $runspace.BeginInvoke()
        	})
    	}

    	$ComputerAccess = @()
		foreach ($run in $runspaces) {
			try {
				$result = $run.Pipe.EndInvoke($run.Status)
			} catch {}
			if ($result.Success) {
				$ComputerAccess += $result.Computer
			} else {
				Write-Warning "[-] Failed on $($result.Computer): $($result.Message)"
			}
		}

    	$runspaces | ForEach-Object {
        	$_.Pipe.Dispose()
    	}

    	$runspacePool.Close()
    	$runspacePool.Dispose()

 	#$ComputerAccess = $ComputerAccess | Sort-Object -Unique
	
	if($ComputerAccess){
		$ComputerAccess = $ComputerAccess | Where-Object { $_ }
		if($InLine){$ComputerAccess = $ComputerAccess -Join ",";Write-Output $ComputerAccess}
		else{$ComputerAccess | ForEach-Object { Write-Output $_ }}
	}
  	else{Write-Output "[-] No Access"}
		
	if($SaveOutput){
	    	try {
	        	$ComputerAccess | Out-File $PWD\LocalAdminAccess.txt -Force
	        	Write-Output ""
			Write-Output "[+] Output saved to: $PWD\LocalAdminAccess.txt"
			Write-Output ""
	    	} catch {
	        	$ComputerAccess | Out-File "c:\Users\Public\Documents\LocalAdminAccess.txt" -Force
			Write-Output ""
	        	Write-Output "[+] Output saved to: c:\Users\Public\Documents\LocalAdminAccess.txt"
			Write-Output ""
	    	}
	} else {Write-Output ""}
	
	if ($Command) {

		if ($UserName -and $Password) {
			$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
			$cred = New-Object System.Management.Automation.PSCredential($UserName, $SecPassword)
		}

		# Load the scripts into variables
		if ($Method -eq 'WMI') {
			$WmiScript = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Leo4j/Invoke-WMIRemoting/main/Invoke-WMIRemoting.ps1')
		}
		if ($Method -eq 'SMB') {
			$SmbScript = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Leo4j/Invoke-SMBRemoting/main/Invoke-SMBRemoting.ps1')
			# Initialize a mutex to synchronize access to sc.exe operations
			if($scsafe){
				$Mutex = [System.Threading.Mutex]::new($false, 'SCMutex')
			}
		}

		# Create and open a runspace pool
		$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, [System.Environment]::ProcessorCount)
		$RunspacePool.Open()

		$scriptBlock = {
			param($Computer, $Command, $Method, $cred, $Username, $Password, $WmiScript, $SmbScript)

			try {
				if ($Method -eq 'PSRemoting') {
					if ($cred) {
						$command = $command + " | Out-String -Width 4096"
						$output = Invoke-Command -ScriptBlock { Invoke-Expression $Using:Command } -ComputerName $Computer -Credential $cred
					}
					else {
     						$command = $command + " | Out-String -Width 4096"
						$output = Invoke-Command -ScriptBlock { Invoke-Expression $Using:Command } -ComputerName $Computer
					}
				}
				elseif ($Method -eq 'WMI') {
					. ([ScriptBlock]::Create($WmiScript))
					if ($cred) {
						$output = Invoke-WMIRemoting -ComputerName $Computer -Command $Command -Username $Username -Password $Password
					}
					else {
						$output = Invoke-WMIRemoting -ComputerName $Computer -Command $Command
					}
				}
				elseif ($Method -eq 'SMB') {
					. ([ScriptBlock]::Create($SmbScript))
					$output = Invoke-SMBRemoting -ComputerName $Computer -Command $Command
				}

				return @{
					ComputerName = $Computer
					Output       = $output
				}
			} catch {
				return @{
					ComputerName = $Computer
					Error        = $_.Exception.Message
				}
			}
		}

		$JobObjects = @()
		
		if ($Method -eq 'SMB' -AND $scsafe) {
			foreach ($Computer in $ComputerAccess) {
				[void]$Mutex.WaitOne()
				try {
					$Job = [PowerShell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($Command).AddArgument($Method).AddArgument($cred).AddArgument($Username).AddArgument($Password).AddArgument($WmiScript).AddArgument($SmbScript)
					$Job.RunspacePool = $RunspacePool
					$JobObjects += @{
						PowerShell = $Job
						Handle     = $Job.BeginInvoke()
					}
				} finally {
					$Mutex.ReleaseMutex()
				}
			}
		}
		
		else{

			foreach ($Computer in $ComputerAccess) {
				$Job = [PowerShell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($Command).AddArgument($Method).AddArgument($cred).AddArgument($Username).AddArgument($Password).AddArgument($WmiScript).AddArgument($SmbScript)
				$Job.RunspacePool = $RunspacePool
				$JobObjects += @{
					PowerShell = $Job
					Handle     = $Job.BeginInvoke()
				}
			}
		}

		# Wait for all jobs to complete
		if(!$NoOutput){
			$JobObjects | ForEach-Object { $_.Handle.AsyncWaitHandle.WaitOne() } > $null

			foreach ($Job in $JobObjects) {
				$Result = $Job.PowerShell.EndInvoke($Job.Handle)
				
				if ($Result.Error) {
					Write-Output "$($Result.ComputerName): Error - $($Result.Error)"
				} else {
					Write-Output "[+] $($Result.ComputerName)"
					Write-Output "$($Result.Output.TrimEnd())"
					Write-Output ""
					Write-Output ""
				}
				
				$Job.PowerShell.Dispose()
			}
			
			$RunspacePool.Close()
		}
		
		if ($Method -eq 'SMB' -AND $scsafe) {
			# Release the mutex
			$Mutex.Dispose()
		}
		
		Write-Output "[+] Command execution completed"
		Write-Output ""
	}
}
