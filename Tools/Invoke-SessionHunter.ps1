function Invoke-SessionHunter {
	
	<#

	.SYNOPSIS
	Invoke-SessionHunter Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-SessionHunter

	.DESCRIPTION
	Retrieve and display information about active user sessions on remote computers.
	Admin privileges on the remote systems are not required.
	
	.PARAMETER Domain
	Specify the target domain
	
	.PARAMETER DomainController
	Specify the target domain
	
	.PARAMETER Targets
	Specify a comma-separated list of targets, or the path to a file containing targets (one per line)
	
	.PARAMETER Hunt
	Show active session for the specified user only
	
	.PARAMETER FailSafe
	Instructs the tool to move on if the target remote registry hangs
	
	.PARAMETER Timeout
	Timeout (in seconds) for remote registry access to prevent hanging. Works in combination with -FailSafe. Default = 2, increase for slower networks.
	
	.PARAMETER Servers
	Retrieve and display information about active user sessions on servers only
	
	.PARAMETER Workstations
	Retrieve and display information about active user sessions on workstations only
	
	.PARAMETER ExcludeLocalHost
	Exclude localhost from the sessions retrieval

 	.PARAMETER UserName
	Check sessions authenticating to targets as the specified UserName

 	.PARAMETER Password
	Provide password for the specified UserName
	
	.PARAMETER RawResults
	Return custom PSObjects instead of table-formatted results

 	.PARAMETER NoPortScan
	Do not run a port scan to enumerate for alive hosts before trying to retrieve sessions

 	.PARAMETER Match
  	Show only hosts where we are admin, and where a session for a user with admin count set to 1 exists

   	.PARAMETER CheckAsAdmin
  	Retrieve sessions as an admin where you have local admin privileges; otherwise, use the registry.

	.EXAMPLE
	Invoke-SessionHunter
 	Invoke-SessionHunter -CheckAsAdmin
  	Invoke-SessionHunter -CheckAsAdmin -UserName ferrari\Administrator -Password P@ssw0rd!
   	Invoke-SessionHunter -CheckAsAdmin -Timeout 2
	Invoke-SessionHunter -Domain contoso.local
	Invoke-SessionHunter -Domain contoso.local -Servers
	Invoke-SessionHunter -TargetsFile c:\Users\Public\Documents\targets.txt
	Invoke-SessionHunter -Hunt "Administrator"
	
	#>
    
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, Position = 0, ValueFromPipeline=$true)]
		[String]
		$Domain,
		
		[Parameter (Mandatory=$False, Position = 1, ValueFromPipeline=$true)]
		[String]
		$DomainController,
		
		[Parameter (Mandatory=$False, Position = 2, ValueFromPipeline=$true)]
		[String]
		$Targets,
		
		[Parameter (Mandatory=$False, Position = 3, ValueFromPipeline=$true)]
		[String]
		$Hunt,
		
		[Parameter (Mandatory=$False, Position = 4, ValueFromPipeline=$true)]
		[int]
		$Timeout,

  		[Parameter (Mandatory=$False, Position = 5, ValueFromPipeline=$true)]
		[String]
		$UserName,

  		[Parameter (Mandatory=$False, Position = 6, ValueFromPipeline=$true)]
		[String]
		$Password,
		
		[Parameter (Mandatory=$False, Position = 7, ValueFromPipeline=$true)]
		[Switch]
		$Servers,
		
		[Parameter (Mandatory=$False, Position = 8, ValueFromPipeline=$true)]
		[Switch]
		$Workstations,
		
		[Parameter (Mandatory=$False, Position = 9, ValueFromPipeline=$true)]
		[Switch]
		$RawResults,
		
		[Parameter (Mandatory=$False, Position = 10, ValueFromPipeline=$true)]
		[Switch]
		$IncludeLocalHost,

  		[Parameter (Mandatory=$False, Position = 11, ValueFromPipeline=$true)]
		[Switch]
		$NoPortScan,
		
		[Parameter (Mandatory=$False, Position = 12, ValueFromPipeline=$true)]
		[Switch]
		$Match,

  		[Parameter (Mandatory=$False, Position = 13, ValueFromPipeline=$true)]
		[Switch]
		$CheckAsAdmin,
		
		[Parameter (Mandatory=$False, Position = 14, ValueFromPipeline=$true)]
		[Switch]
		$FailSafe
	
	)
	
	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	Set-Variable MaximumHistoryCount 32767
	$Color = $Host.UI.RawUI.BackgroundColor
	$currentTextColor = $Host.UI.RawUI.ForegroundColor
 	$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
	
	$ldapretrieveddomain = $False
	
	if($UserName -AND $Password){$CheckAsAdmin = $True}
	
	if(!$Domain){
		try{
			$RetrieveDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$Domain = $RetrieveDomain.Name
			$ldapretrieveddomain = $True
		}
		catch{$Domain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
	}

 	if(!$DomainController){
		if($ldapretrieveddomain){
			$dcObjects = @($RetrieveDomain.DomainControllers)
			$DomainController = $dcObjects[0].Name
			#$DomainController = ($RetrieveDomain.FindDomainController()).Name
			#$DomainController = $allDCs[0].Name
		}
		else{
			$result = nslookup -type=all "_ldap._tcp.dc._msdcs.$Domain" 2>$null
			$DomainController = ($result | Where-Object { $_ -like '*svr hostname*' } | Select-Object -First 1).Split('=')[-1].Trim()
		}
	}
	
	$connection = Establish-LDAPSession -Domain $Domain -DomainController $DomainController
	
	if($Targets){
		
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
	}
	
	elseif($Servers){
		$Computers = Get-ADServers -ADCompDomain $Domain -LdapConnection $connection
		$Computers = $Computers | Sort-Object
	}

	elseif($Workstations){
		$Computers = Get-ADWorkstations -ADCompDomain $Domain -LdapConnection $connection
		$Computers = $Computers | Sort-Object
	}
	
	else{
		$Computers = Get-ADComputers -ADCompDomain $Domain -LdapConnection $connection
		$Computers = $Computers | Sort-Object
	}
	
	if(!$IncludeLocalHost){
		$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
		$Computers = $Computers | Where-Object {-not ($_ -cmatch "$env:computername")}
		$Computers = $Computers | Where-Object {-not ($_ -match "$env:computername")}
		$Computers = $Computers | Where-Object {$_ -ne "$env:computername"}
		$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	}
	
	$Computers = $Computers | Where-Object { $_ -and $_.trim() }

 	if(!$NoPortScan){
	
		# Initialize the runspace pool
		$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
		$runspacePool.Open()

		# Define the script block outside the loop for better efficiency
		$scriptBlock = {
			param ($computer)
			$tcpClient = New-Object System.Net.Sockets.TcpClient
			$asyncResult = $tcpClient.BeginConnect($computer, 135, $null, $null)
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

		# Use a generic list for better performance when adding items
		$runspaces = New-Object 'System.Collections.Generic.List[System.Object]'

		foreach ($computer in $Computers) {
			$powerShellInstance = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer)
			$powerShellInstance.RunspacePool = $runspacePool
			$runspaces.Add([PSCustomObject]@{
				Instance = $powerShellInstance
				Status   = $powerShellInstance.BeginInvoke()
			})
		}

		# Collect the results
		$reachable_hosts = @()
		foreach ($runspace in $runspaces) {
			$result = $runspace.Instance.EndInvoke($runspace.Status)
			if ($result) {
				$reachable_hosts += $result
			}
		}

		# Update the $Computers variable with the list of reachable hosts
		$Computers = $reachable_hosts

		# Close and dispose of the runspace pool for good resource management
		$runspacePool.Close()
		$runspacePool.Dispose()

 	}
	
	# Create a runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()

	# Create an array to hold the runspaces
	$runspaces = @()

	# Iterate through the computers, creating a runspace for each
	foreach ($Computer in $Computers) {
		# ScriptBlock that contains the processing code
		$scriptBlock = {
			param($Computer, $Domain, $searcher, $InvokeWMIRemoting, $UserName, $Password, $CheckAsAdmin, $Timeout, $FailSafe)

   			# Clearing variables
			$userSIDs = $null
			$userKeys = $null
			$remoteRegistry = $null
			$user = $null
			$userTranslation = $null
   			$AdminStatus = $False
    			$TempHostname = $Computer -replace '\..*', ''
			$TempCurrentUser = $env:username
   			if($Timeout){$timeoutSeconds = $Timeout}
      			else{$timeoutSeconds = 2}

			# Gather computer information
			$ipAddress = Resolve-DnsName $Computer | Where-Object { $_.Type -eq "A" } | Select-Object -ExpandProperty IPAddress
			
			$ErrorCheckpoint = $null
			$Error.Clear()
			
   			if($CheckAsAdmin){
	   			# Check Admin Access (and Sessions)
				if($UserName -AND $Password){
					if($FailSafe){
						#$timeoutSeconds = 2
						$checkIntervalMilliseconds = 100
						$elapsedTime = 0
						$processOutput = $null

						$command = @"
						`$cred = New-Object System.Management.Automation.PSCredential('$UserName', (ConvertTo-SecureString -String '$Password' -AsPlainText -Force));
						Get-WmiObject -Class Win32_OperatingSystem -ComputerName '$Computer' -Credential `$cred > `$null
"@

						# Start the process and capture output directly
						$processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
						$processStartInfo.FileName = "powershell.exe"
						$processStartInfo.Arguments = "-Command $command"
						$processStartInfo.RedirectStandardOutput = $true
						$processStartInfo.UseShellExecute = $false

						$process = New-Object System.Diagnostics.Process
						$process.StartInfo = $processStartInfo

						$process.Start() | Out-Null

						while (-not $process.HasExited -and $elapsedTime -lt ($timeoutSeconds * 1000)) {
							Start-Sleep -Milliseconds $checkIntervalMilliseconds
							$elapsedTime += $checkIntervalMilliseconds
						}

						if (-not $process.HasExited) {
							# Kill the process if it's still running
							$process.Kill()
							$ErrorCheckpoint = "ErrorCheckpoint"
						} else {
							$Error.Clear()
							$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
							$cred = New-Object System.Management.Automation.PSCredential($UserName,$SecPassword)
							Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -Credential $cred > $null
						}

						$process.Close()
					}
					else{
						$Error.Clear()
						$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
						$cred = New-Object System.Management.Automation.PSCredential($UserName,$SecPassword)
						Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -Credential $cred > $null
					}
				}
				else{
					if($FailSafe){
						#$timeoutSeconds = 2
						$checkIntervalMilliseconds = 100
						$elapsedTime = 0
						$processOutput = $null

						# Start the process and capture output directly
						$processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
						$processStartInfo.FileName = "powershell.exe"
						$processStartInfo.Arguments = "-Command ""Get-WmiObject -Class Win32_OperatingSystem -ComputerName '$Computer' > `$null"""
						$processStartInfo.RedirectStandardOutput = $true
						$processStartInfo.UseShellExecute = $false

						$process = New-Object System.Diagnostics.Process
						$process.StartInfo = $processStartInfo

						$process.Start() | Out-Null

						while (-not $process.HasExited -and $elapsedTime -lt ($timeoutSeconds * 1000)) {
							Start-Sleep -Milliseconds $checkIntervalMilliseconds
							$elapsedTime += $checkIntervalMilliseconds
						}

						if (-not $process.HasExited) {
							# Kill the process if it's still running
							$process.Kill()
							$ErrorCheckpoint = "ErrorCheckpoint"
						} else {
							$Error.Clear()
							Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer > $null
						}

						$process.Close()
						}
					else{
						$Error.Clear()
						Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer > $null
					}
				}
    			} else {$ErrorCheckpoint = "ErrorCheckpoint"}
			if(($error[0] -eq $null) -AND (-not $ErrorCheckpoint)){
				$AdminStatus = $True
				. ([scriptblock]::Create($InvokeWMIRemoting))
				if($UserName -AND $Password){$CheckSessionsAsAdmin = Invoke-WMIRemoting -ComputerName $Computer -UserName $UserName -Password $Password -Command "klist sessions"}
				else{$CheckSessionsAsAdmin = Invoke-WMIRemoting -ComputerName $Computer -Command "klist sessions"}

    				# Check if the sessions list is empty
				if ((-not $CheckSessionsAsAdmin) -or ($CheckSessionsAsAdmin.Count -eq 0)) {
				    # If there's no session, move to the registry check
				    #return $null
					$ErrorCheckpoint = "ErrorCheckpoint"
				}
				
				else{
				
					$CheckSessionsAsAdmin = ($CheckSessionsAsAdmin | Out-String) -split "`n"
					$CheckSessionsAsAdmin = $CheckSessionsAsAdmin.Trim()
					$CheckSessionsAsAdmin = $CheckSessionsAsAdmin | Where-Object { $_ -ne "" }
					
					$pattern = '\s([\w\s-]+\\[\w\s-]+\$?)\s'
					
					$matches = $CheckSessionsAsAdmin | ForEach-Object {
						if ($_ -match $pattern) {
							$matches[1]
						} else {$matches = $null}
					}
					
					if($UserName -AND $Password){
							$UserNameDomainSplit = $UserName -split '\\'
						$UserNameSplit = $UserNameDomainSplit[1]
						$filtered = $matches | Where-Object {
							# Split the entry based on "\"
							$splitEntry = $_ -split '\\'
							($splitEntry[0] -notlike "* *") -and ($splitEntry[0] -ne $TempHostname) -and ($splitEntry[1] -notlike "*$TempHostname*") -and ($splitEntry[1] -notlike "*$UserNameSplit*") -and ($splitEntry[1] -ne $TempCurrentUser)
						}
					}
					else{
						$filtered = $matches | Where-Object {
							# Split the entry based on "\"
							$splitEntry = $_ -split '\\'
							($splitEntry[0] -notlike "* *") -and ($splitEntry[0] -ne $TempHostname) -and ($splitEntry[1] -notlike "*$TempHostname*") -and ($splitEntry[1] -ne $TempCurrentUser)
						}
					}

					$results = @()
					
					foreach($entry in $filtered){
						$results += [PSCustomObject]@{
							Domain           = $Domain
							HostName         = $TempHostname
							IPAddress        = $ipAddress
							OperatingSystem  = $null
							Method           = "Access"
							Access           = $AdminStatus
							UserSession      = $entry
							AdmCount         = "NO"
						}
					}
				}
				
				$Error.Clear()
	   		}

			if(($error[0] -ne $null) -OR $ErrorCheckpoint){
				
				$remoteRegistry = $null
				
				if($FailSafe){
					#$timeoutSeconds = 2
					$checkIntervalMilliseconds = 100
					$elapsedTime = 0
					$processOutput = $null

					# Start the process and capture output directly
					$processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
					$processStartInfo.FileName = "powershell.exe"
					$processStartInfo.Arguments = "-Command ""[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', '$Computer')"""
					$processStartInfo.RedirectStandardOutput = $true
					$processStartInfo.UseShellExecute = $false

					$process = New-Object System.Diagnostics.Process
					$process.StartInfo = $processStartInfo

					$process.Start() | Out-Null

					while (-not $process.HasExited -and $elapsedTime -lt ($timeoutSeconds * 1000)) {
								Start-Sleep -Milliseconds $checkIntervalMilliseconds
								$elapsedTime += $checkIntervalMilliseconds
							}

					if (-not $process.HasExited) {
						# Kill the process if it's still running
						$process.Kill()
									continue
					} else {
						$remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $Computer)
					}

					$process.Close()
				}
				
				else{$remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $Computer)}
				
				if($remoteRegistry -ne $null){
	
					# Get the subkeys under HKEY_USERS
					$userKeys = $remoteRegistry.GetSubKeyNames()
		
					# Initialize an array to store the user SIDs
					$userSIDs = @()
		
					foreach ($key in $userKeys) {
						# Skip common keys that are not user SIDs
						if ($key -match '^[Ss]-\d-\d+-(\d+-){1,14}\d+$') {
							$userSIDs += $key
						}
					}
		
					# Close the remote registry key
					$remoteRegistry.Close()
		
					$results = @()
		
					# Resolve the SIDs to usernames
					foreach ($sid in $userSIDs) {
						$user = $null
						$userTranslation = $null
		
						try {
							$user = New-Object System.Security.Principal.SecurityIdentifier($sid)
							$userTranslation = $user.Translate([System.Security.Principal.NTAccount])
							
							$splitEntry = $userTranslation -split '\\'
							
							if(($splitEntry[0] -notlike "* *") -and ($splitEntry[0] -ne $TempHostname) -and ($splitEntry[1] -notlike "*$TempHostname*") -and ($splitEntry[1] -ne $TempCurrentUser)){
								$results += [PSCustomObject]@{
									Domain           = $Domain
									HostName         = $TempHostname
									IPAddress        = $ipAddress
									OperatingSystem  = $null
									Method           = "Registry"
									Access           = $AdminStatus
									UserSession      = $userTranslation
									AdmCount         = "NO"
								}
							}
						} catch {}
					}
				}
			}
			
			$results = $results | Sort-Object -Unique HostName,UserSession
	
			# Returning the results
			return $results
		}

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($Domain).AddArgument($searcher).AddArgument($InvokeWMIRemoting).AddArgument($UserName).AddArgument($Password).AddArgument($CheckAsAdmin).AddArgument($Timeout).AddArgument($FailSafe)
		$runspace.RunspacePool = $runspacePool
		$runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
	}

	# Wait for all runspaces to complete
	$allResults = @()
	foreach ($runspace in $runspaces) {
	    $allResults += $runspace.Pipe.EndInvoke($runspace.Status)
	    $runspace.Pipe.Dispose()
	}

 	if(!$CheckAsAdmin){
		if($FailSafe){
			if($Timeout){$timeoutSeconds = $Timeout}
      			else{$timeoutSeconds = 2}
			$checkIntervalMilliseconds = 100

			foreach ($result in $allResults) {
				$Computer = "$($result.HostName).$($result.Domain)"
				$elapsedTime = 0
				$ErrorCheckpoint = $null

				# Start the process and capture output directly
				$processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
				$processStartInfo.FileName = "powershell.exe"
				$processStartInfo.Arguments = "-Command ""Get-WmiObject -Class Win32_OperatingSystem -ComputerName '$Computer' > `$null"""
				$processStartInfo.RedirectStandardOutput = $true
				$processStartInfo.UseShellExecute = $false

				$process = New-Object System.Diagnostics.Process
				$process.StartInfo = $processStartInfo

				$process.Start() | Out-Null

				while (-not $process.HasExited -and $elapsedTime -lt ($timeoutSeconds * 1000)) {
					Start-Sleep -Milliseconds $checkIntervalMilliseconds
					$elapsedTime += $checkIntervalMilliseconds
				}

				if (-not $process.HasExited) {
					# Kill the process if it's still running
					$process.Kill()
					$ErrorCheckpoint = "ErrorCheckpoint"
					$result.Access = $false
				} else {
					$Error.Clear()
					Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer > $null
					$result.Access = ($error[0] -eq $null)
				}

				$process.Close()
			}
		}
		
		else{
			# Define RunspacePool
			$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
			$runspacePool.Open()
		
			$runspaces = @()
		
			foreach ($result in $allResults) {
				$target = "$($result.HostName).$($result.Domain)"
				
				$powershell = [powershell]::Create().AddScript({
					$Error.Clear()
					Get-WmiObject -Class Win32_OperatingSystem -ComputerName $args > $null
					#ls "\\$args\c$" > $null
					return ($error[0] -eq $null)
				}).AddArgument($target)
		
				$powershell.RunspacePool = $runspacePool
		
				$runspaces += [PSCustomObject]@{
					PowerShell = $powershell
					Status = $powershell.BeginInvoke()
					Result = $result
				}
			}
		
			# Wait and collect results
			foreach ($runspace in $runspaces) {
				$runspace.Result.Access = [bool]($runspace.PowerShell.EndInvoke($runspace.Status))
				$runspace.PowerShell.Dispose()
			}
		
			$runspacePool.Close()
			$runspacePool.Dispose()
		}
	}
	
	foreach ($result in $allResults) {
		$username = ($result.UserSession -split '\\')[1]
		$TargetHost = $result.HostName
		if($username -like '*$'){$result.AdmCount = "N/A"}
		else{$result.AdmCount = AdminCount -UserName $username -LdapConnection $connection -Domain $Domain}
		$result.OperatingSystem = Get-OS -HostName $TargetHost -LdapConnection $connection -Domain $Domain
	}
	
 	# Show Results

  	$Host.UI.RawUI.ForegroundColor = $currentTextColor
	$Host.UI.RawUI.BackgroundColor = $Color

	if($RawResults){
		if($Hunt){
			if($Match){
				$FinalResults = $allResults | Where-Object { $_.User -like "*$Hunt*" -AND $_.AdmCount -eq $True -AND $_.Access -eq $True} | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession
				$FinalResults
			}
			else{
				$FinalResults = $allResults | Where-Object { $_.User -like "*$Hunt*" } | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession
				$FinalResults
			}
		}
		else{
			if($Match){
				$FinalResults = $allResults | Where-Object {$_.AdmCount -eq $True -AND $_.Access -eq $True} | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession
				$FinalResults
			}
			else{
				$FinalResults = $allResults | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession
				$FinalResults
			}
     		}
	}
	else{
		if($Hunt){
			if($Match){
				$FinalResults = $allResults | Where-Object { $_.User -like "*$Hunt*" -AND $_.AdmCount -eq $True -AND $_.Access -eq $True} | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession | Format-Table -AutoSize
				$FinalResults
			}
			else{
				$FinalResults = $allResults | Where-Object { $_.User -like "*$Hunt*" } | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession | Format-Table -AutoSize
				$FinalResults
			}
		}
		else{
			if($Match){
				$FinalResults = $allResults | Where-Object {$_.AdmCount -eq $True -AND $_.Access -eq $True} | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession | Format-Table -AutoSize
				$FinalResults
			}
			else{
				$FinalResults = $allResults | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession | Format-Table -AutoSize
				$FinalResults
			}
		}
	}

 	$stopwatch.Stop()
	$elapsedTime = $stopwatch.Elapsed

 	$userInfo = "Ran as User: $(whoami)"
	$domainInfo = "Domain: $($env:USERDOMAIN)"
	$hostInfo = "Ran on Host: $($env:COMPUTERNAME).$($env:USERDOMAIN)"
	$dateTime = "Date and Time: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
 	$ResultselapsedTime = "Elapsed time: $($elapsedTime.Hours):$($elapsedTime.Minutes):$($elapsedTime.Seconds).$($elapsedTime.Milliseconds)"

 	$FinalPlusResults = @($userInfo, $domainInfo, $hostInfo, $dateTime, $ResultselapsedTime) + $FinalResults

 	try{
  		$FinalPlusResults | Out-File $pwd\SessionHunter.txt -Force
    		Write-Output "[+] Output saved to: $pwd\SessionHunter.txt"
		Write-Output ""
    	}
  	catch{
   		$FinalPlusResults | Out-File c:\Users\Public\Document\SessionHunter.txt -Force
    		Write-Output "[+] Output saved to: c:\Users\Public\Document\SessionHunter.txt"
		Write-Output ""
    	}

	Write-Host "[+] Elapsed time: $($elapsedTime.Hours):$($elapsedTime.Minutes):$($elapsedTime.Seconds).$($elapsedTime.Milliseconds)"
 	Write-Host ""
	
}

$InvokeWMIRemoting = @'
function Invoke-WMIRemoting {
	
	<#

	.SYNOPSIS
	Invoke-WMIRemoting Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-WMIRemoting
	
	#>
	
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [string]$Command,
		[string]$UserName,
		[string]$Password
    )
	
	if($UserName -AND $Password){
		$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
		$cred = New-Object System.Management.Automation.PSCredential($UserName,$SecPassword)
	}

    $ClassID = "Custom_WMI_" + (Get-Random)
    $KeyID = "CmdGUID"
	
	$Error.Clear()
	
	if($UserName -AND $Password){
		$classExists = Get-WmiObject -Class $ClassID -ComputerName $ComputerName -List -Namespace "root\cimv2" -Credential $cred
	}else{$classExists = Get-WmiObject -Class $ClassID -ComputerName $ComputerName -List -Namespace "root\cimv2"}
	
	if($error[0]){break}
	
	$Error.Clear()
    
	if (-not $classExists) {
		
		if($cred){
			$connectionOptions = New-Object System.Management.ConnectionOptions
			if($UserName -AND $Password){
				$connectionOptions.Username = $UserName
				$connectionOptions.Password = $Password
			}

			$scope = New-Object System.Management.ManagementScope("\\$ComputerName\root\cimv2", $connectionOptions)
			$scope.Connect()
			
			$createNewClass = New-Object System.Management.ManagementClass($scope, [System.Management.ManagementPath]::new(), $null)
			$createNewClass["__CLASS"] = $ClassID
			$createNewClass.Properties.Add($KeyID, [System.Management.CimType]::String, $false)
			$createNewClass.Properties[$KeyID].Qualifiers.Add("Key", $true)
			$createNewClass.Properties.Add("OutputData", [System.Management.CimType]::String, $false)
			$createNewClass.Properties.Add("CommandStatus", [System.Management.CimType]::String, $false)
			$createNewClass.Put() | Out-Null
		}
		else{
			$createNewClass = New-Object System.Management.ManagementClass("\\$ComputerName\root\cimv2", [string]::Empty, $null)
			$createNewClass["__CLASS"] = $ClassID
			$createNewClass.Properties.Add($KeyID, [System.Management.CimType]::String, $false)
			$createNewClass.Properties[$KeyID].Qualifiers.Add("Key", $true)
			$createNewClass.Properties.Add("OutputData", [System.Management.CimType]::String, $false)
			$createNewClass.Properties.Add("CommandStatus", [System.Management.CimType]::String, $false)
			$createNewClass.Put() | Out-Null
		}
    }
	
	if($error[0]){break}
	
	$Error.Clear()
	
	if($cred){$wmiData = Set-WmiInstance -Class $ClassID -ComputerName $ComputerName -Credential $cred}
	else{$wmiData = Set-WmiInstance -Class $ClassID -ComputerName $ComputerName}
	
	$wmiData.GetType() | Out-Null
	$GuidOutput = ($wmiData | Select-Object -Property $KeyID -ExpandProperty $KeyID)
	$wmiData.Dispose()

	
	if($error[0]){break}

    $RunCmd = {
        param ([string]$CmdInput)
		$resultData = $null
		$wmiDataOutput = $null
        $base64Input = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($CmdInput))
        $commandStr = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand $base64Input"
        $finalCommand = "`$outputData = &$commandStr | Out-String; Get-WmiObject -Class $ClassID -Filter `"$KeyID = '$GuidOutput'`" | Set-WmiInstance -Arguments `@{OutputData = `$outputData; CommandStatus='Completed'} | Out-Null"
        $finalCommandBase64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($finalCommand))
        if($cred){$startProcess = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -Credential $cred -ArgumentList ("powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $finalCommandBase64)}
		else{$startProcess = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList ("powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $finalCommandBase64)}

        if ($startProcess.ReturnValue -ne 0) {
			throw "Failed to start process on $ComputerName. Return value: $($startProcess.ReturnValue)"
			return
		}
		
		if ($startProcess.ReturnValue -eq 0) {
			$elapsedTime = 0
			$timeout = 60
			do {
				Start-Sleep -Seconds 1
				$elapsedTime++
				if($cred){$wmiDataOutput = Get-WmiObject -Class $ClassID -ComputerName $ComputerName -Credential $cred -Filter "$KeyID = '$GuidOutput'"}
				else{$wmiDataOutput = Get-WmiObject -Class $ClassID -ComputerName $ComputerName -Filter "$KeyID = '$GuidOutput'"}
				if ($wmiDataOutput.CommandStatus -eq "Completed") {
					break
				}
			} while ($elapsedTime -lt $timeout)
            $resultData = $wmiDataOutput.OutputData
			$wmiDataOutput.CommandStatus = "NotStarted"
			$wmiDataOutput.Put() | Out-Null
            $wmiDataOutput.Dispose()
            return $resultData
        } else {
            throw "Failed to run command on $ComputerName."
			return
        }
    }

    if ($Command) {
        $finalResult = & $RunCmd -CmdInput $Command
        Write-Output $finalResult
    } else {
        do {
            $inputFromUser = Read-Host "[$ComputerName]: PS:\>"
            if ($inputFromUser -eq 'exit') {
                Write-Output ""
                break
            }
            if ($inputFromUser) {
                $finalResult = & $RunCmd -CmdInput $inputFromUser
                Write-Output $finalResult
            }
        } while ($true)
    }
	
	
	if($cred){
		# Create a CimSession with the provided credentials
		if($UserName -AND $Password) {
			$sessionOptions = New-CimSessionOption -Protocol Dcom
			$cimSession = New-CimSession -Credential $cred -ComputerName $ComputerName -SessionOption $sessionOptions
		} else {
			$cimSession = New-CimSession -ComputerName $ComputerName
		}

		# Use the CimSession to delete the class
		$cimInstance = Get-CimInstance -Namespace "ROOT\CIMV2" -ClassName $ClassID -CimSession $cimSession -ErrorAction SilentlyContinue
		if ($cimInstance) {
			Remove-CimInstance -CimInstance $cimInstance
		}

		# Optionally, remove the session when done
		$cimSession | Remove-CimSession
	}
	else{([wmiclass]"\\$ComputerName\ROOT\CIMV2:$ClassID").Delete()}
}
'@

function Establish-LDAPSession {
    param (
        [string]$Domain,
        [string]$DomainController
    )

    $ErrorActionPreference = "SilentlyContinue"

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

function Get-ADComputers {
    param (
        [string]$ADCompDomain,
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection  # The previously established connection
    )

    $ErrorActionPreference = "SilentlyContinue"

    # Construct distinguished name for the domain.
    $domainDistinguishedName = "DC=" + ($ADCompDomain -replace "\.", ",DC=")

    # Set up an LDAP search request.
    $ldapFilter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $attributesToLoad = @("dNSHostName")

    $allcomputers = @()

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
            $allcomputers += $entry.Attributes["dNSHostName"][0]
        }

    } while ($pageRequest.Cookie.Length -ne 0)

    return $allcomputers
}

function Get-ADWorkstations {
    param (
        [string]$ADCompDomain,
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection  # The previously established connection
    )

    $ErrorActionPreference = "SilentlyContinue"

    # Construct distinguished name for the domain.
    $domainDistinguishedName = "DC=" + ($ADCompDomain -replace "\.", ",DC=")

    # Set up an LDAP search request.
    $ldapFilter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(operatingSystem=*Server*)))"
    $attributesToLoad = @("dNSHostName")

    $allcomputers = @()

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
            $allcomputers += $entry.Attributes["dNSHostName"][0]
        }

    } while ($pageRequest.Cookie.Length -ne 0)

    return $allcomputers
}

function Get-ADServers {
    param (
        [string]$ADCompDomain,
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection  # The previously established connection
    )

    $ErrorActionPreference = "SilentlyContinue"

    # Construct distinguished name for the domain.
    $domainDistinguishedName = "DC=" + ($ADCompDomain -replace "\.", ",DC=")

    # Set up an LDAP search request.
    $ldapFilter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*Server*))"
    $attributesToLoad = @("dNSHostName")

    $allcomputers = @()

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
            $allcomputers += $entry.Attributes["dNSHostName"][0]
        }

    } while ($pageRequest.Cookie.Length -ne 0)

    return $allcomputers
}

function AdminCount {
    param (
        [string]$UserName,
		[string]$Domain,
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )

    $ErrorActionPreference = "SilentlyContinue"

    # Assuming all user objects are under the default "CN=Users" container.
    # Adjust this according to your Active Directory structure.
    $domainDistinguishedName = "DC=" + ($Domain -replace "\.", ",DC=")
    $baseDN = "CN=Users," + $domainDistinguishedName  # Replace with your domain DN

    # Set up the search filter
    $ldapFilter = "(sAMAccountName=$UserName)"
    $attributesToLoad = @("adminCount")

    $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $baseDN,            # Base DN
        $ldapFilter,        # LDAP filter
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        $attributesToLoad   # Attributes to retrieve
    )

    # Perform the search using the LdapConnection.
    $searchResponse = $LdapConnection.SendRequest($searchRequest)

    # Check if results were returned and output the adminCount property.
    if ($searchResponse.Entries -ne $null -and $searchResponse.Entries.Count -ne 0) {
        $entry = $searchResponse.Entries[0]
        if ($entry.Attributes["adminCount"] -ne $null -and $entry.Attributes["adminCount"].Count -gt 0) {
            $adminCount = $entry.Attributes["adminCount"][0]
            return ($adminCount -eq 1)
		} else {
            return $false
        }
    } else {
        return $false
    }
}

function Get-OS {
    param (
        [string]$HostName,
		[string]$Domain,
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )

    $ErrorActionPreference = "SilentlyContinue"

    # Construct the search base. Assuming all computer objects are under the default "CN=Computers" container.
    # You might need to adjust this if your AD structure differs.
	$baseDN = "DC=" + ($Domain -replace "\.", ",DC=")

    $ldapFilter = "(&(objectCategory=computer)(name=$HostName))"
    $attributesToLoad = @("operatingSystem")

    $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $baseDN,            # Base DN
        $ldapFilter,        # LDAP filter
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        $attributesToLoad   # Attributes to retrieve
    )

    # Perform the search using the LdapConnection.
    $searchResponse = $LdapConnection.SendRequest($searchRequest)

    # Check if results were returned and output the operatingSystem property.
    if ($searchResponse.Entries.Count -eq 0) {
        return $null
    } else {
        # The following line retrieves the 'operatingSystem' attribute from the search result.
        return $searchResponse.Entries[0].Attributes["operatingSystem"][0].ToString()
    }
}
