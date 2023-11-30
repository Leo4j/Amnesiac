function Invoke-SessionHunter {
	
	<#

	.SYNOPSIS
	Invoke-SessionHunter Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-SessionHunter
	
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

	$ldapretrieveddomain = $False
	
	if($UserName -AND $Password){$CheckAsAdmin = $True}
	
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
		if($Servers){
			$objSearcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*Server*))"
		}

		elseif($Workstations){
			$objSearcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(operatingSystem=*Server*)))"
		}
		
		else{
			$objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		}
		$objSearcher.PageSize = 1000
		$Computers = $objSearcher.FindAll() | ForEach-Object { $_.properties.dnshostname }
		$Computers = $Computers | Sort-Object -Unique
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
		else{$result.AdmCount = AdminCount -UserName $username -Domain $Domain}
		$result.OperatingSystem = Get-OS -HostName $TargetHost -Domain $Domain
	}
	
 	# Show Results
	$FinalResults = $allResults | Sort-Object -Unique Domain,Access,AdmCount,HostName,UserSession | Format-Table -AutoSize -Wrap | Out-String -Width 4096
	if($FinalResults){
	 	$lines = $FinalResults -split "`n"
		foreach($line in $lines) {
		    Write-Output $line
		}
  	} else {Write-Output "[-] No Sessions Retrieved"}

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

function AdminCount {
    param (
        [string]$UserName,
        [string]$Domain
    )

    $ErrorActionPreference = "SilentlyContinue"

    # Construct distinguished name for the domain.
    $domainDistinguishedName = "DC=" + ($Domain -replace "\.", ",DC=")
    $baseDN = "CN=Users,$domainDistinguishedName"  # Replace with your domain DN

    # Set up the search filter
    $ldapFilter = "(sAMAccountName=$UserName)"
    $attributesToLoad = @("adminCount")

    # Create the directory searcher
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$baseDN")
    $searcher.Filter = $ldapFilter
    $searcher.PropertiesToLoad.Add($attributesToLoad) > $null

    # Perform the search
    $result = $searcher.FindOne()

    # Check if results were returned and output the adminCount property.
    if ($result -ne $null) {
        $entry = $result.GetDirectoryEntry()
        if ($entry.Properties["adminCount"].Value -ne $null) {
            return ($entry.Properties["adminCount"].Value -eq 1)
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
        [string]$Domain
    )

    $ErrorActionPreference = "SilentlyContinue"

    # Construct the search base.
    $baseDN = "DC=" + ($Domain -replace "\.", ",DC=")

    $ldapFilter = "(&(objectCategory=computer)(name=$HostName))"
    $attributesToLoad = "operatingSystem"

    # Create the directory searcher
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$baseDN")
    $searcher.Filter = $ldapFilter
    $searcher.PropertiesToLoad.Add($attributesToLoad) > $null

    # Perform the search
    $result = $searcher.FindOne()

    # Check if results were returned and output the operatingSystem property.
    if ($result -ne $null) {
        $entry = $result.GetDirectoryEntry()
        if ($entry.Properties["operatingSystem"].Value -ne $null) {
            return $entry.Properties["operatingSystem"].Value.ToString()
        } else {
            return $null
        }
    } else {
        return $null
    }
}
