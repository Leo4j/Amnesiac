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
