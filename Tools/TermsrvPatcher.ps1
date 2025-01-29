if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    switch ((Get-Culture).Name) {
        'pt-BR' { Write-Output 'Você não executou este script como Administrador. Este script será executado automaticamente como Administrador.' }
        Default { Write-Output 'You didn''t run this script as an Administrator. This script will self elevate to run as an Administrator and continue.' }
    }

    Start-Sleep -Milliseconds 2500
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

$OSArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture

$termsrvDllFile = "$env:SystemRoot\System32\termsrv.dll"
$termsrvDllCopy = "$env:SystemRoot\System32\termsrv.dll.copy"
$termsrvPatched = "$env:SystemRoot\System32\termsrv.dll.patched"

$patterns = @{
    Pattern = [regex]'39 81 3C 06 00 00 0F (?:[0-9A-F]{2} ){4}00'
    Win24H2 = [regex]'8B 81 38 06 00 00 39 81 3C 06 00 00 75'
}

function Get-OSInfo {
    $OSInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    [PSCustomObject]@{
        CurrentBuild = $OSInfo.CurrentBuild
        BuildRevision = $OSInfo.UBR
        FullOSBuild = "$($OSInfo.CurrentBuild).$($OSInfo.UBR)"
        DisplayVersion = $OSInfo.DisplayVersion
        InstallationType = $OSInfo.InstallationType
    }
}

function Get-OSVersion {
    [version]$OSVersion = [System.Environment]::OSVersion.Version
    $installationType = (Get-OSInfo).InstallationType

    if ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 1) {
        return 'Windows 7'
    } elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 22000 -and $installationType -eq 'Client') {
        return 'Windows 10'
    } elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -gt 22000) {
        return 'Windows 11'
    } elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 22000 -and $installationType -eq 'Server') {
        return 'Windows Server 2016'
    } elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -eq 20348) {
        return 'Windows Server 2022'
    } else {
        return 'Unsupported OS'
    }
}

function Update-Dll {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [regex]$InputPattern,

        [Parameter(Mandatory)]
        [string]$Replacement,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsText,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsFile,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsPatch,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSecurity]$TermsrvAclObject
    )

    begin {
        $match = $TermsrvDllAsText -match $InputPattern
        $patch = $TermsrvDllAsText -match $Replacement
    }

    process {
        if ($match) {
            Write-Output "`nPattern matching!`n"

            $dllAsTextReplaced = $TermsrvDllAsText -replace $InputPattern, $Replacement

            # Use the replaced string to create a byte array again.
            [byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'

            # Create termsrv.dll.patched from the byte array.
            [System.IO.File]::WriteAllBytes($TermsrvDllAsPatch, $dllAsBytesReplaced)

            fc.exe /b $TermsrvDllAsPatch $TermsrvDllAsFile
            <#
            .DESCRIPTION
                Compare patched and original DLL (/b: binary comparison) and displays the differences between them.
            .NOTES
                Expected output something like:

                00098BA2: B8 8B
                00098BA3: 00 99
                00098BA4: 01 30
                00098BA5: 00 03
                00098BA7: 89 00
                00098BA8: 81 8B
                00098BA9: 38 B1
                00098BAA: 06 34
                00098BAB: 00 03
                00098BAD: 90 00
            #>

            Start-Sleep -Milliseconds 1500

            # Overwrite original DLL with patched version:
            Copy-Item -Path $TermsrvDllAsPatch -Destination $TermsrvDllAsFile -Force
        } elseif ($patch) {
            Write-Output "The file is already patched. No changes are needed.`n"
        } else {
            Write-Output "The pattern was not found. Nothing will be changed.`n"
        }

        # Restore original Access Control List (ACL):
        Set-Acl -Path $TermsrvDllAsFile -AclObject $TermsrvAclObject

        # Start services again...
        Start-Service TermService -PassThru
    }
}

function Stop-TermService {
    try {
        Stop-Service -Name TermService -Force -ErrorAction Stop
    } catch {
        Write-Warning -Message $_.Exception.Message
        return
    }

    while ((Get-Service -Name TermService).Status -ne 'Stopped') {
        Start-Sleep -Milliseconds 500
    }

    Write-Output "`nThe Remote Desktop Services (TermService) has been stopped sucsessfully`n"
}

Stop-TermService

# Save Access Control List (ACL) of termsrv.dll file.
$termsrvDllAcl = Get-Acl -Path $termsrvDllFile

Write-Output "Owner of termsrv.dll: $($termsrvDllAcl.Owner)"

# Create a backup of the original termsrv.dll file.
Copy-Item -Path $termsrvDllFile -Destination $termsrvDllCopy -Force

# Take ownership of the DLL...
takeown.exe /F $termsrvDllFile

# Get Current logged in user (changed by .NET class, because in remote connection WMI Object cannot retrieve the user)
$currentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Grant full control to the currently logged in user.
icacls.exe $termsrvDllFile /grant "$($currentUserName):F"

# Read termsrv.dll as byte array to modify bytes
$dllAsByte = [System.IO.File]::ReadAllBytes($termsrvDllFile)

# Convert the byte array to a string that represents each byte value as a hexadecimal value, separated by spaces
$dllAsText = ($dllAsByte | ForEach-Object { $_.ToString('X2') }) -join ' '

$commonParams = @{
    TermsrvDllAsText = $dllAsText
    TermsrvDllAsFile = $termsrvDllFile
    TermsrvDllAsPatch = $termsrvPatched
    TermsrvAclObject = $termsrvDllAcl
}

switch (Get-OSVersion) {
    'Windows 7' {
        if ($OSArchitecture -eq '64-bit') {
            switch ((Get-OSInfo).FullOSBuild) {
                '7601.23964' {
                    $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 2F C3 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                    -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                    -replace '83 7C 24 50 00 74 18 48 8D', '83 7C 24 50 00 EB 18 48 8D'
                }
                '7601.24546' {
                    $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                    -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                    -replace '83 7C 24 50 00 74 43 48 8D', '83 7C 24 50 00 EB 18 48 8D'
                }
                Default {
                    $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                    -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                    -replace '83 7C 24 50 00 74 43 48 8D', '83 7C 24 50 00 EB 18 48 8D'
                }
            }
        }

        # Use the replaced string to create a byte array again.
        [byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'

        # Create termsrv.dll.patched from the byte array.
        [System.IO.File]::WriteAllBytes($termsrvPatched, $dllAsBytesReplaced)

        fc.exe /B $termsrvPatched $termsrvDllFile
        <#
        .DESCRIPTION
            Compares termsrv.dll with tersrv.dll.patched and displays the differences between them.
        .NOTES
            Expected output something like:

            00098BA2: B8 8B
            00098BA3: 00 99
            00098BA4: 01 30
            00098BA5: 00 03
            00098BA7: 89 00
            00098BA8: 81 8B
            00098BA9: 38 B1
            00098BAA: 06 34
            00098BAB: 00 03
            00098BAD: 90 00
        #>

        Start-Sleep -Milliseconds 1500

        # Overwrite original DLL with patched version:
        Copy-Item -Path $termsrvPatched -Destination $termsrvDllFile -Force

        # Restore original Access Control List (ACL):
        Set-Acl -Path $termsrvDllFile -AclObject $termsrvDllAcl

        Start-Sleep -Milliseconds 2500

        # Start services again...
        Start-Service TermService -PassThru
    }
    'Windows 10' {
        Update-Dll @commonParams -InputPattern $patterns.Pattern -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90'
    }
    'Windows 11' {
        if ((Get-OSInfo).DisplayVersion -eq '23H2') {
            Update-Dll @commonParams -InputPattern $patterns.Pattern -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90'
        } elseif ((Get-OSInfo).DisplayVersion -eq '24H2') {
            Update-Dll @commonParams -InputPattern $patterns.Win24H2 -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90 EB'
        }
    }
    'Windows Server 2016' {
        Update-Dll @commonParams -InputPattern $patterns.Pattern -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90'
    }
    'Windows Server 2022' {
        Update-Dll @commonParams -InputPattern $patterns.Pattern -Replacement 'B8 00 01 00 00 89 81 38 06 00 00 90'
    }
    'Unsupported OS' {
        Write-Output 'Unable to get OS Version'
    }
}
