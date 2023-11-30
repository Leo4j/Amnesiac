function Validate-Credentials {
    param(
        [string]$UserName,
        [string]$Password,
        [string]$Domain
    )

    $LDAPPath = "LDAP://"
    $LDAPPath += $Domain

    try {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($LDAPPath, $UserName, $Password)
        if ($directoryEntry.name -ne $null) {
            Write-Output "[+] Authentication Successful for user $UserName"
        } else {
            Write-Output "[-] Authentication Failed for user $UserName"
        }
    } catch {
        Write-Output "[-] Error occurred during authentication for user $UserName : $_"
    }
}
