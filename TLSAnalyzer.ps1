<#
Name: TLSAnalyzer.ps1
    Author: Josh Jerdon
    Email: jojerd@microsoft.com
	Requires: Administrative Priveleges, Exchange Management Shell
    Version History:
    1.0 Initial Release

MIT License

Copyright (c) 2020 jojerd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

   .SYNOPSIS
    Used to analyze the TCP SSL / TLS Secure Channel to provide a list of enabled protocols on a per-server basis.
    Collects Enabled Protocols, Certificates, Keylength and Signature Algorithms.
#>
# Global Setting - Have to set PowerShell to trust untrusted or invalid certificates just in case a server returns an invalid certificate.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
# Checking Powershell Version to Ensure Script Works as Intended
if ($PSVersionTable.PSVersion.Major -gt 3) {
    Write-Host "PowerShell meets minimum version requirements, continuing" -ForegroundColor Green
    Start-Sleep -Seconds 3
    Clear-Host
}
else {
    Write-Host "PowerShell does not meet minimum version requirements To Continue" -ForegroundColor Red
    Write-Error "PowerShell needs to be at least Version 3 or higher." -ErrorAction Stop
    Exit    
}
# Set File Output Parameters
$OutputFileName = "TLSAnalyzer" + "-" + (Get-Date).ToString("MMddyyyyHHmmss") + ".csv"
$OutputFilePath = "."
$Output = $OutputFilePath + "\" + $OutputFileName
  
# Add Exchange Management Capabilities Into The Current PowerShell Session If It Is Not Already Loaded.
$CheckSnapin = (Get-PSSnapin | Where-Object { $_.Name -eq "Microsoft.Exchange.Management.PowerShell.E2010" } | Select-Object Name)
if ($CheckSnapin -like "*Exchange.Management.PowerShell*") {
    Write-Host " "
    Write-Host "Exchange Snap-in already loaded, continuing...." -ForegroundColor Green
    Clear-Host
}
else {
    Write-Host " "
    Write-Host "Loading Exchange Snap-in Please Wait..."
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction Stop
    Clear-Host
}
# Prompt For Namespace That Should Be On a Certificate In Order to Make a Secure Channel Connection.
Write-Host " "
[string]$HostName = Read-Host -Prompt "Namespace to use in order to check certificate and secure channel details. Example: mail.contoso.com"
Clear-Host
# Search local AD Site for all Exchange Servers.
$ADSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
Write-Host " "
Write-Host "Searching Active Directory Site $ADSite for Exchange Servers, Please Wait..."
$Servers = Get-ExchangeServer | Where-Object { $_.Site -match $ADSite }
Clear-Host  
# Get List of Protocols We Are Going to Test from .NET.
$Protocols = [System.Security.Authentication.SslProtocols] | Get-Member -static -MemberType Property | Where-Object { $_.Name -notin @("Default", "None") } | ForEach-Object { $_.Name }
# Port Used to Initiate A Secure Connection.
[int]$Port = 443
if ($Servers.count -gt 0) { 
    foreach ($Server in $Servers) {
        $ExchServer = $Server.Name
        $Ping = New-Object System.Net.NetworkInformation.Ping
        $ServerIP = ($Ping.Send($ExchServer).Address).IPAddressToString
        $Protocols | ForEach-Object {
            $ProtocolName = $_
            $SocketClient = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
            $SocketClient.Connect($ServerIP, $Port)
            try {
                $NetStream = New-Object System.Net.Sockets.NetworkStream($SocketClient, $true)
                $SecureChannel = New-Object System.Net.Security.SslStream($NetStream, $true)
                $SecureChannel.AuthenticateAsClient($HostName, $null, $ProtocolName, $false)
                $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SecureChannel.RemoteCertificate
                $ConnectedCipher = [System.Security.Authentication.CipherAlgorithmType]$SecureChannel.CipherAlgorithm
                $ProtocolStatus = "True"
                  
            }

            catch {
                $ProtocolStatus = "False"
                
            }
            $Report = [PSCustomObject]@{
                Server               = $ExchServer
                Certificate          = $Certificate.Subject
                Thumbprint           = $Certificate.Thumbprint
                CertIssueDate        = $Certificate.NotBefore
                CertExpires          = $Certificate.NotAfter
                KeyLength            = $Certificate.PublicKey.Key.KeySize
                CertificateSignature = $Certificate.SignatureAlgorithm.FriendlyName
                CipherUsed           = $ConnectedCipher
                ProtocolName         = $ProtocolName
                ProtocolEnabled      = $ProtocolStatus
            
            }
            $SocketClient.Dispose()
            $SecureChannel.Dispose()
            $Report | Export-Csv $Output -Append -NoTypeInformation
  
        }
    }
    
}
else {
    Write-Error "Unable to obtain list of servers to check against."
    Read-Host -Prompt "Hit Enter to Exit"
    Exit
}
Clear-Host
Write-Host " "
Write-Host "Script has completed successfully" -ForegroundColor Green