$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin) {
    Write-Host "[+] " -ForegroundColor Green -NoNewline
    Write-Host "Confirmed Script is Running as Administrator"
} else {
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host "Script Needs to be run as Administrator"
    exit
}

Write-Host "[+] " -ForegroundColor Green -NoNewline
Write-Host "Creating C:\bin Directory for Tools"
New-Item -ItemType Directory -Path "C:\bin"

Add-MpPreference -ExclusionPath "C:\bin" -Force
Write-Host "[+] " -ForegroundColor Green -NoNewline
Write-Host "Adding C:\bin to Defender Exclusion List"

Write-Host "[+] " -ForegroundColor Green -NoNewline
Write-Host "Current Defender Exclusions:"
Get-MpPreference | Select-Object ExclusionPath

Write-Host "[+] " -ForegroundColor Green -NoNewline
Write-Host "Downloading Tools"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cdnet01/Toolbox/refs/heads/main/tools.zip" -OutFile "C:\bin\tools.zip"
Expand-Archive C:\bin\tools.zip -DestinationPath C:\bin
Remove-Item -Path "C:\bin\tools.zip"

Write-Host "[+] " -ForegroundColor Green -NoNewline
Write-Host "Adding C:\bin to Path"
Set-PathVariable AddPath 'C:\bin'

Write-Host "[+] " -ForegroundColor Green -NoNewline
Write-Host "Adding BGInfo Config"
Bginfo.exe C:\bin\etc\config.bgi

Write-Host "[+] " -ForegroundColor Yellow -NoNewline
Write-Host "Done!"