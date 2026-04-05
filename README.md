<div align="center">
  <h1>🔒 CryptVault</h1>
  <p><strong>A "Zero-Knowledge" Encrypted File Storage System with Integrated Cyber Tools</strong></p>
  
  <p>
    <img alt="Python" src="https://img.shields.io/badge/Python-3.10+-blue.svg" />
    <img alt="Encryption" src="https://img.shields.io/badge/Encryption-AES--256--GCM-green.svg" />
    <img alt="Security" src="https://img.shields.io/badge/Security-2FA%20Enabled-orange.svg" />
    <img alt="Web UI" src="https://img.shields.io/badge/Interface-Web%20%26%20CLI-yellow.svg" />
  </p>
</div>

---

## 🌟 What is CryptVault?

**CryptVault** is like a super-secure digital safe designed for your files. Whether you are dealing with sensitive notes, passwords, or personal data, CryptVault ensures that nobody—not even the server itself—can sneak a peek.

### ✨ Key Features:
* 🛡️ **Military-Grade Encryption:** Uses highly secure math (`AES-256-GCM` and `Argon2id`) to lock your files down tightly before they ever leave your device.
* 👁️ **"Zero-Knowledge" Architecture:** The server acts strictly as a storage locker. It never sees your password and cannot read your unscrambled files. 
* 📱 **Two-Factor Authentication (2FA):** Just like your bank or social media, it requires a time-based code from an app like **Google Authenticator** or **Authy** for an extra layer of security.
* 🛠️ **Built-in Hacker Tools:** Comes equipped with a suite of cybersecurity analysis tools like an Nmap scanner, a vulnerability checker, and a network traffic analyzer!

---

## 🚀 Step 1: Easy Installation (Beginner Friendly!)

To run CryptVault, make sure you have Python installed on your computer. 
Open your terminal (or command prompt), go to the project folder, and run these commands:

```bash
# 1. Move into the project directory
cd cryptvault

# 2. Create a safe bubble for your Python app (Virtual Environment)
python3 -m venv venv

# 3. Activate the virtual environment
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# 4. Install CryptVault and all its dependencies
pip install -e .
```

---

## 💻 Step 2: Using the Command Line (CLI)

The Command Line Interface (CLI) gives you fast, text-based control over your vault and cyber tools. With your `venv` activated, you can simply use the `cryptvault` command anywhere!

### 🔐 Setting Up Your Vault
The very first thing you need to do is initialize your vault.
```bash
cryptvault init
```
*(This will ask you to set a Master Password and give you a QR Code. Scan the QR code with your phone's authenticator app!)*

### 📁 Managing Your Files
* **To lock a file into the vault:**
  ```bash
  cryptvault store my_secret_file.txt
  ```
* **To browse what's inside your vault:**
  ```bash
  cryptvault list
  ```
* **To retrieve and unlock a file:**
  ```bash
  cryptvault retrieve <paste-the-file-id-here>
  ```

### 🧰 Bonus Cybersecurity Tools
CryptVault is packed with utilities for analysis:
* **Scan a website/server for open ports:** 
  ```bash
  cryptvault scan-network scanme.nmap.org
  ```
* **Check for known software bugs (CVEs):** 
  ```bash
  cryptvault cve-check python 3.10
  ```
* **Analyze network traffic traps (PCAP files):**
  ```bash
  cryptvault packet-analyze traffic_capture.pcap
  ```

---

## 🌐 Step 3: Using the Web Dashboard

If you prefer a beautiful visual interface instead of the black-and-white terminal, CryptVault has a web dashboard!

To start the Web Server, enter this command:
```bash
python -m cryptvault.web.app
```

Now, open your favorite web browser (Chrome, Firefox, Safari) and visit:
👉 **[http://localhost:8000](http://localhost:8000)** 👈

From the dashboard, you can point, click, and drag to safely encrypt and upload files straight from your browser. 
*(Note: CryptVault uses modern Web Crypto APIs to mathematically lock your files inside your browser BEFORE uploading them. True zero-knowledge!)*

---
<div align="center">
  <i>Created for college cybersecurity submissions. Built cleanly and defensively.</i>
</div>
