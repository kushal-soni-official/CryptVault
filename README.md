# 🔒 CryptVault

**CryptVault** is a security-first, "Zero-Knowledge" encrypted file storage system integrated with a suite of professional cybersecurity analysis tools. It is designed to ensure that private data remains private, even from the storage provider, while giving security researchers a unified interface for network and vulnerability analysis.

---

## 🚀 Quick Start (Root Folder Access)

You can now run CryptVault directly from this root directory using our new wrapper scripts. No need to navigate deep into folders!

### 🐧 For Linux Users:
1. **Initialize Vault:** `./vault.sh cli init`
2. **Launch Web UI:** `./vault.sh web`
3. **Scan Network:** `./vault.sh cli scan-network <target>`

### 🪟 For Windows Users:
1. **Initialize Vault:** `vault.bat cli init`
2. **Launch Web UI:** `vault.bat web`
3. **Scan Network:** `vault.bat cli scan-network <target>`

---

## 🛠️ Main Features

*   **Zero-Knowledge Encryption**: All files are encrypted on your local machine using **AES-256-GCM** before being stored. The server never sees your master password or unencrypted data.
*   **Two-Factor Authentication (2FA)**: Mandatory TOTP (Time-based One-Time Password) setup via apps like Google Authenticator or Authy.
*   **Integrated Cyber Tools**:
    *   **Nmap Integration**: Direct port scanning from the CLI.
    *   **CVE Lookup**: Query the NIST NVD for known software vulnerabilities.
    *   **Packet Analysis**: Analyze PCAP files for suspicious network patterns using Scapy.

---

## 📋 Installation

### 1. Requirements
*   Python 3.10 or higher
*   Pip (Python package manager)
*   *Note: Nmap must be installed on your system for network scanning features.*

### 2. Setup
```bash
# Clone or enter the project directory
cd cryptvault

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

---

## 🔮 Future Scope

As this project evolves, we aim to implement the following high-impact features:
*   **Cloud Synchronization**: Securely sync encrypted vaults across Google Drive, Dropbox, or AWS S3 while maintaining zero-knowledge integrity.
*   **Hardware Token Support**: Integration with YubiKey and other HSMs for physical multi-factor authentication.
*   **Multi-User Shared Vaults**: Implementing proxy re-encryption to allow users to securely share specific encrypted files without ever sharing their master keys.
*   **Mobile Companion App**: A mobile interface for viewing file metadata, performing remote vault locks, and managing 2FA keys.

---

## ⚠️ Warnings
*   **Do Not Lose Your Master Password**: Since this is zero-knowledge, there is **no password recovery**. If you lose your password and your 2FA device, your data is gone forever.
*   **Network Scanning Ethics**: Only use the network scanning tools on hardware and networks you own or have explicit permission to test.
*   **PCAP Sizes**: Large PCAP files (over 500MB) may cause high memory usage during analysis.

---

## 💡 Suggestions & Notes
*   **Suggestion**: Use a long, complex passphrase as your master password. A 12+ character phrase is recommended.
*   **Note**: All stored files are located at `~/.cryptvault/files` on Linux or `C:\Users\<User>\.cryptvault\files` on Windows.
*   **Compatibility**: This project is fully tested on Ubuntu 22.04+ and Windows 10/11.

---

## ⚖️ License
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details. (Note: This is a project intended for security research and educational purposes).

---
<div align="center">
  <i>"Efficiency is doing things right; effectiveness is doing the right things."</i>
</div>
