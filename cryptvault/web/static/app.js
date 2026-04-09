/**
 * CryptVault — Premium Client-Side Encryption
 * Developer: Kushal Soni
 * All encryption/decryption happens in-browser via Web Crypto API.
 */

// ── UTILS ─────────────────────────────────────────────────────

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    // Simple icon choice based on type
    const icon = type === 'success' ? '✅' : (type === 'error' ? '❌' : 'ℹ️');
    
    toast.innerHTML = `<span>${icon}</span> ${message}`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ── CRYPTO ────────────────────────────────────────────────────

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 250000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

function bufToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function hexToBuf(hex) {
    const bytes = new Uint8Array(Math.ceil(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
}

// ── UI INITIALIZATION ──────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Format all existing sizes in the table
    document.querySelectorAll('.file-size-cell').forEach(cell => {
        const bytes = parseInt(cell.getAttribute('data-bytes'));
        if (!isNaN(bytes)) {
            cell.textContent = formatBytes(bytes);
        }
    });

    // Password Visibility Toggle
    const toggleBtn = document.getElementById('toggle-password-btn');
    const passwordInput = document.getElementById('master-password');
    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener('click', () => {
            const isPassword = passwordInput.type === 'password';
            passwordInput.type = isPassword ? 'text' : 'password';
            toggleBtn.innerHTML = isPassword 
                ? '<svg class="icon-svg" style="width:20px; height:20px;" viewBox="0 0 24 24"><path d="M9.88 9.88 3.59 3.59"/><path d="M2 12s3-7 10-7a7.14 7.14 0 0 1 3.49.93"/><path d="M22 12s-3 7-10 7a7.14 7.14 0 0 1-3.49-.93"/><path d="m14.12 14.12-6.24-6.24"/><circle cx="12" cy="12" r="3"/><path d="m15 15 5.41 5.41"/></svg>'
                : '<svg class="icon-svg" style="width:20px; height:20px;" viewBox="0 0 24 24"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>';
        });
    }

    // Real-time Search
    const searchInput = document.getElementById('vault-search');
    const tableRows = document.querySelectorAll('.file-row');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            tableRows.forEach(row => {
                const fileName = row.querySelector('.name-text').textContent.toLowerCase();
                row.style.display = fileName.includes(query) ? '' : 'none';
            });
        });
    }

    // Drag & Drop
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const nameDisplay = document.getElementById('file-name-display');

    if (dropZone && fileInput) {
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = 'var(--gold-primary)';
            dropZone.style.background = 'rgba(212, 175, 55, 0.1)';
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.style.borderColor = 'var(--glass-border)';
            dropZone.style.background = 'rgba(0,0,0,0.1)';
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = 'var(--glass-border)';
            dropZone.style.background = 'rgba(0,0,0,0.1)';
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                nameDisplay.textContent = `Selected: ${fileInput.files[0].name}`;
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                nameDisplay.textContent = `Selected: ${fileInput.files[0].name}`;
            }
        });
    }
});

// ── CORE ACTIONS ─────────────────────────────────────────────

document.getElementById("upload-btn").addEventListener("click", async () => {
    const password = document.getElementById("master-password").value;
    const fileInput = document.getElementById("file-input");

    if (!password) {
        showToast("Access Key required for encryption.", "error");
        return;
    }
    if (fileInput.files.length === 0) {
        showToast("Please select a file to secure.", "error");
        return;
    }

    const file = fileInput.files[0];
    if (file.size > 100 * 1024 * 1024) {
        showToast("File exceeds 100MB limit.", "error");
        return;
    }

    try {
        const arrayBuffer = await file.arrayBuffer();
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const key = await deriveKey(password, salt);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        showToast("Cryptographic processing active...", "info");
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            arrayBuffer
        );

        const formData = new FormData();
        formData.append("file", new Blob([encryptedBuffer]), file.name);
        formData.append("nonce", bufToHex(iv));
        formData.append("tag", "included_in_ciphertext");
        formData.append("salt", bufToHex(salt));
        formData.append("original_size", file.size);

        const response = await fetch("/api/upload", {
            method: "POST",
            body: formData
        });

        if (response.ok) {
            showToast("Asset secured in vault.", "success");
            setTimeout(() => window.location.reload(), 1200);
        } else {
            const err = await response.json();
            showToast(err.detail || "Vault rejection.", "error");
        }
    } catch (e) {
        console.error(e);
        showToast("Encryption Engine failure.", "error");
    }
});

async function downloadAndDecrypt(fileId, originalName) {
    const password = document.getElementById("master-password").value;
    if (!password) {
        showToast("Password required for decryption.", "error");
        return;
    }

    try {
        showToast("Fetching encrypted payload...", "info");
        const response = await fetch(`/api/download/${fileId}`);
        if (!response.ok) throw new Error("Network rejection");

        const nonceHex = response.headers.get("X-Nonce");
        const saltHex = response.headers.get("X-Salt");
        const encryptedBlob = await response.blob();
        const encryptedBuffer = await encryptedBlob.arrayBuffer();

        const salt = new Uint8Array(hexToBuf(saltHex));
        const key = await deriveKey(password, salt);
        const iv = hexToBuf(nonceHex);

        showToast("Decryption in progress...", "info");
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedBuffer
        );

        const downloadUrl = URL.createObjectURL(new Blob([decryptedBuffer]));
        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = originalName;
        a.click();
        URL.revokeObjectURL(downloadUrl);
        showToast("File decrypted and downloaded.", "success");

    } catch (e) {
        console.error(e);
        showToast("Decryption failed. Invalid key.", "error");
    }
}

async function deleteFile(fileId, fileName) {
    if (!confirm(`Permanently purge "${fileName}" from vault?`)) return;

    try {
        const response = await fetch(`/api/files/${fileId}`, { method: "DELETE" });
        if (response.ok) {
            document.getElementById(`file-${fileId}`).remove();
            const countStat = document.getElementById('vault-count-stat');
            if (countStat) countStat.textContent = parseInt(countStat.textContent) - 1;
            showToast("Asset purged successfully.", "success");
        } else {
            showToast("Purge request failed.", "error");
        }
    } catch (e) {
        console.error(e);
        showToast("Purge Engine error.", "error");
    }
}
