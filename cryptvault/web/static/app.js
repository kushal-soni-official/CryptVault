// ============================================================
//  CryptVault — Client-Side Encryption (Web UI)
//  All encryption/decryption happens in the browser.
//  The server never sees your password or plaintext data.
// ============================================================

/**
 * Derive an AES-256-GCM key from a password + random salt using PBKDF2.
 * NOTE: The CLI uses Argon2id. Files are NOT cross-compatible between
 * CLI and Web UI — each tracks its "source" to prevent mismatched decryption.
 */
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

function displayStatus(msg, type = "info") {
    const statusDiv = document.getElementById("upload-status");
    statusDiv.textContent = msg;
    statusDiv.className = "status-msg " + "status-" + type + " show";
    
    // Auto-hide success messages after 5 seconds
    if (type === "success") {
        setTimeout(() => {
            statusDiv.classList.remove("show");
        }, 5000);
    }
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

// ── Upload & Encrypt ──────────────────────────────────────────

document.getElementById("upload-btn").addEventListener("click", async () => {
    const password = document.getElementById("master-password").value;
    const fileInput = document.getElementById("file-input");

    if (!password) {
        displayStatus("Please enter your master password.", "error");
        return;
    }
    if (fileInput.files.length === 0) {
        displayStatus("Please select a file.", "error");
        return;
    }

    const file = fileInput.files[0];

    // Client-side file size check (100 MB)
    if (file.size > 100 * 1024 * 1024) {
        displayStatus("File too large. Maximum size is 100 MB.", "error");
        return;
    }

    const arrayBuffer = await file.arrayBuffer();

    try {
        // Generate a unique random salt for this file (16 bytes)
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const key = await deriveKey(password, salt);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        displayStatus("Encrypting...", "info");
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            arrayBuffer
        );

        const combinedBlob = new Blob([encryptedBuffer]);

        displayStatus("Uploading...", "info");
        const formData = new FormData();
        formData.append("file", combinedBlob, file.name);
        formData.append("nonce", bufToHex(iv));
        formData.append("tag", "included_in_ciphertext");
        formData.append("salt", bufToHex(salt));
        formData.append("original_size", file.size);

        const response = await fetch("/api/upload", {
            method: "POST",
            body: formData
        });

        if (response.ok) {
            displayStatus("File uploaded securely!", "success");
            // Refresh table after a short delay
            setTimeout(() => window.location.reload(), 1500);
        } else {
            const err = await response.json();
            displayStatus(err.detail || "Upload failed.", "error");
        }
    } catch (e) {
        console.error(e);
        displayStatus("Encryption failed. Check console for details.", "error");
    }
});

// ── Download & Decrypt ────────────────────────────────────────

async function downloadAndDecrypt(fileId, originalName) {
    const password = document.getElementById("master-password").value;
    if (!password) {
        alert("Please enter your master password to decrypt this file.");
        return;
    }

    try {
        const response = await fetch(`/api/download/${fileId}`);
        if (!response.ok) throw new Error("Failed to download");

        const nonceHex = response.headers.get("X-Nonce");
        const saltHex = response.headers.get("X-Salt");
        const encryptedBlob = await response.blob();
        const encryptedBuffer = await encryptedBlob.arrayBuffer();

        // Use the per-file salt that was stored during upload
        const salt = new Uint8Array(hexToBuf(saltHex));
        const key = await deriveKey(password, salt);
        const iv = hexToBuf(nonceHex);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedBuffer
        );

        const decryptedBlob = new Blob([decryptedBuffer]);
        const downloadUrl = URL.createObjectURL(decryptedBlob);

        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = originalName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(downloadUrl);

    } catch (e) {
        console.error(e);
        alert("Decryption failed. Incorrect password or corrupted file.");
    }
}

// ── Delete File ───────────────────────────────────────────────

async function deleteFile(fileId, fileName) {
    if (!confirm(`Permanently delete "${fileName}"? This cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch(`/api/files/${fileId}`, { method: "DELETE" });
        if (response.ok) {
            // Remove the row from the table without full page reload
            const row = document.getElementById(`file-${fileId}`);
            if (row) row.remove();

            // Check if vault is now empty
            const tbody = document.querySelector("#files-table tbody");
            if (tbody && tbody.children.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4">Vault is empty.</td></tr>';
            }
        } else {
            alert("Failed to delete file.");
        }
    } catch (e) {
        console.error(e);
        alert("Delete request failed.");
    }
}
