// Note: Native Web Crypto API supports PBKDF2 directly. For high compatibility without CDNs,
// we'll use PBKDF2. To exactly match the CLI's Argon2id we would need WebAssembly.
// Given the "keep it simple and working for college", PBKDF2 with 250,000 iterations is very strong.
const SALT = new TextEncoder().encode("cryptvault-static-salt-adjust-later");

async function deriveKey(password) {
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
            salt: SALT,
            iterations: 250000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

function displayStatus(msg, color = "black") {
    const statusDiv = document.getElementById("upload-status");
    statusDiv.style.color = color;
    statusDiv.textContent = msg;
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

document.getElementById("upload-btn").addEventListener("click", async () => {
    const password = document.getElementById("master-password").value;
    const fileInput = document.getElementById("file-input");

    if (!password) {
        displayStatus("Please enter your master password.", "red");
        return;
    }
    if (fileInput.files.length === 0) {
        displayStatus("Please select a file.", "red");
        return;
    }

    const file = fileInput.files[0];
    const arrayBuffer = await file.arrayBuffer();

    try {
        const key = await deriveKey(password);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        displayStatus("Encrypting...", "blue");
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            arrayBuffer
        );

        // AES-GCM output is ciphertext + tag (last 16 bytes). 
        // We will send the whole blob and let python store nonce separately, 
        // and tag conceptually. In JS, they are combined. 
        const combinedBlob = new Blob([encryptedBuffer]);
        
        displayStatus("Uploading...", "blue");
        const formData = new FormData();
        formData.append("file", combinedBlob, file.name);
        formData.append("nonce", bufToHex(iv));
        formData.append("tag", "included_in_ciphertext");
        formData.append("original_size", file.size);

        const response = await fetch("/api/upload", {
            method: "POST",
            body: formData
        });

        if (response.ok) {
            displayStatus("File uploaded securely!", "green");
            setTimeout(() => window.location.reload(), 1500);
        } else {
            displayStatus("Upload failed.", "red");
        }
    } catch (e) {
        console.error(e);
        displayStatus("Encryption failed.", "red");
    }
});

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
        const encryptedBlob = await response.blob();
        const encryptedBuffer = await encryptedBlob.arrayBuffer();

        const key = await deriveKey(password);
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
