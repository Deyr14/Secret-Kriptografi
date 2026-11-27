// Modul Kriptografi Client-Side (AES-256-GCM menggunakan Web Crypto API)
const CryptoEngine = (() => {
  // Konversi ArrayBuffer <-> Base64URL (aman untuk parameter URL #key=)
  function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlToBuffer(base64Url) {
    let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Enkripsi Plaintext -> { ciphertext, iv, key }
  async function encryptMessage(plainText) {
    // 1. Bangkitkan kunci simetris acak AES-256 (256-bit)
    const cryptoKey = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // 2. Bangkitkan Initialization Vector (IV) acak 12-byte (96-bit)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // 3. Enkripsi teks menggunakan AES-256-GCM
    const encodedText = new TextEncoder().encode(plainText);
    const cipherBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      encodedText
    );

    // 4. Ekspor kunci mentah untuk ditaruh di URL fragment (#key=)
    const rawKeyBuffer = await window.crypto.subtle.exportKey("raw", cryptoKey);

    return {
      ciphertext: bufferToBase64Url(cipherBuffer),
      iv: bufferToBase64Url(iv),
      key: bufferToBase64Url(rawKeyBuffer),
    };
  }

  // Dekripsi (ciphertext, iv, key) -> Plaintext
  async function decryptMessage(ciphertextBase64Url, ivBase64Url, keyBase64Url) {
    const rawKeyBuffer = base64UrlToBuffer(keyBase64Url);
    const ivBuffer = base64UrlToBuffer(ivBase64Url);
    const cipherBuffer = base64UrlToBuffer(ciphertextBase64Url);

    const cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      rawKeyBuffer,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(ivBuffer) },
      cryptoKey,
      cipherBuffer
    );

    return new TextDecoder().decode(decryptedBuffer);
  }

  return {
    encryptMessage,
    decryptMessage,
  };
})();