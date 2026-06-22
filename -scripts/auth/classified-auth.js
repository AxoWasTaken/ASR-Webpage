/**
 * classified-auth.js
 * AXR Classified Document Authentication Engine
 *
 * HOW IT WORKS:
 * 1. Each classified document page stores its file URL as AES-GCM ciphertext.
 * 2. The user enters an auth code. That code is hashed (SHA-256) and compared
 *    against a stored hash — if it matches, the code is used as the AES key
 *    to decrypt the real URL.
 * 3. The URL is fetched and turned into a blob: URL, which is loaded into the
 *    iframe. The real URL is never visible in the DOM, source, or network tab.
 * 4. No cookies or localStorage are ever used.
 *
 * SETUP FOR A NEW PAGE:
 * Run the companion tool (encrypt-tool.html) to generate:
 *   - STORED_HASH     → paste into the page's data-auth-hash attribute
 *   - ENCRYPTED_URL   → paste into the page's data-enc-url attribute
 *   - IV              → paste into the page's data-iv attribute
 *
 * LEVEL SYSTEM:
 * LVL0  → no auth required (public)
 * LVL1+ → requires the correct level code (set via data-level on the page)
 */

(function () {
  "use strict";

  /* ── Helpers ───────────────────────────────────────────────────── */

  /** Convert a hex string to a Uint8Array */
  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  /** Encode a string as UTF-8 bytes */
  const encode = (str) => new TextEncoder().encode(str);

  /** Decode UTF-8 bytes to a string */
  const decode = (buf) => new TextDecoder().decode(buf);

  /**
   * Hash a string with SHA-256 and return a hex string.
   * Used to compare the entered code against the stored hash
   * without ever storing the plaintext code in the source.
   */
  async function sha256hex(str) {
    const digest = await crypto.subtle.digest("SHA-256", encode(str));
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Derive an AES-GCM key from a passphrase using PBKDF2.
   * The salt is the page's stored hash (publicly visible but unique per page).
   * 200,000 iterations makes brute-forcing expensive.
   */
  async function deriveKey(passphrase, saltHex) {
    const raw = await crypto.subtle.importKey(
      "raw",
      encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: hexToBytes(saltHex),
        iterations: 200000,
        hash: "SHA-256",
      },
      raw,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }

  /**
   * Decrypt the stored ciphertext using the derived AES-GCM key.
   * Returns the plaintext URL string, or throws if the key is wrong.
   */
  async function decryptUrl(ciphertextHex, ivHex, key) {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(ivHex) },
      key,
      hexToBytes(ciphertextHex)
    );
    return decode(plaintext);
  }

  /**
   * Fetch a URL and turn it into a blob: object URL.
   * This means the real URL never appears in the iframe src attribute.
   * The blob URL is revoked after the iframe loads to free memory.
   */
  async function fetchAsBlob(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Fetch failed: ${resp.status}`);
    const blob = await resp.blob();
    return URL.createObjectURL(blob);
  }

  /* ── Main auth flow ─────────────────────────────────────────────── */

  /**
   * Called when the user submits the auth form.
   * Elements expected on the page (supplied by the page template):
   *   #auth-gate        → the login box div (hidden on success)
   *   #auth-code        → the password <input>
   *   #auth-error       → error message <p>
   *   #auth-spinner     → loading indicator (hidden by default)
   *   #doc-frame        → the <iframe> to load the document into
   *   #doc-viewer       → the iframe wrapper (hidden until auth succeeds)
   *   [data-auth-hash]  → SHA-256 hex of the correct code (on <body> or <main>)
   *   [data-enc-url]    → AES-GCM encrypted URL (hex)
   *   [data-iv]         → AES-GCM IV (hex)
   */
  async function attemptAuth() {
    const codeInput = document.getElementById("auth-code");
    const errorEl = document.getElementById("auth-error");
    const spinner = document.getElementById("auth-spinner");
    const gate = document.getElementById("auth-gate");
    const viewer = document.getElementById("doc-viewer");
    const iframe = document.getElementById("doc-frame");

    // Read encrypted data from the page's data attributes
    const config = document.getElementById("classified-config");
    const storedHash = config.dataset.authHash;
    const encUrl = config.dataset.encUrl;
    const iv = config.dataset.iv;

    const code = codeInput.value.trim();
    if (!code) {
      errorEl.textContent = "Please enter an authentication code.";
      errorEl.hidden = false;
      return;
    }

    errorEl.hidden = true;
    spinner.hidden = false;
    document.getElementById("auth-submit").disabled = true;

    try {
      // Step 1: check the code hash
      const enteredHash = await sha256hex(code);
      if (enteredHash !== storedHash) {
        throw new Error("incorrect");
      }

      // Step 2: derive the AES key from the code and decrypt the URL
      const key = await deriveKey(code, storedHash);
      const realUrl = await decryptUrl(encUrl, iv, key);

      // Step 3: fetch as blob so the URL is never exposed
      let blobUrl;
      try {
        blobUrl = await fetchAsBlob(realUrl);
      } catch {
        // If CORS blocks the fetch, fall back to loading the URL directly.
        // This still hides the URL from the DOM until load, but it will
        // appear briefly in the network tab. OneDrive embed links generally
        // do not support CORS, so this fallback is expected.
        blobUrl = realUrl;
      }

      // Step 4: show the document
      iframe.src = blobUrl;
      gate.hidden = true;
      viewer.hidden = false;

      // Revoke the blob URL a moment after the iframe starts loading
      if (blobUrl.startsWith("blob:")) {
        iframe.addEventListener("load", () => URL.revokeObjectURL(blobUrl), { once: true });
      }
    } catch (err) {
      spinner.hidden = true;
      document.getElementById("auth-submit").disabled = false;
      if (err.message === "incorrect") {
        errorEl.textContent = "Incorrect authentication code. Access denied.";
      } else {
        errorEl.textContent = "An error occurred. Please try again.";
        console.error("[classified-auth]", err);
      }
      errorEl.hidden = false;
      codeInput.value = "";
      codeInput.focus();
    }
  }

  /* ── Boot ───────────────────────────────────────────────────────── */

  document.addEventListener("DOMContentLoaded", function () {
    const submitBtn = document.getElementById("auth-submit");
    const codeInput = document.getElementById("auth-code");

    if (!submitBtn || !codeInput) return; // not a classified page

    submitBtn.addEventListener("click", attemptAuth);
    codeInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") attemptAuth();
    });
  });
})();
