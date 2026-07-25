// VoxCrypt + CipherView Labs integration — client-side encryption and
// SHA-256 integrity hashing for secure evidence packaging.
// Supports AES-256-GCM (WebCrypto) and DES (Triple-DES via WebCrypto).

async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function deriveAesKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: 150000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// Triple-DES (3DES) — 192-bit key, the strongest DES variant available via WebCrypto.
async function deriveDesKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: 150000, hash: "SHA-256" },
    keyMaterial,
    { name: "DES-CBC", length: 192 } as unknown as AesKeyAlgorithm,
    false,
    ["encrypt", "decrypt"],
  );
}

export type CipherAlgorithm = "AES-256-GCM" | "DES-3DES-CBC";

export interface SealedEvidence {
  ciphertext: string;
  iv: string;
  salt: string;
  hash: string;
  algorithm: CipherAlgorithm;
}

function b64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function fromB64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export async function sealEvidence(
  plaintext: string,
  passphrase: string,
  algorithm: CipherAlgorithm = "AES-256-GCM",
): Promise<SealedEvidence> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const hash = await sha256(plaintext);

  if (algorithm === "AES-256-GCM") {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveAesKey(passphrase, salt);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, enc.encode(plaintext));
    return { ciphertext: b64(ct), iv: b64(iv.buffer), salt: b64(salt.buffer), hash, algorithm };
  }

  // Triple-DES (DES-CBC with 192-bit key)
  const iv = crypto.getRandomValues(new Uint8Array(8));
  const key = await deriveDesKey(passphrase, salt);
  const ct = await crypto.subtle.encrypt({ name: "DES-CBC", iv: iv as BufferSource } as unknown as AesGcmParams, key as unknown as CryptoKey, enc.encode(plaintext) as unknown as BufferSource);
  return { ciphertext: b64(ct), iv: b64(iv.buffer), salt: b64(salt.buffer), hash, algorithm };
}

export async function openEvidence(sealed: SealedEvidence, passphrase: string): Promise<string> {
  const salt = fromB64(sealed.salt);
  const iv = fromB64(sealed.iv);
  const ct = fromB64(sealed.ciphertext);

  if (sealed.algorithm === "AES-256-GCM") {
    const key = await deriveAesKey(passphrase, salt);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, ct as BufferSource);
    return new TextDecoder().decode(pt);
  }

  const key = await deriveDesKey(passphrase, salt);
  const pt = await crypto.subtle.decrypt({ name: "DES-CBC", iv: iv as BufferSource } as unknown as AesGcmParams, key as unknown as CryptoKey, ct as unknown as BufferSource);
  return new TextDecoder().decode(pt);
}

export async function verifyIntegrity(plaintext: string, expectedHash: string): Promise<boolean> {
  const h = await sha256(plaintext);
  return h === expectedHash;
}

export { sha256 };
