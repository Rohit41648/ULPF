/**
 * AES-256-GCM encryption with SHA-256 integrity hashing.
 *
 * RSA has been removed — the shared AES key is fetched over HTTPS/TLS.
 * The browser encrypts payloads with AES-256-GCM using the shared key,
 * and attaches a SHA-256 hash of the plaintext for tamper detection.
 */

let cachedKeyPromise = null

function bytesToBase64Url(bytes) {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/**
 * Compute a SHA-256 hex digest of the given bytes using the Web Crypto API.
 */
async function sha256Hex(data) {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Import the shared AES-256 key from hex string into a CryptoKey.
 */
async function importAesKey(hexKey) {
  const keyBytes = new Uint8Array(hexKey.match(/.{2}/g).map((b) => parseInt(b, 16)))
  return window.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  )
}

/**
 * Fetch and cache the shared AES key from the backend.
 */
async function getSharedKey(fetchEncryptionKey) {
  if (!cachedKeyPromise) {
    cachedKeyPromise = fetchEncryptionKey()
      .then((keyData) => importAesKey(keyData.key_hex))
      .catch((error) => {
        cachedKeyPromise = null
        throw error
      })
  }
  return cachedKeyPromise
}

/**
 * Encrypt a JSON payload using AES-256-GCM with the shared key.
 *
 * @param {object} payload - The JSON-serializable payload to encrypt
 * @param {function} fetchEncryptionKey - Async function returning { key_hex }
 * @returns {{ version, algorithm, iv, ciphertext, integrity_hash }}
 */
export async function encryptPayload(payload, fetchEncryptionKey) {
  if (!window.crypto?.subtle) {
    throw new Error('This browser does not support Web Crypto API.')
  }

  const aesKey = await getSharedKey(fetchEncryptionKey)
  const iv = window.crypto.getRandomValues(new Uint8Array(12))
  const plaintext = new TextEncoder().encode(JSON.stringify(payload))

  // Compute SHA-256 integrity hash of the plaintext BEFORE encryption.
  // The backend will re-hash the decrypted data and compare to detect tampering.
  const integrityHash = await sha256Hex(plaintext)

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    plaintext,
  )

  return {
    version: 1,
    algorithm: 'A256GCM',
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
    integrity_hash: integrityHash,
  }
}
