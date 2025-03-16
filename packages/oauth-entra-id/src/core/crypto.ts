import crypto from 'node:crypto';

/**
 * Encodes a UTF-8 string to a Base64 URL-safe string.
 * @param {string} str - The input string.
 * @returns {string} The Base64 URL-encoded string.
 */
export const encodeBase64 = (str: string): string => Buffer.from(str, 'utf8').toString('base64url');

/**
 * Decodes a Base64 URL-safe string to a UTF-8 string.
 * @param {string} str - The Base64 URL-encoded string.
 * @returns {string} The decoded UTF-8 string.
 */
export const decodeBase64 = (str: string): string => Buffer.from(str, 'base64url').toString('utf8');

/**
 * Hashes a string using SHA-256.
 * @param {string} str - The input string.
 * @returns {Buffer} The SHA-256 hash as a Buffer.
 */
export const hash = (str: string): Buffer => crypto.createHash('sha256').update(str).digest();

/**
 * Creates a cryptographic secret key from a given string.
 * @param {string} key - The input string.
 * @returns {crypto.KeyObject} The generated secret key.
 */
export const createSecretKey = (key: string): crypto.KeyObject => crypto.createSecretKey(hash(key));

const PREFIX = 'OA2.';

/**
 * Encrypts a string using AES-256-GCM.
 * @param {string} data - The data to encrypt.
 * @param {crypto.KeyObject} secretKey - The secret key used for encryption.
 * @returns {string} The encrypted data in Base64 URL format with a prefix.
 * @throws {Error} If encryption fails.
 */
export function encrypt(data: string, secretKey: crypto.KeyObject): string {
  try {
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return PREFIX + [iv, encrypted, tag].map((buffer) => buffer.toString('base64url')).join('.');
  } catch {
    throw new Error('Failed to encrypt');
  }
}

/**
 * Decrypts an AES-256-GCM encrypted string.
 * @param {string} encryptedData - The encrypted data string with prefix.
 * @param {crypto.KeyObject} secretKey - The secret key used for decryption.
 * @returns {string} The decrypted string.
 * @throws {Error} If decryption fails or data format is invalid.
 */
export function decrypt(encryptedData: string, secretKey: crypto.KeyObject): string {
  try {
    if (!encryptedData.startsWith(PREFIX)) throw new Error('Invalid decrypt data format');
    const strippedData = encryptedData.slice(PREFIX.length);
    const [ivBase64, encryptedBase64, tagBase64] = strippedData.split('.');
    if (!ivBase64 || !encryptedBase64 || !tagBase64) throw new Error('Invalid decrypt data format');

    const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, Buffer.from(ivBase64, 'base64url'));
    decipher.setAuthTag(Buffer.from(tagBase64, 'base64url'));

    const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedBase64, 'base64url')), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    throw new Error('Failed to decrypt');
  }
}

/**
 * Encrypts an object using AES-256-GCM.
 * @param {Record<string, unknown>} data - The object to encrypt.
 * @param {crypto.KeyObject} secretKey - The secret key used for encryption.
 * @returns {string} The encrypted object as a Base64 URL string.
 * @throws {Error} If encryption fails.
 */
export function encryptObject(data: Record<string, unknown>, secretKey: crypto.KeyObject): string {
  try {
    return encrypt(JSON.stringify(data), secretKey);
  } catch {
    throw new Error('Failed to encrypt object');
  }
}

/**
 * Decrypts an AES-256-GCM encrypted object.
 * @param {string} data - The encrypted object string.
 * @param {crypto.KeyObject} secretKey - The secret key used for decryption.
 * @returns {Record<string, unknown>} The decrypted object.
 * @throws {Error} If decryption fails.
 */
export function decryptObject(data: string, secretKey: crypto.KeyObject): Record<string, unknown> {
  try {
    return JSON.parse(decrypt(data, secretKey));
  } catch {
    throw new Error('Failed to decrypt object');
  }
}
