const crypto = require('crypto');

const KDF_ITER = 200000;
const KEY_LEN = 32;

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, KDF_ITER, KEY_LEN, 'sha256');
}

function encryptMessage(plaintext, password) {
  if (!password) throw new Error('Password required');
  const salt = crypto.randomBytes(16);
  const key = deriveKey(Buffer.from(password), salt);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cfb', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return Buffer.concat([salt, iv, ciphertext]).toString('base64');
}

function decryptMessage(b64combined, password) {
  if (!password) throw new Error('Password required');
  const raw = Buffer.from(b64combined, 'base64');
  if (raw.length < 32) throw new Error('Payload too short');
  const salt = raw.slice(0, 16);
  const iv = raw.slice(16, 32);
  const ciphertext = raw.slice(32);
  const key = deriveKey(Buffer.from(password), salt);
  const decipher = crypto.createDecipheriv('aes-256-cfb', key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

module.exports = { encryptMessage, decryptMessage };
