// utils/encryption.js
const crypto = require('crypto');
const KEY = Buffer.from(process.env.ENCRYPTION_KEY_BASE64, 'base64'); // 32 bytes

if (!KEY || KEY.length !== 32) {
  throw new Error('Invalid ENCRYPTION_KEY_BASE64. Provide a base64 32-byte key.');
}

function encrypt(plain) {
  if (plain === null || plain === undefined) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

function decrypt(b64) {
  if (!b64) return null;
  const data = Buffer.from(b64, 'base64');
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const ct = data.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  return plain.toString('utf8');
}

module.exports = { encrypt, decrypt };
