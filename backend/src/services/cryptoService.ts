import crypto from 'crypto';
import logger from '../utils/logger';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const KEY_LENGTH = 32;

export function ensureClientProfileKey(): void {
  const keyHex = process.env.CLIENT_PROFILE_KEY;

  if (!keyHex) {
    throw new Error(
      'CLIENT_PROFILE_KEY não definida no .env. ' +
      'Gere uma com: node -e "console.log(require(\"crypto\").randomBytes(32).toString(\"hex\"))"'
    );
  }

  const keyBuffer = Buffer.from(keyHex, 'hex');
  if (keyBuffer.length !== KEY_LENGTH) {
    throw new Error(
      "CLIENT_PROFILE_KEY deve ter " + KEY_LENGTH + " bytes (" + (KEY_LENGTH * 2) + " chars hex). " +
      "Atual: " + keyBuffer.length + " bytes."
    );
  }

  logger.info('CLIENT_PROFILE_KEY validated successfully');
}

export function generateClientProfileKey(): string {
  return crypto.randomBytes(KEY_LENGTH).toString('hex');
}

function getKeyBuffer(): Buffer {
  return Buffer.from(process.env.CLIENT_PROFILE_KEY!, 'hex');
}

export function encryptConfig(config: Record<string, unknown>): {
  iv: string;
  authTag: string;
  ciphertext: string;
} {
  const key = getKeyBuffer();
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const plaintext = JSON.stringify(config);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  };
}

export function decryptConfig(
  iv: string,
  authTag: string,
  ciphertext: string
): Record<string, unknown> {
  const key = getKeyBuffer();

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString('utf8'));
}
