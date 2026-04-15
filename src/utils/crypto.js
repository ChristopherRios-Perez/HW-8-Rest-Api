import bcryptjs from 'bcryptjs'

import { BCRYPT_ROUNDS } from './constants.js'

export async function hashPassword(plain) {
  return bcryptjs.hash(plain, BCRYPT_ROUNDS)
}

export async function verifyPassword(plain, hash) {
  return bcryptjs.compare(plain, hash)
}

export function generateRefreshToken() {
  return crypto.randomUUID()
}

export async function hashToken(raw) {
  const encoded = new TextEncoder().encode(raw)
  const buffer = await crypto.subtle.digest('SHA-256', encoded)
  const bytes = new Uint8Array(buffer)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
