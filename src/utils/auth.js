import { sign, verify } from 'hono/jwt'

import { ACCESS_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_DAYS } from './constants.js'

export async function signAccessToken(payload, secret) {
  const now = Math.floor(Date.now() / 1000)
  return sign(
    {
      ...payload,
      iat: now,
      exp: now + ACCESS_TOKEN_TTL_SECONDS,
    },
    secret,
  )
}

export async function verifyAccessToken(token, secret) {
  return verify(token, secret, 'HS256')
}

export function refreshTokenExpiresAt() {
  const date = new Date()
  date.setDate(date.getDate() + REFRESH_TOKEN_TTL_DAYS)
  return date.toISOString()
}
