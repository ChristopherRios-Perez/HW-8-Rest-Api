import { Hono } from 'hono'

import { getDb } from '../data/db.js'
import { createSession, deleteSessionByTokenHash, deleteExpiredSessions, findSessionByTokenHash } from '../data/sessions.repository.js'
import { createUser, findUserByEmail } from '../data/users.repository.js'
import { parseJsonBody } from '../utils/body.js'
import { signAccessToken, refreshTokenExpiresAt } from '../utils/auth.js'
import { hashPassword, verifyPassword, generateRefreshToken, hashToken } from '../utils/crypto.js'
import { ApiError } from '../utils/errors.js'
import { sendResource } from '../utils/response.js'
import { validateLogin, validateLogout, validateRefresh, validateRegister } from '../utils/validation.js'

const auth = new Hono()

auth.post('/register', async (c) => {
  const payload = await parseJsonBody(c)
  const details = validateRegister(payload)

  if (details.length > 0) {
    throw new ApiError(422, 'VALIDATION_ERROR', 'Some fields are invalid.', details)
  }

  const db = getDb(c.env.DB)
  const existing = await findUserByEmail(db, payload.email)

  if (existing) {
    throw new ApiError(409, 'CONFLICT', 'Email already in use.')
  }

  const passwordHash = await hashPassword(payload.password)
  const user = await createUser(db, { email: payload.email, passwordHash })

  c.header('Location', `/api/auth/users/${user.id}`)
  return sendResource(c, { id: user.id, email: user.email, createdAt: user.createdAt }, 201)
})

auth.post('/login', async (c) => {
  const payload = await parseJsonBody(c)
  const details = validateLogin(payload)

  if (details.length > 0) {
    throw new ApiError(422, 'VALIDATION_ERROR', 'Some fields are invalid.', details)
  }

  const db = getDb(c.env.DB)
  const user = await findUserByEmail(db, payload.email)

  if (!user) {
    throw new ApiError(401, 'UNAUTHORIZED', 'Invalid credentials.')
  }

  const valid = await verifyPassword(payload.password, user.passwordHash)

  if (!valid) {
    throw new ApiError(401, 'UNAUTHORIZED', 'Invalid credentials.')
  }

  await deleteExpiredSessions(db, user.id)

  const accessToken = await signAccessToken({ sub: user.id, email: user.email }, c.env.JWT_SECRET)
  const refreshToken = generateRefreshToken()
  const tokenHash = await hashToken(refreshToken)

  await createSession(db, { userId: user.id, tokenHash, expiresAt: refreshTokenExpiresAt() })

  return sendResource(c, { access_token: accessToken, refresh_token: refreshToken })
})

auth.post('/refresh', async (c) => {
  const payload = await parseJsonBody(c)
  const details = validateRefresh(payload)

  if (details.length > 0) {
    throw new ApiError(422, 'VALIDATION_ERROR', 'Some fields are invalid.', details)
  }

  const db = getDb(c.env.DB)
  const tokenHash = await hashToken(payload.refresh_token)
  const session = await findSessionByTokenHash(db, tokenHash)

  if (!session) {
    throw new ApiError(401, 'UNAUTHORIZED', 'Invalid refresh token.')
  }

  if (new Date(session.expiresAt) < new Date()) {
    await deleteSessionByTokenHash(db, tokenHash)
    throw new ApiError(401, 'UNAUTHORIZED', 'Refresh token has expired.')
  }

  const accessToken = await signAccessToken({ sub: session.userId }, c.env.JWT_SECRET)

  return sendResource(c, { access_token: accessToken })
})

auth.post('/logout', async (c) => {
  const payload = await parseJsonBody(c)
  const details = validateLogout(payload)

  if (details.length > 0) {
    throw new ApiError(422, 'VALIDATION_ERROR', 'Some fields are invalid.', details)
  }

  const db = getDb(c.env.DB)
  const tokenHash = await hashToken(payload.refresh_token)
  await deleteSessionByTokenHash(db, tokenHash)

  return c.body(null, 204)
})

export default auth
