import { and, eq, lt } from 'drizzle-orm'

import { nowIso } from './db.js'
import { sessions } from './schema.js'

export async function createSession(db, { userId, tokenHash, expiresAt }) {
  const [created] = await db
    .insert(sessions)
    .values({
      userId,
      tokenHash,
      expiresAt,
      createdAt: nowIso(),
    })
    .returning()
  return created
}

export async function findSessionByTokenHash(db, tokenHash) {
  const [session] = await db
    .select()
    .from(sessions)
    .where(eq(sessions.tokenHash, tokenHash))
  return session || null
}

export async function deleteSessionByTokenHash(db, tokenHash) {
  const deleted = await db
    .delete(sessions)
    .where(eq(sessions.tokenHash, tokenHash))
    .returning({ id: sessions.id })
  return deleted.length > 0
}

export async function deleteExpiredSessions(db, userId) {
  await db
    .delete(sessions)
    .where(and(eq(sessions.userId, userId), lt(sessions.expiresAt, nowIso())))
}
