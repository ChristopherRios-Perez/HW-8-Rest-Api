import { eq } from 'drizzle-orm'

import { nowIso } from './db.js'
import { users } from './schema.js'

export async function findUserByEmail(db, email) {
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.email, email.toLowerCase()))
  return user || null
}

export async function createUser(db, { email, passwordHash }) {
  const timestamp = nowIso()
  const [created] = await db
    .insert(users)
    .values({
      email: email.toLowerCase(),
      passwordHash,
      createdAt: timestamp,
      updatedAt: timestamp,
    })
    .returning()
  return created
}
