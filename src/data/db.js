import { drizzle } from 'drizzle-orm/d1'
import * as schema from './schema'

export function getDb(connection) {
  return drizzle(connection, { schema })
}

export function nowIso() {
  return new Date().toISOString()
}