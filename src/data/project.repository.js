import { asc, eq } from 'drizzle-orm'
import { nowIso } from './db'
import { projects } from './schema'

function normalizeProjectInput(input) {
  return {
    name: input.name?.trim(),
    description: input.description?.trim() || '',
  }
}

export async function listProjects(db) {
  return db.select().from(projects).orderBy(asc(projects.id))
}

export async function getProjectById(db, id) {
  const [project] = await db.select().from(projects).where(eq(projects.id, id))
  return project || null
}

export async function createProject(db, input) {
  const timestamp = nowIso()

  const values = {
    ...normalizeProjectInput(input),
    createdAt: timestamp,
    updatedAt: timestamp,
  }

  const [created] = await db.insert(projects).values(values).returning()
  return created
}

export async function updateProject(db, id, input) {
  const values = {
    updatedAt: nowIso(),
    ...('name' in input ? { name: input.name.trim() } : {}),
    ...('description' in input
      ? { description: input.description.trim() }
      : {}),
  }

  const [updated] = await db
    .update(projects)
    .set(values)
    .where(eq(projects.id, id))
    .returning()

  return updated || null
}

export async function deleteProject(db, id) {
  const deleted = await db
    .delete(projects)
    .where(eq(projects.id, id))
    .returning({ id: projects.id })

  return deleted.length > 0
}