import { Hono } from 'hono'

import { getDb } from '../data/db.js'
import {
  createProject,
  deleteProject,
  getProjectById,
  listProjects,
  updateProject,
} from '../data/projects.repository.js'
import { createTask, listTasksByProject } from '../data/tasks.repository.js'
import { parseJsonBody } from '../utils/body.js'
import { ApiError } from '../utils/errors.js'
import { sendCollection, sendResource } from '../utils/response.js'
import {
  parseIdParam,
  validateProjectCreate,
  validateProjectPatch,
  validateTaskCreate,
} from '../utils/validation.js'

const projects = new Hono()

projects.get('/', async (c) => {
  const db = getDb(c.env.DB)
  const data = await listProjects(db)
  return sendCollection(c, data)
})

projects.post('/', async (c) => {
  const payload = await parseJsonBody(c)
  const details = validateProjectCreate(payload)

  if (details.length > 0) {
    throw new ApiError(
      422,
      'VALIDATION_ERROR',
      'Some fields are invalid.',
      details,
    )
  }

  const db = getDb(c.env.DB)
  const project = await createProject(db, payload)
  c.header('Location', `/api/projects/${project.id}`)
  return sendResource(c, project, 201)
})

projects.get('/:id/tasks', async (c) => {
  const projectId = parseIdParam(c.req.param('id'))
  const db = getDb(c.env.DB)
  const project = await getProjectById(db, projectId)

  if (!project) {
    throw new ApiError(404, 'NOT_FOUND', 'Project not found.')
  }

  const data = await listTasksByProject(db, projectId)
  return sendCollection(c, data)
})

projects.post('/:id/tasks', async (c) => {
  const projectId = parseIdParam(c.req.param('id'))
  const db = getDb(c.env.DB)
  const project = await getProjectById(db, projectId)

  if (!project) {
    throw new ApiError(404, 'NOT_FOUND', 'Project not found.')
  }

  const payload = await parseJsonBody(c)
  const details = validateTaskCreate(payload)

  if (details.length > 0) {
    throw new ApiError(
      422,
      'VALIDATION_ERROR',
      'Some fields are invalid.',
      details,
    )
  }

  const task = await createTask(db, projectId, payload)
  c.header('Location', `/api/tasks/${task.id}`)
  return sendResource(c, task, 201)
})

projects.get('/:id', async (c) => {
  const id = parseIdParam(c.req.param('id'))
  const db = getDb(c.env.DB)
  const project = await getProjectById(db, id)

  if (!project) {
    throw new ApiError(404, 'NOT_FOUND', 'Project not found.')
  }

  return sendResource(c, project)
})

projects.patch('/:id', async (c) => {
  const id = parseIdParam(c.req.param('id'))
  const payload = await parseJsonBody(c)
  const details = validateProjectPatch(payload)

  if (details.length > 0) {
    throw new ApiError(
      422,
      'VALIDATION_ERROR',
      'Some fields are invalid.',
      details,
    )
  }

  const db = getDb(c.env.DB)
  const updatedProject = await updateProject(db, id, payload)

  if (!updatedProject) {
    throw new ApiError(404, 'NOT_FOUND', 'Project not found.')
  }

  return sendResource(c, updatedProject)
})

projects.delete('/:id', async (c) => {
  const id = parseIdParam(c.req.param('id'))
  const db = getDb(c.env.DB)
  const deleted = await deleteProject(db, id)

  if (!deleted) {
    throw new ApiError(404, 'NOT_FOUND', 'Project not found.')
  }

  return c.body(null, 204)
})

export default projects
