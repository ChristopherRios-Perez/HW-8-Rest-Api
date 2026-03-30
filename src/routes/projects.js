import { Hono } from 'hono'
import {
  listProjects,
  getProjectById,
  createProject,
  updateProject,
  deleteProject,
  createTask,
  listTasksByProject,
} from '../data/store.js'

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

projects.get('/', (c) => {
  const data = listProjects()
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

  const project = createProject(payload)
  c.header('Location', `/api/projects/${project.id}`)
  return sendResource(c, project, 201)
})

projects.get('/:id/tasks', (c) => {
  const projectId = parseIdParam(c.req.param('id'))
  const project = getProjectById(projectId)

  if (!project) {
    throw new ApiError(404, 'NOT_FOUND', 'Project not found.')
  }

  const data = listTasksByProject(projectId)
  return sendCollection(c, data)
})

projects.post('/:id/tasks', async (c) => {
  const projectId = parseIdParam(c.req.param('id'))
  const project = getProjectById(projectId)

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

  const task = createTask(projectId, payload)
  c.header('Location', `/api/tasks/${task.id}`)
  return sendResource(c, task, 201)
})

projects.get('/:id', (c) => {
  const id = parseIdParam(c.req.param('id'))

  const project = getProjectById(id)

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

  const updatedProject = updateProject(id, payload)

  if (!updatedProject) {
    throw new ApiError(404, 'NOT_FOUND', 'Project not found.')
  }

  return sendResource(c, updatedProject)
})

projects.delete('/:id', (c) => {
  const id = parseIdParam(c.req.param('id'))
  const deleted = deleteProject(id)

  if (!deleted) {
    throw new ApiError(404, 'NOT_FOUND', 'Project not found.')
  }

  return c.body(null, 204)
})

export default projects