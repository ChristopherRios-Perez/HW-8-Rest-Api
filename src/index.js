import { Hono } from 'hono'

import auth from './routes/auth.js'
import projects from './routes/projects.js'
import tasks from './routes/tasks.js'
import { authenticate } from './middleware/authenticate.js'
import { isApiError } from './utils/errors.js'
import { sendError } from './utils/response.js'

const app = new Hono()
const api = new Hono()

app.use('*', async (c, next) => {
  c.set('traceId', crypto.randomUUID())
  await next()
})

api.route('/auth', auth)
api.use('/projects/*', authenticate)
api.use('/tasks/*', authenticate)
api.route('/projects', projects)
api.route('/tasks', tasks)

app.route('/api', api)

app.notFound((c) => {
  return sendError(c, 404, 'NOT_FOUND', 'Route not found.')
})

app.onError((error, c) => {
  if (isApiError(error)) {
    return sendError(c, error.status, error.code, error.message, error.details)
  }

  console.error('Unhandled error:', error)
  return sendError(
    c,
    500,
    'INTERNAL_SERVER_ERROR',
    'An unexpected server error occurred.',
  )
})

export default app
