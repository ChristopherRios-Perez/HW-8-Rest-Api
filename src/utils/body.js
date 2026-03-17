import { ApiError } from './errors.js'

export async function parseJsonBody(c) {
  try {
    return await c.req.json()
  } catch {
    throw new ApiError(400, 'BAD_REQUEST', 'Malformed JSON request body.')
  }
}