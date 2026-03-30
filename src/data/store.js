const seededAt = new Date().toISOString()

let projects = [
  {
    id: 1,
    name: 'Berserk Web Project',
    description: 'Redesign and rebuild the portfolio website for the Berserk design system.',
    created_at: seededAt,
    updated_at: seededAt,
  },
  {
    id: 2,
    name: 'Cybersecurity Workshop',
    description: 'Prepare teaching material for the class workshop.',
    created_at: seededAt,
    updated_at: seededAt,
  },
]

let tasks = [
  {
    id: 1,
    project_id: 1,
    title: 'Draft homepage wireframes',
    description: 'Create desktop and mobile layout drafts.',
    status: 'in_progress',
    created_at: seededAt,
    updated_at: seededAt,
  },
  {
    id: 2,
    project_id: 1,
    title: 'Update portfolio images',
    description: 'Replace old screenshots with new ones from the latest release.',
    status: 'todo',
    created_at: seededAt,
    updated_at: seededAt,
  },
  {
    id: 3,
    project_id: 2,
    title: 'update slides with better examples',
    description: 'Replace outdated examples with recent examples',
    status: 'todo',
    created_at: seededAt,
    updated_at: seededAt,
  },
]

let nextProjectId = 3
let nextTaskId = 4

function clone(item) {
  return { ...item }
}

function nowIso() {
  return new Date().toISOString()
}

export function listProjects() {
  return projects.map(clone)
}

export function getProjectById(id) {
  const project = projects.find((item) => item.id === id)
  return project ? clone(project) : null
}

export function createProject(input) {
  const timestamp = nowIso()
  const project = {
    id: nextProjectId,
    name: input.name.trim(),
    description: input.description?.trim() || '',
    created_at: timestamp,
    updated_at: timestamp,
  }

  nextProjectId += 1
  projects.push(project)

  return clone(project)
}

export function updateProject(id, input) {
  const index = projects.findIndex((item) => item.id === id)

  if (index === -1) {
    return null
  }

  const current = projects[index]
  const updated = {
    ...current,
    ...('name' in input ? { name: input.name.trim() } : {}),
    ...('description' in input
      ? { description: input.description.trim() }
      : {}),
    updated_at: nowIso(),
  }

  projects[index] = updated
  return clone(updated)
}

export function deleteProject(id) {
  const startSize = projects.length
  projects = projects.filter((item) => item.id !== id)

  if (projects.length === startSize) {
    return false
  }

  tasks = tasks.filter((task) => task.project_id !== id)

  return true
}

export function listTasksByProject(projectId) {
  return tasks.filter((task) => task.project_id === projectId).map(clone)
}

export function createTask(projectId, input) {
  const timestamp = nowIso()
  const task = {
    id: nextTaskId,
    project_id: projectId,
    title: input.title.trim(),
    description: input.description?.trim() || '',
    status: input.status || 'todo',
    created_at: timestamp,
    updated_at: timestamp,
  }

  nextTaskId += 1
  tasks.push(task)

  return clone(task)
}

export function getTaskById(id) {
  const task = tasks.find((item) => item.id === id)
  return task ? clone(task) : null
}

export function updateTask(id, input) {
  const index = tasks.findIndex((item) => item.id === id)

  if (index === -1) {
    return null
  }

  const current = tasks[index]
  const updated = {
    ...current,
    ...('title' in input ? { title: input.title.trim() } : {}),
    ...('description' in input
      ? { description: input.description.trim() }
      : {}),
    ...('status' in input ? { status: input.status } : {}),
    updated_at: nowIso(),
  }

  tasks[index] = updated
  return clone(updated)
}

export function deleteTask(id) {
  const startSize = tasks.length
  tasks = tasks.filter((item) => item.id !== id)
  return tasks.length !== startSize
}