const seededAt = new Date().toISOString()

let projects = [
  {
    id: 1,
    project_id: 1,
    name: 'Anime Recommendation App',
    description: 'Build a web app that suggests anime based on user preferences.',
    status: 'todo',
    created_at: seededAt,
    updated_at: seededAt,
  },
  {
    id: 2,
    project_id: 2,
    name: 'Cybersecurity Awareness Campaign',
    description: 'Create a campaign to educate users about online security best practices.',
    status: 'todo',
    created_at: seededAt,
    updated_at: seededAt,
  },
  {
    id: 3,
    project_id: 3,
    name: 'Top Games of 2025',
    description: 'Compile a list of the best video games released in 2025.',
    created_at: seededAt,
    updated_at: seededAt,
  }
]

let nextProjectId = 3
let nextTaskID = 4

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

  return true
}

export function listTasks(projectId) {
  return TaskSignal.filter((task) => task.project_id === projectId).map(clone)
}