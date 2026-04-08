const fs = require('fs')
const { USERS_FILE } = require('./constants')

function loadUsers() {
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')) }
    catch { return { admin: '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918' } }
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2))
}

// Initialiser users.json si absent
if (!fs.existsSync(USERS_FILE)) saveUsers(loadUsers())

module.exports = { loadUsers, saveUsers }
