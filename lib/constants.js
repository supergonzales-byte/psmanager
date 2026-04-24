const path = require('path')

const PORT             = 4000
const HTTPS_PORT       = 443
const PARC_FILE        = 'C:\\ps-manager\\inventaire\\parc.txt'
const SCRIPTS_DIR      = 'C:\\ps-manager\\scripts'
const INSTALLERS_DIR   = 'C:\\ps-manager\\installers'
const DRIVERS_BASE     = 'C:\\ps-manager\\Drivers'
const LOG_BASE         = 'C:\\ps-manager\\inventaire\\Logiciels'
const INSTALLER_ARGS_FILE = path.join(__dirname, '..', 'installer-args.json')
const INSTALLER_META_FILE = path.join(__dirname, '..', 'installer-meta.json')
const USERS_FILE       = path.join(__dirname, '..', 'users.json')
const CONFIG_FILE      = path.join(__dirname, '..', 'config.json')
const SCHEDULES_FILE   = path.join(__dirname, '..', 'schedules.json')
const KEY_FILE         = path.join(__dirname, '..', '.schedule.key')
const SSL_DIR          = path.join(__dirname, '..', 'ssl')
const SSL_KEY          = path.join(__dirname, '..', 'ssl', 'key.pem')
const SSL_CERT         = path.join(__dirname, '..', 'ssl', 'cert.pem')
const VEYON_DIR        = 'C:\\ps-manager\\veyon'

module.exports = {
    PORT, HTTPS_PORT,
    PARC_FILE, SCRIPTS_DIR, INSTALLERS_DIR, DRIVERS_BASE, LOG_BASE,
    INSTALLER_ARGS_FILE, INSTALLER_META_FILE, USERS_FILE, CONFIG_FILE,
    SCHEDULES_FILE, KEY_FILE,
    SSL_DIR, SSL_KEY, SSL_CERT,
    VEYON_DIR,
}
