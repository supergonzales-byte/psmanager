const multer = require('multer')
const os     = require('os')

const upload   = multer({ dest: os.tmpdir() })  // pour scripts/installers/copy-files
const multerFs = multer({ dest: os.tmpdir() })  // pour fs/upload

module.exports = { upload, multerFs }
