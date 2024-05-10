const fs = require('fs');
const crypto = require('crypto');

// Generate random string
const randomString = crypto.randomBytes(35).toString('hex');

// Write the random string to the .env file
fs.writeFileSync('.env', `SECRET_KEY=${randomString}\n`, { flag: 'a' });

console.log('Random string generated and saved to .env file:', randomString);
