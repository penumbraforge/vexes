// Legitimate postinstall patterns that should NOT trigger false positives

// Pattern 1: Reading a config file
const fs = require('fs');
const config = fs.readFileSync('./config.json', 'utf8');
const parsed = JSON.parse(config);

// Pattern 2: Console output
console.log('Package installed successfully');
console.warn('Remember to set your API key');

// Pattern 3: String manipulation
const name = 'my-package';
const version = '1.0.0';
const full = `${name}@${version}`;

// Pattern 4: Math operations
const hash = Math.random().toString(36).substring(2);

// Pattern 5: Path manipulation
const path = require('path');
const dir = path.join(__dirname, 'lib');

// Pattern 6: Simple object creation
const defaults = {
  port: 3000,
  host: 'localhost',
  debug: false,
};

// Pattern 7: Array operations
const items = [1, 2, 3].map(x => x * 2).filter(x => x > 2);
