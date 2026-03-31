/**
 * Known-good packages that legitimately trigger certain signals.
 *
 * These packages have postinstall scripts, spawn processes, or access the network
 * for legitimate reasons (downloading platform-specific binaries, installing hooks, etc.).
 * Signals from these packages are downweighted, not suppressed — a compromised version
 * of esbuild would still be caught if new dangerous patterns appear.
 *
 * This list is auditable in the repo. Users can extend it in .vexesrc.json.
 */

// Packages with legitimate postinstall scripts (download platform binaries)
export const KNOWN_POSTINSTALL = new Set([
  'esbuild', '@esbuild/darwin-arm64', '@esbuild/linux-x64',
  'swc', '@swc/core',
  'sharp', 'canvas',
  'better-sqlite3', 'sqlite3',
  'node-sass', 'sass',
  'puppeteer', 'playwright',
  'electron', 'electron-builder',
  'node-gyp', 'node-pre-gyp', '@mapbox/node-pre-gyp', 'prebuild-install',
  'grpc', '@grpc/grpc-js',
  'bcrypt', 'argon2',
  'fsevents',
  'protobufjs', 'protobuf',
  'lightningcss',
  '@parcel/watcher',
  'turbo', '@vercel/turbo',
  'prisma', '@prisma/client', '@prisma/engines',
  'keytar',
  '@img/sharp-darwin-arm64', '@img/sharp-darwin-x64',
  '@img/sharp-linux-arm', '@img/sharp-linux-arm64', '@img/sharp-linux-x64',
  '@img/sharp-linuxmusl-arm64', '@img/sharp-linuxmusl-x64',
  '@img/sharp-win32-arm64', '@img/sharp-win32-ia32', '@img/sharp-win32-x64',
  '@img/sharp-wasm32',
  '@img/sharp-libvips-darwin-arm64', '@img/sharp-libvips-darwin-x64',
  '@img/sharp-libvips-linux-arm', '@img/sharp-libvips-linux-arm64',
  '@img/sharp-libvips-linux-x64', '@img/sharp-libvips-linuxmusl-arm64',
  '@img/sharp-libvips-linuxmusl-x64',
  '@img/sharp-linux-ppc64', '@img/sharp-linux-riscv64', '@img/sharp-linux-s390x',
  '@img/sharp-libvips-linux-ppc64', '@img/sharp-libvips-linux-riscv64',
  '@img/sharp-libvips-linux-s390x',
  'vite',     // Uses esbuild postinstall
  'cypress',
  'lefthook', 'husky', 'simple-git-hooks',
  'patch-package',
  'core-js',  // Controversial but not malicious
]);

// Top ~200 npm packages by weekly downloads — used for typosquat detection
export const POPULAR_NPM = new Set([
  'lodash', 'chalk', 'react', 'axios', 'express', 'debug', 'tslib', 'commander',
  'moment', 'uuid', 'async', 'bluebird', 'request', 'underscore', 'mkdirp',
  'glob', 'minimist', 'yargs', 'semver', 'colors', 'fs-extra', 'rimraf',
  'jquery', 'dotenv', 'typescript', 'webpack', 'babel-core', 'rxjs', 'inquirer',
  'eslint', 'prettier', 'jest', 'mocha', 'chai', 'sinon', 'supertest',
  'body-parser', 'cors', 'helmet', 'passport', 'jsonwebtoken', 'bcryptjs',
  'mongoose', 'sequelize', 'knex', 'pg', 'mysql2', 'redis', 'ioredis',
  'socket.io', 'ws', 'node-fetch', 'got', 'superagent', 'cheerio',
  'puppeteer', 'playwright', 'sharp', 'jimp', 'canvas',
  'next', 'nuxt', 'gatsby', 'svelte', 'vue', 'angular',
  'tailwindcss', 'postcss', 'autoprefixer', 'sass', 'less', 'styled-components',
  'webpack-cli', 'rollup', 'esbuild', 'vite', 'parcel', 'turbo',
  'prisma', 'typeorm', 'drizzle-orm', 'zod', 'joi', 'yup', 'ajv',
  'pino', 'winston', 'bunyan', 'morgan', 'log4js',
  'nodemon', 'concurrently', 'cross-env', 'dotenv-cli', 'husky',
  'ora', 'chalk', 'ansi-styles', 'strip-ansi', 'supports-color', 'color-convert',
  'wrap-ansi', 'ansi-regex', 'escape-string-regexp', 'has-flag',
  'lru-cache', 'cache-manager', 'keyv',
  'dayjs', 'date-fns', 'luxon',
  'ramda', 'fp-ts', 'immer',
  'nanoid', 'cuid', 'short-uuid',
  'formidable', 'multer', 'busboy',
  'nodemailer', 'sendgrid',
  'stripe', 'paypal-rest-sdk',
  'aws-sdk', '@aws-sdk/client-s3', 'firebase', 'firebase-admin',
  '@google-cloud/storage', 'azure-storage',
  'graphql', 'apollo-server', '@apollo/client',
  'socket.io-client', 'mqtt', 'amqplib',
  'bull', 'bullmq', 'agenda', 'node-cron',
  'passport-local', 'passport-jwt', 'passport-google-oauth20',
  'connect', 'koa', 'fastify', 'hapi', 'hono', 'express-validator',
  'http-proxy', 'http-proxy-middleware',
  'compression', 'cookie-parser', 'express-session',
  'path-to-regexp', 'qs', 'content-type', 'mime', 'mime-types',
  'tsconfig-paths', 'ts-node', 'tsx', 'swc',
  'electron', 'electron-builder', 'electron-updater',
]);

// Top PyPI packages for typosquat detection
export const POPULAR_PYPI = new Set([
  'requests', 'numpy', 'pandas', 'flask', 'django', 'scipy', 'matplotlib',
  'pillow', 'setuptools', 'pip', 'wheel', 'six', 'urllib3', 'certifi',
  'pyyaml', 'cryptography', 'jinja2', 'markupsafe', 'click', 'pydantic',
  'fastapi', 'uvicorn', 'httpx', 'aiohttp', 'beautifulsoup4', 'lxml',
  'sqlalchemy', 'psycopg2', 'pymongo', 'redis', 'celery',
  'boto3', 'botocore', 'google-cloud-storage', 'azure-storage-blob',
  'tensorflow', 'torch', 'transformers', 'scikit-learn', 'keras',
  'opencv-python', 'tqdm', 'rich', 'colorama', 'pytest', 'pytest-cov',
  'black', 'flake8', 'mypy', 'isort', 'pylint', 'ruff',
  'poetry', 'pipenv', 'virtualenv', 'tox',
  'openai', 'anthropic', 'langchain', 'litellm', 'tiktoken',
  'gunicorn', 'daphne', 'hypercorn',
  'alembic', 'marshmallow', 'attrs', 'dataclasses-json',
  'python-dotenv', 'python-multipart', 'python-jose',
  'starlette', 'websockets', 'grpcio', 'protobuf',
  'docker', 'kubernetes', 'paramiko', 'fabric',
  'pendulum', 'arrow', 'python-dateutil',
  'loguru', 'structlog',
  'httptools', 'ujson', 'orjson', 'msgpack',
  'tenacity', 'backoff', 'retry',
  'pyjwt', 'passlib', 'bcrypt', 'argon2-cffi',
  'stripe', 'twilio', 'sendgrid',
  'sentry-sdk', 'newrelic',
  'celery', 'dramatiq', 'rq',
  'networkx', 'sympy', 'statsmodels',
]);
