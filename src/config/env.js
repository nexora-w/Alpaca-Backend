const path = require('path');
const dotenv = require('dotenv');

const projectRoot = process.cwd();
const envPath = path.join(projectRoot, '.env');

dotenv.config({ path: envPath });

const env = process.env.NODE_ENV || 'development';

const config = {
  env,
  isDev: env === 'development',
  isProd: env === 'production',
  port: parseInt(process.env.PORT, 10) || 4000,
  logging: {
    level: process.env.LOG_LEVEL || (env === 'development' ? 'debug' : 'info'),
  },
  app: {
    name: process.env.APP_NAME || 'Alpaca Backend',
    root: projectRoot,
  },
};

module.exports = config;

