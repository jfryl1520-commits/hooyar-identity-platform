const serverless = require('serverless-http');
const app = require('../../server');

const handler = serverless(app);

const FUNCTION_PREFIX = '/.netlify/functions/api';

// Depending on how Netlify proxies the request, the path reaching this function
// may be the original one (/api/..., /health), or the prefix may be stripped.
// serverless-http needs the full public path to route into the Express app, so
// it is normalised here instead of relying on one specific proxy behaviour.
function normalizePath(event) {
  let path = event.rawPath || event.path || '/';
  if (path.startsWith(FUNCTION_PREFIX)) path = path.slice(FUNCTION_PREFIX.length) || '/';
  if (!path.startsWith('/api') && !path.startsWith('/health')) path = `/api${path}`;
  return path;
}

module.exports.handler = async (event, context) => {
  // The connection pool must not keep the invocation alive after the response.
  context.callbackWaitsForEmptyEventLoop = false;

  const path = normalizePath(event);
  if (path !== event.path) event = { ...event, path };

  return handler(event, context);
};
