// @konstant-studio/auth v2 -- control-plane auth. Entry point: require('@konstant-studio/auth/v2').
// v1 exports (setupClerk, protect, requireService, ...) are unchanged and live in the package root.

const { createAuth: createCore, Principal, parsePermission } = require('./auth');
const { expressAdapter } = require('./adapters/express');
const { nextAdapter } = require('./adapters/next');
const { ConfigError } = require('./config');
const { routeAllowed, validatePolicy } = require('./service-keys');
const { verifySignature, eventsWebhookHandler } = require('./events-webhook');

function createAuth(opts) {
  const core = createCore(opts);
  core.express = expressAdapter(core);
  core.next = nextAdapter(core);
  core.eventsWebhook = (o) => eventsWebhookHandler(core, o);
  return core;
}

module.exports = { createAuth, Principal, ConfigError, parsePermission, routeAllowed, validatePolicy, verifySignature };
