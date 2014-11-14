module.exports = require('./sws').SecureWebSocket;
module.exports.Server = require('./SecureWebSocketServer');

module.exports.createServer = function (options, connectionListener) {
  var server = new module.exports.Server(options, options.secinfo || options);
  if (typeof connectionListener === 'function') {
    server.on('connection', connectionListener);
  }
  return server;
};

module.exports.connect = module.exports.createConnection = function (address, secinfo, openListener) {
  var client = new module.exports(address, secinfo);
  if (typeof openListener === 'function') {
    client.on('open', openListener);
  }
  return client;
};
