var sws = require('./sws');
module.exports = sws.SecureWebSocket;
module.exports.Server = require('./SecureWebSocketServer');
module.exports.Stream = require('./SecureStream');

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

// NACL
module.exports.keyPair   = sws.keyPair;
module.exports.Box       = sws.Box;
module.exports.SecretBox = sws.SecretBox;

// Utils
module.exports.ArrayToUint8  = sws.ArrayToUint8;
module.exports.Uint8ToArray  = sws.Uint8ToArray;
module.exports.Uint8ToBuffer = sws.Uint8ToBuffer;