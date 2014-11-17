var SecureWebSocket = require('../index.js');
var SecureWebSocketServer = SecureWebSocket.Server;
var Uint8ToBuffer = SecureWebSocket.Uint8ToBuffer;
var nacl = require('tweetnacl/nacl-fast');
var msgpack = require('msgpack-js');


var skp = nacl.box.keyPair();
var wss = new SecureWebSocketServer(
		{port: 6668, host: 'localhost', path: '/wspp'},
		{
				myPublicKey: skp.publicKey,
				mySecretKey: skp.secretKey
		});
wss.on('connection', function(ws){
	ws.on('message', function(message, flags){
		///console.log('srv msg:'+JSON.stringify(message));
		
		if (flags.binary) {
			console.log('server message:'+msgpack.decode(Uint8ToBuffer(message)));
			ws.send(message);
		} else 
			console.error('Not support String message');
	});
});

var ckp = nacl.box.keyPair();
var ws = new SecureWebSocket(
		'ws://127.0.0.1:6668/wspp', 
		{
				myPublicKey: ckp.publicKey,
				mySecretKey: ckp.secretKey
		});

ws.onopen(function(){
	console.log('secure ws connected');
	
	ws.onmessage(function(message, flags){
		///console.log('cln msg:'+JSON.stringify(message));

		if (flags.binary) {
			console.log('client message:'+msgpack.decode(Uint8ToBuffer(message)));
		} else {
			console.log('Not support String:'+JSON.stringify(message))
		}
	});
	setInterval(function(){
		ws.send(msgpack.encode('Hello,Am tom@'+Date.now()));
	}, 2000);
});

ws.on('warn', function(warn){
	console.log('Warning: '+JSON.stringify(warn));
});

ws.on('error', function(err){
	console.log('Error: '+JSON.stringify(err));
});





