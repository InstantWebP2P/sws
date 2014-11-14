var SecureWebSocket = require('../index.js');
var SecureWebSocketServer = SecureWebSocket.Server;
var nacl = require('tweetnacl/nacl-fast');

var skp = nacl.box.keyPair();
var wss = new SecureWebSocketServer(
		{port: 6668, host: 'localhost', path: '/wspp'},
		{
				myPublicKey: skp.publicKey,
				mySecretKey: skp.secretKey
		});
wss.on('connection', function(ws){
	ws.on('message', function(message, flags){
		if (flags.binary) {
			console.log('server message:'+new Buffer(message).toString('utf-8'));
			ws.send(message, {binary: true, mask: false});
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
	console.log('connected');
	
	ws.onmessage(function(message, flags){
		if (flags.binary) {
			console.log('client message:'+new Buffer(message).toString('utf-8'));
		} else {
			console.log('Not support String:'+JSON.stringify(message))
		}
	});
	setInterval(function(){
		ws.send(new Buffer('Hello,Am tom@'+Date.now(), 'utf-8'), {binary: true, mask: false});
	}, 2000);
});

ws.on('warn', function(warn){
	console.log('Warning: '+JSON.stringify(warn));
});

ws.on('error', function(err){
	console.log('Error: '+JSON.stringify(err));
});
