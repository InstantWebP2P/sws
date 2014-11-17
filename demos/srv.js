var connect = require('connect');
var http = require('http');
var sws = require('../index');
var msgpack = require('msgpack-js');

var srv = connect();

srv.use(connect.static(__dirname+'/content/'));
srv.use(function(req, res){
	res.writeHead(400, 'Invalid path');
	res.end();
});

var app = http.createServer(srv);

var kp = sws.keyPair();
var swss = sws.createServer({
	server: app, 
	path: '/wspp', 
	
	secinfo: {
	    myPublicKey: kp.publicKey,
	    mySecretKey: kp.secretKey
	}
});
swss.on('connection', function(ws){
	ws.on('message', function(message, flags){
		if (flags.binary) {
			var data = msgpack.decode(message);
			console.log('Server message:'+data);
			ws.send(message);
		} else {
			console.log('Not support String message');
		}
	});
});

app.listen(6188);
console.log('SecureWebSocketServer listen on 6188');
