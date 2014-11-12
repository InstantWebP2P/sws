(function(Export, Nacl, WebSocket){
	var PROTO_VERSION = 1;
	
	// secure WebSocket 
	var SecureWebSocket = function(url, secinfo) {
		var self = this;
		
		// eventEmitter
		self.events = {};
		
		// check parameters
		if ((url && typeof url === 'string') && 
			(secinfo && typeof secinfo === 'object')) {
			// Client
			self.isServer = false;
			self.url = url;
		} else if ((url && url instanceof WebSocket) && 
				   (secinfo && typeof secinfo === 'object')) {
			// ServerClient
			self.isServer = true;
			self.ws = url;
		} else 
			throw new Error('Invalid parameters');
				
		// Check security info
		if (PROTO_VERSION >= 1) {
			// setup V1
			self.secinfo = secinfo;
			self.myPublicKey = secinfo.myPublicKey;
			self.mySecretKey = secinfo.mySecretKey;
			
			// check V1
			if (!(self.myPublicKey && Array.isArray(self.myPublicKey) && self.myPublicKey.length===Nacl.box.publicKeyLength))
				throw new Error('Invalid nacl public key');
			if (!(self.mySecretKey && Array.isArray(self.mySecretKey) && self.mySecretKey.length===Nacl.box.secretKeyLength))
				throw new Error('Invalid nacl secret key');
		}
		if (PROTO_VERSION >= 2) {
			// setup V2
			self.myCert = secinfo.cert;
			self.caCert = secinfo.ca;
			
			// check V2
			if (!(self.myCert )
				throw new Error('Invalid nacl cert');
			if (!(self.caCert )
				throw new Error('Invalid nacl CA');
		}
		
		// FSM: new->connected->HandshakeStart->SendClientHello->RecvServerHello->SendClientReady->HandshakeDone
		self.state = 'new';
		self.ws = self.isServer ? self.ws : new WebSocket(url);
		
		// Handshake process
		var handshake = function() {
			// state -> connected
			self.state = 'connected';
			
			// Handshake message handle
			self.ws.onmessage(function(message, flags){
				if (self.state === 'HandshakeDone') {
				    // Normal authenticated-encryption 
					if (flags && flags.binary) {
						var data = toUint8Array(message);
						
						// decrypt data
						var plain = self.rxSecretBox.open(data);
						if (plain) {
							// increase nonce
							self.rxSecretBox.incrNonce();
							
							// notify data
							self.emit('message', plain.buffer, {binary: true, mask: false});
						} else {
							self.emit('warn', 'Attacked message:'+JSON.stringify(message));
						}
					} else {
						// TBD... String
						self.emit('warn', 'Not support String message');
					}
				} else if (self.state === 'SendClientHello') {
					// Handshake process
					if (flags && !flags.binary) {
						var shm = JSON.parse(message);
						
						if (shm && shm.opc === 1) {
							console.log('got ServerHello message:'+JSON.stringify(shm));
							
							self.theirPublicKey = shm.server_public_key;
							// extract rxShareKey, nonce
							var rxshare_nonce_a = Nacl.Box.open(shm.rx);
						} else {
							self.emit('warn', 'Invalid ServerHello message:'+JSON.stringify(message));
						}
					} else {
						self.emit('warn', 'Invalid handshake message:'+JSON.stringify(message));
					}
				} else {
					self.emit('warn', 'Invalid message:'+JSON.stringify(message));
				}
			});
			
			// 1.
			// Send ClientHello message
			var chm = 
			{
				opc: 0, 
				version: PROTO_VERSION,
				client_public_key: self.myPublicKey,
			};
			chm.nonce = []; Nacl.randombytes(chm.nonce, 8);
			// update secure info
			self.myNonce = chm.nonce;
			
			// send 
			try {
				self.ws.send(JSON.stringify(chm), {binary: false, mask: false}, function(err){
					if (err) {
						console.log('send ClientHello failed:'+err);
						self.ws.close();
						return;
					}

					// state -> SendClientHello
					self.state = 'SendClientHello';
				});
			} catch (e) {
				console.log('send ClientHello immediately failed:'+e);
				self.ws.close();
				return;
			}
			
			// state -> HandshakeStart
			self.state = 'HandshakeStart';
			
			// 2.
			// Start hand-shake timer
			self.hs_tmo = setTimeout(function(){
				if (self.state != 'HandshakeDone') {
					console.log('handshake timeout');
					
					self.emit('timeout', 'handshake timeout');
                    self.ws.close();
				}
			}, 2000); // 2s
		};
		
		// handshake 
		if (self.isServer)
			handshake();
		} else
			self.ws.onopen(handshake);
		
		// Send cache
		self.sendCache = [];
	};
	SecureWebSocket.prototype.onopen = function(fn) {
		this.on('secure', fn);
	};
	SecureWebSocket.prototype.onmessage = function(fn) {
			
	};
	SecureWebSocket.prototype.close = function(fn) {
			
	};
	SecureWebSocket.prototype.send = function(message, flags, fn) {
		var self = this;

		if (self.state === 'HandshakeDone') {
			if (message) {
				if (flags && flags.binary) {
					var data = toUint8Array(message);

					// ecrypt
					var cipher = self.txSecretBox.box(data);
					if (cipher) {
						// increase nonce
						self.txSecretBox.incrNonce();

						// write data out
						self.ws.send(cipher.buffer, {binary: true, mask: false}, fn);
					} else {
						console.log('hacked write ByteBuffer, ingore it');
						self.emit('warn', 'hacked write ByteBuffer, ingore it');
						if (fn) fn('hacked write ByteBuffer, ingore it');
					}
				} else {
					console.log('dont support write string so far');
					self.emit('warn', 'dont support write string so far');
					if (fn) fn('dont support write string so far');
				}
			} else {
				console.log('invalid write data');
				self.emit('warn', 'invalid write data');
				if (fn) fn('invalid write data');
			}
		} else {
			// cache send
			self.sendCache.push({data, flags, fn});
			return false;
		}

		return true;
	};
	
	// EventEmitter
	SecureWebSocket.prototype.on = function(event, fn) {
		var self = this;
		
		self.events[event] = self.events[event] || [];
		
		self.events[event].push(fn);
		
		return self;
	};	
	SecureWebSocket.prototype.emit = function(event, message, flags) {
		var self = this;
		
		if (self.events && self.events[event]) {
			self.events[event].forEach(function(fn) {
			    if (fn && typeof fn === 'function')
			    	fn(message, flags);
			});
		} else {
			console.log('Unknown event:'+event);
			return false;
		}
		
		return true;
	}
	
	// export 
	Export.sws = SecureWebSocket;
})((module && module.exports) || document, 
   (require && require('nacl-fast')) || nacl,
   (require && require('wspp')) || (require && require('ws')) || WebSocket);