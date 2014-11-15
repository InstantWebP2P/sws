// SecureWebSocket implementation with NACL
// Copyright (c) 2014 Tom Zhou<iwebpp@gmail.com>


(function(Export, Nacl, WebSocket){
	var PROTO_VERSION = 1;
	var SEND_WATER_MARK = 4096;
	var RECV_WATER_MARK = 4096;

	// secure WebSocket 
	var SecureWebSocket = function(url, secinfo) {
		if (!(this instanceof SecureWebSocket))
			return new SecureWebSocket(url, secinfo);
		
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
			if (!(self.myPublicKey && 
				 (self.myPublicKey instanceof Uint8Array) && 
				  self.myPublicKey.byteLength===Nacl.box.publicKeyLength))
				throw new Error('Invalid nacl public key');
			if (!(self.mySecretKey && 
				 (self.mySecretKey instanceof Uint8Array) && 
				  self.mySecretKey.byteLength===Nacl.box.secretKeyLength))
				throw new Error('Invalid nacl secret key');
		}
		if (PROTO_VERSION >= 2) {
			// setup V2
			self.myCert = secinfo.cert;
			self.caCert = secinfo.ca;

			// check V2
			if (!self.myCert)
					throw new Error('Invalid nacl cert');
			if (!self.caCert)
					throw new Error('Invalid nacl CA');
		}
		
		// FSM: new->connected->HandshakeStart->SendClientHello->
		//      RecvServerHello->SendClientReady->HandshakeDone
		self.state = 'new';
		self.ws = self.isServer ? self.ws : new WebSocket(url);
		// use arrayBuffer as binaryType
		self.ws.binaryType = 'arraybuffer';

		// Handshake process
		var client_handshake = function() {
			// state -> connected
			self.state = 'connected';
			
			// Handshake message handle
			self.ws.onmessage = function(msg){
				///console.log('client msg,type:'+JSON.stringify(msg.type));
				
				var message = msg.data;
				var flags = {
				    binary: !(typeof message === 'string')
				};

				if (self.state === 'HandshakeDone') {
				    // Normal authenticated-encryption 
					if (flags && flags.binary) {
						var data = new Uint8Array(message);
						
						// decrypt data
						var plain = self.rxSecretBox.open(data);
						if (plain) {
							// increase nonce
							self.rxSecretBox.incrNonce();
							
							// notify data
							self.emit('message', plain, {binary: true});
						} else {
							self.emit('warn', 'Attacked message:'+JSON.stringify(message));
						}
					} else {
						// TBD... String
						self.emit('error', 'Not support String message');
					}
				} else if (self.state === 'HandshakeStart') {
					// Handshake process
					if (flags && !flags.binary) {
						try {
							var shm = JSON.parse(message);

							if (shm && shm.opc === 1 && shm.version === PROTO_VERSION) {
								///console.log('ServerHello message<-:'+JSON.stringify(shm));

								self.theirPublicKey = ArrayToUint8(shm.server_public_key);
								// extract rxsharedKey, nonce
								var rx_tempbox = new Box(self.theirPublicKey, self.mySecretKey, self.myNonce);
								var rx_nonce_share_key = rx_tempbox.open(ArrayToUint8(shm.s_nonce_share_key_a));
								
								if (rx_nonce_share_key) {
									// update secure info
									self.theirNonce = rx_nonce_share_key.subarray(0, 8);
									self.rxShareKey = rx_nonce_share_key.subarray(8);
									self.myNonce = Nacl.randomBytes(8);
									self.txShareKey = Nacl.randomBytes(Nacl.secretbox.keyLength);
									
									// Constructor NACL tx box
									self.txBox = new Box(self.theirPublicKey, self.mySecretKey, self.myNonce);
									self.txSecretBox = new SecretBox(self.txShareKey, self.myNonce);

									// send ClientReady message
									var tx_nonce_share_key = new Uint8Array(self.myNonce.length+self.txShareKey.length);
									tx_nonce_share_key.set(self.myNonce); 
									tx_nonce_share_key.set(self.txShareKey, self.myNonce.length);
											
									// tx temp Box
									var tx_tempbox = new Box(self.theirPublicKey, self.mySecretKey, self.theirNonce);
									var s_tx_nonce_share_key = tx_tempbox.box(tx_nonce_share_key);
									
									var crm = 
									{
											opc: 2, 
											version: PROTO_VERSION,

											s_nonce_share_key_a: Uint8ToArray(s_tx_nonce_share_key)
									};
									///console.log("ClientReady message->:" + JSON.stringify(crm));
																		
									// send 
									try {
										self.ws.send(JSON.stringify(crm)/*, {binary: false, mask: false}*/);

										// clear Handshake timeout
										if (self.hs_tmo)
											clearTimeout(self.hs_tmo);

										// state -> SendClientReady
										self.state = 'SendClientReady';

										// Construct NACL rx box
										self.rxBox = new Box(self.theirPublicKey, self.mySecretKey, self.theirNonce);
										self.rxSecretBox = new SecretBox(self.rxShareKey, self.theirNonce);

										// defer hand-shake done 20ms(about RTT)
										setTimeout(function(){
											// set hand shake done
											self.state = 'HandshakeDone';

											// Flush sendCache
											self.sendCache.forEach(function(c){
												self.send(c.message, c.fn)
											});
											self.sendCache = [];

											// emit Open event
											self.emit("open");
										}, 20);
									} catch (e) {
										console.log('send ClientReady immediately failed:'+e);
										self.ws.close();
									}
								} else {
									self.emit('warn', 'Attacked ServerHello opc message:'+JSON.stringify(message));
								}
							} else {
								self.emit('warn', 'Invalid ServerHello opc message:'+JSON.stringify(message));
							}
						} catch (e) {
							self.emit('warn', e+'Error ServerHello message:'+JSON.stringify(message));
						}
					} else {
						self.emit('warn', 'Invalid handshake message:'+JSON.stringify(message));
					}
				} else {
					self.emit('warn', 'Invalid message:'+JSON.stringify(message));
				}
			};
			
			// 1.
			// Send ClientHello message
			
			// update secure info
			self.myNonce = Nacl.randomBytes(8);
			var chm = 
			{
				opc: 0, 
				version: PROTO_VERSION,
				
				client_public_key: Uint8ToArray(self.myPublicKey),
				nonce: Uint8ToArray(self.myNonce)
			};
			///console.log("ClientHello message->:" + JSON.stringify(chm));

			// send 
			try {
				self.ws.send(JSON.stringify(chm)/*, {binary: false, mask: false}*/);

				// state -> SendClientHello
				self.state = 'SendClientHello';
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

		// server client handshake
		var server_handshake = function() {
			// state -> connected
			self.state = 'connected';
			
			// Handshake message handle
			self.ws.onmessage = function(msg){
				///console.log('server msg,type:'+JSON.stringify(msg.type));

				var message = msg.data;
				var flags = {
				    binary: !(typeof message === 'string')
				};
				
				if (self.state === 'HandshakeDone') {
				    // Normal authenticated-encryption 
					if (flags && flags.binary) {
						var data = new Uint8Array(message);

						// decrypt data
						var plain = self.rxSecretBox.open(data);
						if (plain) {
							// increase nonce
							self.rxSecretBox.incrNonce();

							// notify data
							self.emit('message', plain, {binary: true});
						} else {
							self.emit('warn', 'Attacked message:'+JSON.stringify(message));
						}
					} else {
						// TBD... String
						self.emit('warn', 'Not support String message');
					}
				} else if (self.state === 'HandshakeStart') {
					// ClientHello process
					if (flags && !flags.binary) {
						try {
							var chm = JSON.parse(message);

							if (chm && chm.opc === 0 && chm.version === PROTO_VERSION) {
								///console.log('ClientHello message<-:'+JSON.stringify(chm));
								
								// update secure info
								self.theirPublicKey = ArrayToUint8(chm.client_public_key);
								self.theirNonce = ArrayToUint8(chm.nonce);

								self.myNonce = Nacl.randomBytes(8);
								self.txShareKey = Nacl.randomBytes(Nacl.secretbox.keyLength);

								// Constructor NACL tx box
								self.txBox = new Box(self.theirPublicKey, self.mySecretKey, self.myNonce);
								self.txSecretBox = new SecretBox(self.txShareKey, self.myNonce);

								// send ServerHello message
								var tx_nonce_share_key = new Uint8Array(self.myNonce.length+self.txShareKey.length);
								tx_nonce_share_key.set(self.myNonce); 
								tx_nonce_share_key.set(self.txShareKey, self.myNonce.length);

								// tx temp Box
								var tx_tempbox = new Box(self.theirPublicKey, self.mySecretKey, self.theirNonce);
								var s_tx_nonce_share_key = tx_tempbox.box(tx_nonce_share_key);

								var shm = 
								{
										opc: 1, 
										version: PROTO_VERSION,

										server_public_key: Uint8ToArray(self.myPublicKey),
										s_nonce_share_key_a: Uint8ToArray(s_tx_nonce_share_key)
								};
								///console.log("ServerHello message->:" + JSON.stringify(shm));

								// send 
								try {
									self.ws.send(JSON.stringify(shm)/*, {binary: false, mask: false}*/);

									// state -> SendServerHello
									self.state = 'SendServerHello';
								} catch (e) {
									console.log('send ServerHello immediately failed:'+e);
									self.ws.close();
								}
							} else {
								self.emit('warn', 'Invalid ClientHello opc message:'+JSON.stringify(message));
							}
						} catch (e) {
							self.emit('warn', e+'Error ClientHello message:'+JSON.stringify(message));
						}
					} else {
						self.emit('warn', 'Invalid handshake message:'+message);
					}
				} else if (self.state === 'SendServerHello') {
					// ClientReady process
					if (flags && !flags.binary) {
						try {
							var crm = JSON.parse(message);

							if (crm && crm.opc === 2 && crm.version === PROTO_VERSION) {
								///console.log('ClientReady message<-:'+JSON.stringify(crm));

								// extract rxsharedKey, nonce
								var rx_tempbox = new Box(self.theirPublicKey, self.mySecretKey, self.myNonce);
								var rx_nonce_share_key = rx_tempbox.open(ArrayToUint8(crm.s_nonce_share_key_a));

								if (rx_nonce_share_key) {
									// clear Handshake timeout
									if (self.hs_tmo)
										clearTimeout(self.hs_tmo);

									// update secure info
									self.theirNonce = rx_nonce_share_key.subarray(0, 8);
									self.rxShareKey = rx_nonce_share_key.subarray(8);

									// Construct NACL rx box
									self.rxBox = new Box(self.theirPublicKey, self.mySecretKey, self.theirNonce);
									self.rxSecretBox = new SecretBox(self.rxShareKey, self.theirNonce);

									// set hand shake done
									self.state = 'HandshakeDone';

									// Flush sendCache
									self.sendCache.forEach(function(c){
										self.send(c.message, c.fn)
									});
									self.sendCache = [];

									// emit Open event
									self.emit("open");
								} else {
									self.emit('warn', 'Attacked ClientReady opc message:'+JSON.stringify(message));
								}
							} else {
								self.emit('warn', 'Invalid ClientReady opc message:'+JSON.stringify(message));
							}
						} catch (e) {
							self.emit('warn', e+'Error ClientReady message:'+JSON.stringify(message));
						}
					} else {
						self.emit('warn', 'Invalid handshake message:'+JSON.stringify(message));
					}
				} else {
					self.emit('warn', 'Invalid message:'+JSON.stringify(message));
				}
			};
			
			// state -> HandshakeStart
			self.state = 'HandshakeStart';
			
			// 1.
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
			server_handshake();
		else
			self.ws.onopen = client_handshake;
		
		// Send cache
		self.sendCache = [];
	};
	SecureWebSocket.prototype.onopen = function(fn) {
		this.events['open'] = [];
		this.on('open', fn);
	};
	SecureWebSocket.prototype.onmessage = function(fn) {
		this.events['message'] = [];
	    this.on('message', fn);
	};
	SecureWebSocket.prototype.onerror = function(fn) {
		this.events['error'] = [];
		this.on('error', fn);
		this.ws.onerror = fn;
	};
	SecureWebSocket.prototype.onwarn = function(fn) {
		this.events['warn'] = [];
		this.on('warn', fn);
	};
	SecureWebSocket.prototype.onclose = function(fn) {
		this.events['close'] = [];
		this.ws.onclose = fn;
	};

	SecureWebSocket.prototype.close = function(fn) {
	    this.ws.close();
	};
	SecureWebSocket.prototype.send = function(message, fn) {
		var self = this;
		var ret = true;

		if (self.state === 'HandshakeDone') {
			if (message) {
				if (!(typeof message === 'string')) {
					var data = new Uint8Array(message);

					// ecrypt
					var cipher = self.txSecretBox.box(data);
					if (cipher) {
						// increase nonce
						self.txSecretBox.incrNonce();

						// write data out
						try {
							// TBD... flow control
							var rc = self.ws.send(cipher/*, {binary: true, mask: false}*/);
							if (fn) fn();

							if (typeof rc === 'undefined' || rc === null)
								ret = self.ws.bufferedAmount < SEND_WATER_MARK;
							else
								ret = rc;
						} catch (e) {
							if (fn) fn('ws.send failed:'+e);
						}
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
			self.sendCache.push({message: message, fn: fn});
			return false;
		}

		return ret;
	};
	SecureWebSocket.prototype.pause = function() {
		var self = this;
		if (self.ws && self.ws.pause) self.ws.pause();
	};
	SecureWebSocket.prototype.resume = function() {
		var self = this;
		if (self.ws && self.ws.resume) self.ws.resume();
	};
	SecureWebSocket.prototype.terminate = function() {
		var self = this;
		if (self.ws && self.ws.terminate) self.ws.terminate();
	};
	
	// EventEmitter
	SecureWebSocket.prototype.on = function(event, fn) {
		var self = this;
		
		self.events[event] = self.events[event] || [];
		
		self.events[event].push(fn);
		
		return self;
	};	
	SecureWebSocket.prototype.emit = function(event, message, flags, cb) {
		var self = this;
		
		if (self.events && self.events[event]) {
			self.events[event].forEach(function(fn) {
			    if (fn && typeof fn === 'function')
			    	fn(message, flags, cb);
			});
		} else {
			console.log('Unknown event:'+event);
			return false;
		}
		
		return true;
	}
	
	// NACL wrapper
	var Box = function(theirPublicKey, mySecretKey, nonce) {
		if (!(this instanceof Box))
			return new Box(theirPublicKey, mySecretKey, nonce);

		// check on parameters
		if (!(theirPublicKey instanceof Uint8Array &&
			  mySecretKey instanceof Uint8Array &&
			  nonce instanceof Uint8Array))
			throw new Error('Invalid Box params:'+JSON.stringify(arguments));

		var self = this;
		
		self.theirPublicKey = new Uint8Array(theirPublicKey);
		self.mySecretKey = new Uint8Array(mySecretKey);
		
		self.nonce = new Uint8Array(nonce);
	
		self.nonceH = 
				(self.nonce[7]&0xff) << 24 |
				(self.nonce[6]&0xff) << 16 |
				(self.nonce[5]&0xff) <<  8 |
				(self.nonce[4]&0xff) <<  0;
		self.nonceL = 
				(self.nonce[3]&0xff) << 24 |
				(self.nonce[2]&0xff) << 16 |
				(self.nonce[1]&0xff) <<  8 |
				(self.nonce[0]&0xff) <<  0;

		// pre sharedkey
		self.sharedKey = Nacl.box.before(self.theirPublicKey, self.mySecretKey);
	}
	Box.prototype.box = function(plain) {
		var self = this;
		
		if (!(plain instanceof Uint8Array))
		    throw new Error('Invalid Box.box params:'+JSON.stringify(arguments));

		var cipher = Nacl.box.after(plain, self.generateNonce(), self.sharedKey);
		if (cipher) {
			return cipher;
		} else {
			console.log('Box box attacked:'+JSON.stringify(plain));
			return false;
		}
	}
	Box.prototype.open = function(cipher) {
		var self = this;

		if (!(cipher instanceof Uint8Array))
			throw new Error('Invalid Box.open params:'+JSON.stringify(arguments));

		var plain = Nacl.box.open.after(cipher, self.generateNonce(), self.sharedKey);
		if (plain) {			
			return plain;
		} else {
			console.log('Box open attacked:'+JSON.stringify(cipher));
			return false;
		}
	}
	Box.prototype.incrNonce = function() {		
		// check on 32bits carry
		if (((++this.nonceL)&0xffffffff) == 0) {
			this.nonceH ++;
			return true;
		}
		return false;
	}
	Box.prototype.generateNonce = function() {
		var n = new Uint8Array(Nacl.box.nonceLength);

		for (var i = 0; i < Nacl.box.nonceLength; i += 8) {
			n[i+0] = ((this.nonceL >>>  0) & 0xff);
			n[i+1] = ((this.nonceL >>>  8) & 0xff);
			n[i+2] = ((this.nonceL >>> 16) & 0xff);
			n[i+3] = ((this.nonceL >>> 24) & 0xff);

			n[i+4] = ((this.nonceH >>>  0) & 0xff);
			n[i+5] = ((this.nonceH >>>  8) & 0xff);
			n[i+6] = ((this.nonceH >>> 16) & 0xff);
			n[i+7] = ((this.nonceH >>> 24) & 0xff);
		}

		return n;
	}
	
	// SecretBox
	var SecretBox = function(sharedKey, nonce) {
		if (!(this instanceof SecretBox))
			return new SecretBox(sharedKey, nonce);

		// check on parameters
		if (!(sharedKey instanceof Uint8Array &&
			  nonce instanceof Uint8Array))
			throw new Error('Invalid SecretBox params:'+JSON.stringify(arguments));
		
		var self = this;
		
		self.sharedKey = new Uint8Array(sharedKey);
		
		self.nonce = new Uint8Array(nonce);
		
		self.nonceH = 
				(self.nonce[7]&0xff) << 24 |
				(self.nonce[6]&0xff) << 16 |
				(self.nonce[5]&0xff) <<  8 |
				(self.nonce[4]&0xff) <<  0;
		self.nonceL = 
				(self.nonce[3]&0xff) << 24 |
				(self.nonce[2]&0xff) << 16 |
				(self.nonce[1]&0xff) <<  8 |
				(self.nonce[0]&0xff) <<  0;
	}
	SecretBox.prototype.box = function(plain) {
		if (!(plain instanceof Uint8Array))
			throw new Error('Invalid SecretBox.box params:'+JSON.stringify(arguments));

		var cipher = Nacl.secretbox(plain, this.generateNonce(), this.sharedKey);
		if (cipher) {
			return cipher;
		} else {
			console.log('SecretBox box attacked:'+JSON.stringify(plain));
			return false;
		}
	}
	SecretBox.prototype.open = function(cipher) {
		if (!(cipher instanceof Uint8Array))
			throw new Error('Invalid SecretBox.open params:'+JSON.stringify(arguments));

		var plain = Nacl.secretbox.open(cipher, this.generateNonce(), this.sharedKey);
		if (plain) {
			return plain;
		} else {
			console.log('SecretBox open attacked:'+JSON.stringify(cipher));
			return false;
		}
	}
	SecretBox.prototype.incrNonce = function() {		
		// check on 32bits carry
		if (((++this.nonceL)&0xffffffff) == 0) {
			this.nonceH ++;
			return true;
		}
		return false;
	}
	SecretBox.prototype.generateNonce = function() {
		var n = new Uint8Array(Nacl.secretbox.nonceLength);

		for (var i = 0; i < Nacl.secretbox.nonceLength; i += 8) {
			n[i+0] = ((this.nonceL >>>  0) & 0xff);
			n[i+1] = ((this.nonceL >>>  8) & 0xff);
			n[i+2] = ((this.nonceL >>> 16) & 0xff);
			n[i+3] = ((this.nonceL >>> 24) & 0xff);

			n[i+4] = ((this.nonceH >>>  0) & 0xff);
			n[i+5] = ((this.nonceH >>>  8) & 0xff);
			n[i+6] = ((this.nonceH >>> 16) & 0xff);
			n[i+7] = ((this.nonceH >>> 24) & 0xff);
		}

		return n;
	}

	// Utils
	function ArrayToUint8(data) {
		if (Array.isArray(data)) {
			var ret = new Uint8Array(data.length);
			ret.set(data);
			return ret;
		} else if (data instanceof Uint8Array) {
			return data
		} else {
			console.log('invalid ArrayToUint8:'+JSON.stringify(data));
			return null;
		}
	}
	function Uint8ToArray(data) {
		if (Array.isArray(data)) {
			return data;
		} else if (data instanceof Uint8Array) {
			return Array.prototype.slice.call(data);
		} else {
			console.log('invalid Uint8ToArray:'+JSON.stringify(data));
			return null;
		}
	}
	function Uint8ToBuffer(data) {
		// check node buffer first
		if (typeof Buffer != 'undefined' && data instanceof Buffer) {
			return data;
		} else if (data instanceof ArrayBuffer) {
			return data;
		} else if (data instanceof Uint8Array) {
			// check node buffer first
			if (typeof Buffer != 'undefined')
				return new Buffer(data);
			else {
				var ret = new ArrayBuffer(data.length);
				var viw = new Uint8Array(ret);
				viw.set(data);
				return ret;
			} 
		} else {
			console.log('invalid Uint8ToArray:'+JSON.stringify(data));
			return null;
		}
	}
	
	// Export 
	Export.SecureWebSocket = SecureWebSocket;
	
	Export.Nacl    = Nacl;	
	Export.keyPair = Nacl.box.keyPair;
	
	Export.Box       = Box;
	Export.SecretBox = SecretBox;
	
	Export.ArrayToUint8  = ArrayToUint8;
	Export.Uint8ToArray  = Uint8ToArray;
	Export.Uint8ToBuffer = Uint8ToBuffer;
})(typeof module  !== 'undefined' ? module.exports                    :(window.sws = window.sws || {}), 
   typeof require !== 'undefined' ? require('tweetnacl/nacl-fast.js') : window.nacl,
   typeof require !== 'undefined' ? require('wspp')                   : window.WebSocket);
