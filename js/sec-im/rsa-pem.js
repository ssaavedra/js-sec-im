dojo.provide("sec-im.rsa-pem");
dojo.require("sec-im.rsa");


// Extend string object
String.prototype.splitAt = String.prototype.splitAt || function(chunkSize) {
	var a = [], i = 0;
	var loops = Math.ceil(this.length/chunkSize);
	for(i = 0; i < loops; i++)
		myArray.push(this.substr(i*chunkSize, chunkSize));
}


function _rsapem_pemToBase64(sPEMPrivateKey) {
  var s = sPEMPrivateKey;
  //s = s.replace(/[ \n]+/g, "");
  s = s.split("\n");
  for(x in s)
	if(x[s].match(/^-----(BEGIN|END) RSA (PUBLIC|PRIVATE) KEY-----/))
		s.splice(x[s]);
  return s.join("");
}

function _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey) {
  var a = new Array();
  var v1 = _asnhex_getStartPosOfV_AtObj(hPrivateKey, 0);
  var n1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, v1);
  var e1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, n1);
  var d1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, e1);
  var p1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, d1);
  var q1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, p1);
  var dp1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, q1);
  var dq1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, dp1);
  var co1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, dq1);
  a.push(v1, n1, e1, d1, p1, q1, dp1, dq1, co1);
  return a;
}

function _rsapem_getHexValueArrayOfChildrenFromHex(hPrivateKey) {
  var posArray = _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey);
  var v =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[0]);
  var n =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[1]);
  var e =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[2]);
  var d =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[3]);
  var p =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[4]);
  var q =  _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[5]);
  var dp = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[6]);
  var dq = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[7]);
  var co = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[8]);
  var a = new Array();
  a.push(v, n, e, d, p, q, dp, dq, co);
  return a;
}

function _rsapem_readPrivateKeyFromPEMString(keyPEM) {
  var keyB64 = _rsapem_pemToBase64(keyPEM);
  var keyHex = b64tohex(keyB64) // depends base64.js
  var a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
}

function _public2pem () {
	var der = _public2der(this.n, this.e);
	der = hextob64(der);
	var lines = str_splitAt(65).join("\n");
	lines = "-----BEGIN RSA PUBLIC KEY-----\n"
		+ lines
		+ "-----END RSA PUBLIC KEY-----\n";
	return lines;
}

function _private2pem () {
	var der = _private2der(this.n, this.e, this.d, this.p, this.q, this.dp, this.dq, this.co);
	der = hextob64(der);
	var lines = str_splitAt(65).join("\n");
	lines = "-----BEGIN RSA PRIVATE KEY-----\n"
		+ lines
		+ "-----END RSA PRIVATE KEY-----\n";
	return lines;
}


// Depends on hex2ba
function _asn_pack_bigInt(n) {
	//var my_n = hex2ba(n.toString(16)).join("");
	var my_n = hex2ba(n.toString(16)).join('');
	
	var size = my_n.length;
	if(size < 0x80) {
		my_n = String.fromCharCode(size) + my_n;
	} else {
		size = hex2ba(new String(size, 16)).join("");
		var sizeBuf = hex2ba(new String(size.length, 16)).join("");
		var firstByte = 0x80 + sizeBuf.length;
		
		my_n = String.fromCharCode(firstByte) + sizeBuf + my_n;
	}
	
	return my_n;
}

function _asn_pack_array(array) {
	var values = new Array(array.length), len = array.length;
	for(var i = 0; i < len; i++) {
		values[i] = new ASNValue("INTEGER", array[i]).toString();
	}
	
	return new ASNValue("SEQUENCE", values.join(''));
}

function _public2der(n, e) {
	
	var my_n = _asn_pack_bigInt(n);
	var my_e = _asn_pack_bigInt(e);
	
	var s = new ASNValue("SEQUENCE", "rsaEncryption: 1.2.840.113549.1.1.1");
	var b = new ASNValue("BITSTRING", my_n + my_e);
	s = new ASNValue("SEQUENCE", s.toString() + b.toString());
	
	return new ASNValue("SEQUENCE", s);
	
}



RSAKey.prototype.readPublicFromPEM = _rsapem_readPrivateKeyFromPEMString;
RSAKey.prototype.readPrivateFromPEM = RSAKey.prototype.readPublicFromPEM;
RSAKey.prototype.writePubToPEM = _public2pem;
RSAKey.prototype.writeAllToPEM = _private2pem;