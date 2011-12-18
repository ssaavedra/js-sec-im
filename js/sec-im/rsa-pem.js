dojo.provide("sec-im.rsa-pem");
dojo.require("sec-im.rsa");

dojo.require("dojox.encoding.base64");
dojo.require("jsrsa.rsa-pem");




function _public2der(n, e) {
	
	var my_n = new ASNValue("INTEGER", n);
	var my_e = new ASNValue("INTEGER", e);
	
	var s1 = new ASNValue("SEQUENCE", [my_n, my_e]);
	var bs = new ASNValue("BITSTRING", s1);
	
	var oid = new ASNValue("OBJECTID", "rsaEncryption: 1.2.840.113549.1.1.1");
	var nll = new ASNValue("NULL", null);
	var s2 = new ASNValue("SEQUENCE", [oid, nll]);
	
	var es = new ASNValue("SEQUENCE", [s2, bs]);
	return es.toASNbytes();
	
}

function _private2der(a /* values: n, e, d, p, q, dp, dq, co */) {
	var len = a.length, i;
	
	for(i = 0; i < len; i++) {
		a[i] = new ASNValue("INTEGER", a[i]);
	}
	var noise = new ASNValue("INTEGER", 0);
	
	return (new ASNValue("SEQUENCE", [noise].concat(a)).toASNbytes());
	
}

RSAKey.prototype.pub2DER = function() {
	return _public2der(this.n, this.e);
}

RSAKey.prototype.prv2DER = function() {
	var v = "n,e,d,p,q,dmp1,dmq1,coeff".split(',');
	var a = [];
	for(var i = 0; i < v.length; i++)
		a[i] = this[v[i]];
	return _private2der(a);
}


String.prototype.splitAt = String.prototype.splitAt || function(chunkSize) {
	var a = [], i = 0;
	var loops = Math.ceil(this.length/chunkSize);
	for(i = 0; i < loops; i++)
		a.push(this.substr(i*chunkSize, chunkSize));
	return a
}
String.prototype.toBase64 = String.prototype.toBase64 || function() {
	return dojox.encoding.base64.encode(this.toByteArray());
}

function _public2pem () {
	var der = dojox.encoding.base64.encode(_public2der(this.n, this.e));
	var lines = der.splitAt(65).join("\n");
	
	lines = "-----BEGIN RSA PUBLIC KEY-----\n" + lines;
	lines += "\n-----END RSA PUBLIC KEY-----\n";
	return lines;
}

function _private2pem () {

	
	var der = _private2der([this.n, this.e, this.d, this.p, this.q, this.dmp1, this.dmq1, this.coeff]);
	der = dojox.encoding.base64.encode(der);
	
	var lines = der.splitAt(65).join("\n");
	
	lines = "-----BEGIN RSA PRIVATE KEY-----\n" + lines;
	lines +="\n-----END RSA PRIVATE KEY-----\n";
	return lines;
}
RSAKey.prototype.pub2PEM = _public2pem;
RSAKey.prototype.prv2PEM = _private2pem;


function _rsapem_pemToBase64(sPEMPrivateKey) {
  var s = sPEMPrivateKey;
  //s = s.replace(/[ \n]+/g, "");
  s = s.split("\n");
  for(x in s)
	if(x[s].match(/^-----(BEGIN|END) RSA (PUBLIC|PRIVATE) KEY-----/))
		s.splice(x[s]);
  return s.join("");
}
function _rsapem_readPrivateKeyFromPEMString(keyPEM) {
  var keyB64 = _rsapem_pemToBase64(keyPEM);
  var keyHex = b64tohex(keyB64) // depends base64.js
  var a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
  this.setPrivateEx(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
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


RSAKey.prototype.readPublicFromPEM = _rsapem_readPrivateKeyFromPEMString;
RSAKey.prototype.readPrivateFromPEM = RSAKey.prototype.readPublicFromPEM;

//*/
