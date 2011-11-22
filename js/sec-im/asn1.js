dojo.provide("sec-im.asn1");


// Depends on hex2ba
function _asn_pack_bigInt(n) {
	var my_n = hex2ba(n.toString(16)).join("");
	var size = my_n.length;
	if(size < 0x80) {
		my_n = String.fromCharCode(size) + my_n;
	} else {
		size = hex2ba(size.toString(16)).join("");
		var sizeBuf = hex2ba(new String(size.length, 16)).join("");
		var firstByte = 0x80 + sizeBuf.length;
		
		my_n = String.fromCharCode(firstByte) + sizeBuf + my_n;
	}
	
	return my_n;
}

function _public2der(n, e) {
	
	var my_n = _asn_pack_bigInt(n);
	var my_e = _asn_pack_bigInt(e);
	
}

function _asnvalue_encode() {
	var result = String.fromCharCode(this.tag);
	var size = this.value.length;
	if(size < 0x80)
		result += String.fromCharCode(size);
	else {
		var sizebuf = this.int2bin(size);
		var firstByte = 0x80 + sizebuf.length;
		result += String.fromCharCode(firstByte) + sizebuf;
	}
	
	result += this.value;
	return result;
}

function _asnvalue_decode(buffer) {
	this.tag = buffer.substring(0, 1);
	var firstByte = this.bin2int(buffer.substring(1, 1)), size;
	var buffer = buffer.substring(2);

	if(firstByte < 0x80)
		size = firstByte
	else {
		var len = firstByte - 0x80;
		size = this.bin2int(buffer.substring(0, len));
		buffer = buffer.substring(len);
	}
	
	this.value = buffer.substring(0, size);
	return this.value;
}

function _asnvalue_tostring() {
	
}


ASNValue = function(tag, value) {
	this.tag = this.tags[tag];
	this.value = "" || value;
}
ASNValue.prototype.tags = {
	INTEGER: 0x02,
	BITSTRING: 0x03,
	SEQUENCE: 0x30
};


function _bin2int_(str) {
	var x = str.split(''), len = x.length, work = new Array();
	for(var i=0; i<len; i++) {
		var c = str.charCodeAt(i);
		c = (c < 0x10) ? "0" + (c.toString(16)) : c.toString(16);
		work.push(c);
	}
	return parseInt(work.join(''), 16);
}

function _bin2int(str) {
	var x = str.split(''), len = x.length, result = 0;
	for(var i = 0; i < len; i++) {
		var curByte = x[i];
		result += curByte << ((len - i - 1) << 3);
	}
}

function _int2bin(integer) {
	var result = '', curbyte;
	do {
		curbyte = integer % 256;
		result += String.fromCharCode(curbyte);
		
		integer = Math.floor(integer - curbyte) / 256;
	} while(integer > 0);
	
	
	result = result.split('').reverse().join('');
}

// Protected
ASNValue.prototype.int2bin = _int2bin;
ASNValue.prototype.bin2int = _bin2int;

// Public
ASNValue.prototype.encode = _asnvalue_encode;
