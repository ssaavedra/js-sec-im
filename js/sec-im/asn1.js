dojo.provide("sec-im.asn1");
dojo.require("dojox.encoding.base64");

/**
 * ASNValue constructor
 *
 * The value of an ASNValue shall be:
 *   * A Number or a BigInteger if the tag is INTEGER,
 *   * A String or something alike (or an ASNValue) if the tag is BITSTRING,
 *   * An Array object containing 0 or more ASNValue objects.
 * 
 * Currently only the basic values for RSA to work are implemented, namely:
 * OBJECT_IDENTIFIER (as OBJECTID), INTEGER, BITSTRING, NULL and SEQUENCE.
 * Any other ASN.1 Valid string will not be generated (and will not be
 * correctly parsed).
 *
 * @param tag The tag name (as in ANValue.prototype.tags)
 * @param value The value of this ASNValue
 */
function ASNValue(tag, value) {
	this.tag = this.tags[tag];
	this.value = value;
}

/**
 * The possible tags for an ASNValue
 */
ASNValue.prototype.tags = {
	INTEGER: 0x02,
	BITSTRING: 0x03,
	NULL: 0x05,
	OBJECTID: 0x06,
	SEQUENCE: 0x30
};

ASNValue.getSizeBytes = function(size) {
	if(size < 0x80) {
		return [size];
	} else {
		var s = hex2ba(size.toString(16));
		var f = [0x80 + s.length];
		return f.concat(s);
	}
}

ASNValue.prototype.toASNbytes = function() {
	if(this.tag == 0x02)
		var r = ASNValue._integer2ASN(this.value);
	if(this.tag == 0x03)
		var r = ASNValue._bitstring2ASN(this.value);
	if(this.tag == 0x30)
		var r = ASNValue._sequence2ASN(this.value);
	if(this.tag == 0x05)
		var r = [0x01, 0x00];
	if(this.tag == 0x06)
		var r = ASNValue._oid2ASN(this.value);
	
	r.unshift(this.tag);
	return r;
}

ASNValue._oid2ASN = function(str) {
	// Get OID octets from str
	// First discard until ":" if any
	var str = str
			.replace(/^.*:/g, '')
			.replace(/\./g, ' ')
			.replace(/\s+/g, ' ')
			.trim();
	
	// Get the octets as bytes
	var subids = str.split(" ").map(function(e) {
		return parseInt(e);
	});
	
	// Now parse them as ASN.1 wants us to
	// So, let us sum the first two subids to get the first octet
	var firstOctet = subids[0] * 40 + subids[1];
	var rest = subids.slice(2);
	var subids = [firstOctet].concat(rest);
	
	var octetsinarray = subids.map(function(x) {
		var h;
		var offset = 0, sum = 0;
		if(x < 0x100)
			return [x];
		
		// First octet:
		var masked = x & 0x7F;
		sum += masked;
		x = x >> 7;
		offset = 8;
		
		while(x) {
			masked = x & 0x7F;
			sum += (masked + 0x80) << offset;
			offset += 8;
			x = x >> 7;
		}
		return hex2ba(sum.toString(16));
	});
	var bytes = [];
	for(var i = 0; i < octetsinarray.length; i++) {
		var value = octetsinarray[i];
		for(var j = 0; j < value.length; j++)
			bytes.push(value[j]);
	}
	
	var size = ASNValue.getSizeBytes(bytes.length);
	
	return size.concat(bytes);
}

ASNValue._bitstring2ASN = function(v) {
	if(v instanceof ASNValue)
		var v = v.toASNbytes();
	else
		var v = v.split('').map(function(e) { return e.charCodeAt(0); });
	
	var size = ASNValue.getSizeBytes(v.length);
	return size.concat(v);
}

ASNValue._integer2ASN = function(v) {
	var my_v = hex2ba(v.toString(16));
	var size = ASNValue.getSizeBytes(my_v.length);
	return size.concat(my_v);
}

ASNValue._sequence2ASN = function(array) {
	var array_len = array.length;
	var bytes = [];
	
	// Now push every element on the sequence.
	// They must all already be ASNValues
	// TODO Test for ASNValues *or bytestrings?*
	for(var i = 0; i < array_len; i++) {
		if(array[i] instanceof ASNValue) {
			bytes = bytes.concat(array[i].toASNbytes());
		} else { throw [array[i] , "is not an ASNValue!"]; }
	}
	
	var size = ASNValue.getSizeBytes(bytes.length);
	return size.concat(bytes);
}

/**
 * @static
 * Method for parsing a buffer into an ASNValue Object
 */
ASNValue.fromASN = function(buffer) {

	if(buffer instanceof String) {
		var buffer = s2ba(buffer);
	}
	var tag = buffer[0];
	if(tag == 0x02 || tag == 0x03) // Integer or bytestring
	{
		var size = buffer[1];
		var base = 2;
		if(size > 0x80) {
			size -= 0x80;
			base += size;
			var size = parseInt(byte2hex(buffer.splice(2, size)), 16)
		}
		var body = buffer.splice(base, ssize);
		return new ASNValue(tag, body);
	} else if (tag == 0x30) { // Sequence
		var size = buffer[1];
		var offset = 2;
		if(size > 0x80) {
			size -= 0x80;
			var size = parseInt(byte2hex(buffer.splice(2, size)), 16);
			offset += size;
		}
		var value = []; var v, new_offset = 0, next_size;
		for(var i = 0; i < size; i++) {
			// For performance, we'll forward-look the size:
			next_size = buffer.splice(offset, 1);
			if(next_size > 0x80) {
				next_size -= 0x80;
				next_size = parseInt(byte2hex(buffer.splice(offset + 1, next_size)), 16);
			}
			v = ASNValue.fromASN(buffer.splice(offset, next_size));
			offset += next_size;
			value.push(v);
		}
		
		return new ASNValue(tag, value);
	}
}


function hex2ba(h) {
	  if(h.length % 2)
		h = "0"+h;
	  var a = new Array();
	  for(var i = 0; 2*i < h.length; ++i) {
	    a[i] = parseInt(h.substring(2*i,2*i+2),16);
	  }
	  return a;
}

function ba2s(array) {
	var stream = "";
	var len = array.length;
	for(var i = 0; i < len; i++)
		stream += String.fromCharCode(array[i]);
	return stream;
}

function s2ba(string) {
	var len = string.length;
	var a = [];
	for(var i = 0; i < len; i++) {
		a.push(string.charCodeAt(i));
	}
	return a;
}

function byte2hex(ba) {
	return ba.map(
		function (e) {
			var h = e.toString(16);
			return h.length == 1 ? "0" + h : h;
		}
	).join('');
}

