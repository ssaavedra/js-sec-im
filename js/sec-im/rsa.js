dojo.provide("sec-im.rsa");

var requirements = "base64|jsbn|jsbn2|prng4|rng|rsa|rsa2|sha1".split("|");
for(x in requirements)
	if(typeof requirements[x] == "string")
		dojo.require("jsbn." + requirements[x]);

//requirements = "asn1hex|rsa-pem|rsa-sign|x509".split("|");
//for(x in requirements)
//	if(typeof requirements[x] == "string")
//		dojo.require("jsrsa." + requirements[x]);
dojo.require("sec-im.asn1");
dojo.require("sec-im.rsa-pem");


/**
 * Get RSA Key Instance by public and private parts
 * as returned by RSAKey.toString()
 */
RSAKey.instance = function(serialized) {
	var t = new RSAKey();
	
	t.setPrivateEx(N,E,D,P,Q,DP,DQ,C);
	return t;
}

RSAKey.prototype.serialize = function() {
	var v = "n,e,d,p,q,dmp1,dmq1,coeff".split(",");
	var o = {};
	for(var i = 0; i < v.length; i++) {
		o[v[i]] = this[v[i]].toString(16);
	}
	return JSON.stringify(o);
}

RSAKey.prototype.unserialize = function(str) {
	var o = JSON.parse(str);
	var v = "n,e,d,p,q,dmp1,dmq1,coeff".split(",");
	var p = [];
	for(var i = 0; i < v.length; i++) {
		p.push(o[v[i]]);
	}
	this.setPrivateEx.apply(this, p);
}


sec_im.rsa = {
	
	getKeyByHash: function() {
		if(2 > window.location.hash.length)
			return;
		var h = window.location.hash.substring(1);
		var pu, pr;
		h = h.split("&");
		for(x in h)
			if(typeof h[x] == "string")
				if(h[x].match(/^pu/))
					pu = h[x];
				if(h[x].match(/^pr/))
					pr = h[x];

		if(typeof pr == "undefined"
		|| typeof pu == "undefined") return;

		return RSAKey.instance(pu, pr);
	},
	
	getKeyByLocalStorage: function() {
		if(!window.localStorage) return;
		if(!window.localStorage.rsa) return;
		
		var t = new RSAKey();
		t.unserialize(window.localStorage.rsa);
		return t;
	},
	
	
	getSavedKey: function() {
		return this.getKeyByHash() || this.getKeyByLocalStorage() || this.generateKey(1024, "65537");
	},
	
	generateKey: function(bits, exp) {
		var t = new RSAKey();
		t.generate(bits, exp);
		return t;
	},
	
	saveKey: function(key) {
		this.key = key;
		if(!window.localStorage) return;
		window.localStorage.rsa = this.key.serialize();
	}
}
sec_im.rsa.key = sec_im.rsa.getSavedKey();

