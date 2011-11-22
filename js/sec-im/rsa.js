dojo.provide("sec-im.rsa");

var requirements = "base64|jsbn|jsbn2|prng4|rng|rsa|rsa2|sha1".split("|");
for(x in requirements)
	if(typeof requirements[x] == "string")
		dojo.require("jsbn." + requirements[x]);

requirements = "asn1hex|rsa-pem|rsa-sign|x509".split("|");
for(x in requirements)
	if(typeof requirements[x] == "string")
		dojo.require("jsrsa." + requirements[x]);


/**
 * Get RSA Key Instance by public and private parts
 * as returned by RSAKey.toString()
 */
function RSAKeyInstance(public, private) {
	
}

/**
 * Returns a 
 */
function RSAKeyToString() {
	
}



function getUserKey() {
	return getKeyByHash() || getKeyByLocalStorage() || generateKey();
}

function getKeyByHash() {
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
}

function getKeyByLocalStorage() {
	if(!window.localStorage) return;
	if(!window.localStorage.rsa_pu) return;
	if(!window.localStorage.rsa_pr) return;
	
	return RSAKey.instance(window.localStorage.rsa_pu,
							window.localStorage.rsa_pr);
}

