dojo.provide("sec-im.rsa");

var requirements = "base64|jsbn|jsbn2|prng4|rng|rsa|rsa2|sha1".split("|");
for(x in requirements)
	if(typeof requirements[x] == "string")
		dojo.require("jsbn." + requirements[x]);


