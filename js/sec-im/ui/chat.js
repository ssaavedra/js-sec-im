dojo.provide("sec-im.ui.chat");
dojo.require("sec-im.ui");

dojo.require("dijit.TitlePane");
dojo.require("dijit.form.Form");
dojo.require("dijit.form.Textarea");
dojo.require("dijit.form.Button");
dojo.require("dijit.form.NumberTextBox");

sec_im.ui.chat = dojo.mixin(sec_im.ui.chat, {

	// TODO: Send somewhere
	send: function(text) {
		var cyphertext = sec_im.rsa.key.encrypt(text);
		
		console.log(text, cyphertext);
		
		var sent = document.createElement('div');
		sent.className = "chat message sent";
		var author = document.createElement('div');
		author.className = "author";
		author.innerHTML = "Me";
		
		var timestamp = document.createElement('timestamp');
		timestamp.innerHTML = new Date().toString();
		
		var content = document.createElement('div');
		content.className = "chat inner"
		content.innerHTML = text;
		
		sent.appendChild(author);
		sent.appendChild(timestamp);
		sent.appendChild(content);
		
		this.text.appendChild(sent);
	},
	
	ui: function() {
		this.form = new dijit.form.Form({
			id: "chatform",
			action: "#",
			onsubmit: function(){return false}
		});
		
		this.text = document.createElement('div');
		this.text.id = "chat_content";
		this.text.className ="chat_content";
		this.form.domNode.appendChild(this.text);
		
		this.input = new dijit.form.Textarea({
			id: "chatinput",
			style:"width:30em;"
		});
		
		this.input.domNode.onkeypress = (function($, callback, input) {
			return function(evt) {
				callback.call(input, $, evt);
			}
		})(this, this._inputkeypress, this.input);
		this.input.placeAt(this.form.domNode);
		
		this.form.domNode.appendChild(document.createElement('p'));
		
		return this.form;
	},
	
	_inputkeypress: function($, evt) {
		if(evt.keyIdentifier == "Meta" || evt.ctrlKey && evt.keyIdentifier == "Enter")
		{
			// Disable textarea
			this.set('disabled', "disabled");

			// Cypher and send.
			var txt = this.get('value');
			$.send(txt);
			
			// Clear textarea
			this.set('disabled', false);
			this.set('value', '');
			evt.preventDefault();
			evt.stopPropagation();
			return false;
		}
		return true;
	}
	
});
