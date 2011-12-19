dojo.provide("sec-im.ui");

dojo.require("dijit.TitlePane");
dojo.require("dijit.form.Form");
dojo.require("dijit.form.Textarea");
dojo.require("dijit.form.Button");
dojo.require("dijit.form.NumberTextBox");

// Get User Interface

sec_im.ui = dojo.mixin(sec_im.ui, {
	tp: null,
	
	
	genkey: {
		form_options: {
			id: "genkey_form"
		},
		form_ui: function() {
			this.f = new dijit.form.Form(this.form_options);
			var x = new dijit.form.NumberTextBox({
				id: "rsagen_bits",
				label: "RSA Key Length",
				value: 1024
			});
			this.tb = x;
			this.tb.placeAt(this.f.domNode);
			
			this.btn = new dijit.form.Button({
				id: "rsagen_btn",
				label: "Generate Key",
				onClick: function() {
					sec_im.ui.genkey.generateAndShowKey(x.get('value'));
				}
			});
			this.btn.placeAt(this.f.domNode);
			
			return this.f;
		},
		
		generateAndShowKey: function(bits) {
			sec_im.rsa.saveKey(sec_im.rsa.generateKey(bits, "65537"));
			sec_im.ui.showkey.refresh();
		}
	},
	
	showkey: {
		form_id: 0,
		pub: null,
		pri: null,
		ui: function(pubkey, prkey) {
			var key = sec_im.rsa.key;
			
			
			this.div = new dijit.form.Form({id:"showkey_form_" + this.form_id++});
			this.pub = new dijit.form.Textarea({
				id: "showkey_form_pubits",
				name: "pubits",
				style: "width:44em;font-family:monospace;padding:10px",
				value: key.pub2PEM()
			});
			
			this.pri = new dijit.form.Textarea({
				id: "showkey_form_prbits",
				name: "prbits",
				style: "width:44em;font-family:monospace;padding:10px",
				value: key.prv2PEM()
			});
			
			this.pub.placeAt(this.div.domNode);
			this.div.domNode.appendChild(document.createElement('br'));
			this.pri.placeAt(this.div.domNode);
			
			return this.div;
		},
		refresh: function() {
			// Look for new key
			if(!this.pub || !this.pri) throw "This is strange…";
			var key = sec_im.rsa.key;
			this.pub.set('value', key.pub2PEM());
			this.pri.set('value', key.prv2PEM());
		}
	},
	
	onLoad: function() {
		dojo.require("sec-im.ui.chat");
		
		this.tp_chat = new dijit.TitlePane({
			title: "Chat utility",
			content: ""
		});
		dojo.byId("canvas").appendChild(this.tp_chat.domNode);
		
		this.tp_chat.set('content', sec_im.ui.chat.ui());
		
		
		this.tp_gen = new dijit.TitlePane({
			title: "Generate RSA Key",
			content: ""
		});
		dojo.byId("canvas").appendChild(this.tp_gen.domNode);
		
		this.tp_gen.set('content', sec_im.ui.genkey.form_ui());
		this.tp_gen.open && this.tp_gen.toggle();
		
		this.tp_show = new dijit.TitlePane({
			title: "Show RSA Key in use",
			content: "",
			onHide: function() {
				this.get('content').destroy();
				this.set('content', '');
			},
			onFocus: function() {
				this.set('content', sec_im.ui.showkey.ui());
			}
		});
		dojo.byId("canvas").appendChild(this.tp_show.domNode);
		this.tp_show.set('content', sec_im.ui.showkey.ui());
		
		if(this.tp_show.open)
			this.tp_show.toggle();
		
	}
	
});

dojo.addOnLoad(sec_im.ui.onLoad);

