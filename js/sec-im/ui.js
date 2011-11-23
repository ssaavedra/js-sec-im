dojo.provide("sec-im.ui");

dojo.require("dijit.TitlePane");
dojo.require("dijit.form.Form");
dojo.require("dijit.form.Button");
dojo.require("dijit.form.NumberTextBox");

// Get User Interface

sec_im.ui = {
	tp: null,
	key: null,
	
	
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
				label: "Generate Key",
				onClick: function() {
					sec_im.ui.genkey.generateAndShowKey(x.get('value'));
				}
			});
			this.btn.placeAt(this.f.domNode);
			
			return this.f;
		},
		
		generateAndShowKey: function(bits) {
			sec_im.ui.key = new RSAKey();
			sec_im.ui.key.generate(bits, "65537");
			
		}
	},
	
	showkey: {
		ui: function(pubkey, prkey) {
			var key = sec_im.ui.key;
			
			
			this.div = new dijit.form.Form({id:"showkey_form_" + this.form_id++});
			this.pub = new dijit.form.Textarea({
				name: "pubits",
				value: key.pub2PEM()
			}, this.div.domNode);
			
			this.pri = new dijit.form.Textarea({
				name: "prbits",
				value: key.prv2PEM()
			}, this.div.domNode);
			
			return this.div;
		}
	},
	
	onLoad: function() {
		this.tp_gen = new dijit.TitlePane({
			title: "Generate RSA Key",
			content: ""
		});
		dojo.byId("canvas").appendChild(this.tp_gen.domNode);
		
		this.tp_gen.set('content', sec_im.ui.genkey.form_ui());
		
		
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
		
		if(this.tp_show.open)
			this.tp_show.toggle();
		
	}
	
};

dojo.addOnLoad(sec_im.ui.onLoad);

