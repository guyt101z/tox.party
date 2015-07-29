// DNS stuff
var named = require("node-named");
var dnsServer = named.createServer();

// Frontend stuff
var bodyParser = require("body-parser");
var express = require("express");
var webapp = express();
var server = webapp.listen(3000, console.log("Webapp running..."));

webapp.use(bodyParser.json());
webapp.use(bodyParser.urlencoded({ extended: true }));
webapp.use(express.static("www"));

// Other stuff
var toxRecords = {};

// Handle postdata for registration
webapp.post("/", function(req, res) {
	console.dir(req.body);

	// check if all params specified and shorten var names
	if (!req.body.uname || !req.body.addr || !req.body.pass) return res.redirect("/errors/specifyparams.html");
	uname = req.body.uname;
	addr = req.body.addr;
	pass = req.body.pass;

	// Check that params are valid
	if (uname.length >= 20 || addr.length != 76 || uname.match(/[^A-Za-z0-9_\.]/) || addr.match(/\W/)) return res.redirect("/errors/invalid.html");

	// check to see if registered and if so, check pass
	if (toxRecords[uname] != undefined && pass != toxRecords[uname].pass) return res.redirect("/errors/incorrect.html");

	toxRecords[uname] = {
		addr: addr,
		pass: pass
	};

	res.redirect("/success.html");
});

// DNS listener
dnsServer.listen(9999, "127.0.0.1", console.log("Listening..."));
dnsServer.on("query", function(query) {
	var name = query.name();
	var type = query.type();

	if (type == "TXT" && toxRecords[name]) {
		var record = new named.TXTRecord("v=tox1;id=" + toxRecords[name].addr);
		query.addAnswer(name, record, 60);
		dnsServer.send(query);
	}
});