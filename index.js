// DNS stuff
var named = require("node-named");
var dnsServer = named.createServer();

// Webapp stuff
var bodyParser = require("body-parser");
var express = require("express");
var webapp = express();

webapp.listen(3000, console.log("Webapp running..."));
webapp.use(bodyParser.json());
webapp.use(bodyParser.urlencoded({extended: true}));
webapp.use(express.static("www"));

// Other stuff
var fs = require("fs");

// Startup
fs.readFile("./toxRecords.json", function(err, data) {
	if (!err) {
		toxRecords = JSON.parse(data.toString());
	} else {
		toxRecords = {};
	}
});

// Handle postdata for registration
webapp.post("/", function(req, res) {
	console.dir(req.body);

	// check if all params specified
	if (!req.body.uname || !req.body.addr || !req.body.pass) {
		console.log("Missing parameters!");
		return res.redirect("/errors/specifyparams.html");
	}

	// shorten var names
	uname = req.body.uname;
	addr = req.body.addr;
	pass = req.body.pass;

	// Check that params are valid
	if (uname.length >= 20 || addr.length != 76 || uname.match(/[^A-Za-z0-9_\.]/) || addr.match(/\W/)) {
		console.log("Invalid username or password!");
		console.log("...Username is: " + uname);
		console.log("...Address is: " + addr);
		return res.redirect("/errors/invalid.html");
	}

	// check to see if registered and if so, check password
	if (toxRecords[uname] != undefined && pass != toxRecords[uname].pass) {
		console.log("Incorrect password, tried \"" + pass + "\", correct is \"" + toxRecords[uname].pass + "\"");
		return res.redirect("/errors/incorrect.html");
	};

	// All good, set user and send user to success page
	toxRecords[uname] = {
		addr: addr,
		pass: pass
	};

	fs.writeFileSync("./toxRecords.json", JSON.stringify(toxRecords));
	console.log(uname + "has registered or modified ID correctly!");
	res.redirect("/success.html");
});

// DNS listener
dnsServer.listen(53, "", console.log("Listening..."));
dnsServer.on("query", function(query) {
	var name = query.name();
	var type = query.type();
	var username = name.split("._tox")[0];

	console.log("Request for: " + username);

	if (type == "TXT" && toxRecords[username]) {
		var record = new named.TXTRecord("v=tox1;id=" + toxRecords[username].addr);
		query.addAnswer(name, record, 60);
		console.log("...Resolved to: " + toxRecords[username].addr);
	} else {
		console.log("...Not found :(");
	}

	dnsServer.send(query);
});