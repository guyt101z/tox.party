// DNS stuff
var named = require("node-named"),
	dnsServer = named.createServer();

// Webapp stuff
var express = require("express"),
	bodyParser = require("body-parser"),
	swig = require("swig"),
	webapp = express();

webapp.listen(3000, console.log("Webapp running..."));

webapp.use(bodyParser.json());
webapp.use(bodyParser.urlencoded({extended: true}));

// Other stuff
var fs = require("fs"),
	passwordHash = require("password-hash"),
	config = require("./config.js");

// Startup
fs.readFile("./toxRecords.json", function(err, data) {
	if (!err) {
		toxRecords = JSON.parse(data.toString());
	} else {
		toxRecords = {};
	}
});

// Make serving content less ugly
function generatePage(file, data) {
	if (!data) data = {};

	// Set some generally required data
	data.domain = config.domain;
	data.name = config.name;
	data.tag = config.tags[Math.floor(Math.random() * config.tags.length)];

	// Return the generated page
	return swig.renderFile("./views/" + file + ".html", data);
}

// Static content (css, js, etc)
webapp.use("/static", express.static("static"));

// Homepage
webapp.get("/", function(req, res) {
	res.send(generatePage("index"));
});

// Handle postdata for registration
webapp.post("/", function(req, res) {
	console.log("Recieved postdata");

	// check if all params specified
	if (!req.body.uname || !req.body.addr || !req.body.pass) {
		console.log("Missing parameters!");
		return res.send(generatePage("error", { error: "Missing parameters!" }));
	}

	// shorten var names
	var uname = req.body.uname.toLowerCase(),
		addr = req.body.addr,
		pass = req.body.pass;

	// Log some details for debugging
	console.log("...Username is: " + uname);
	console.log("...Address is: " + addr);
	console.log("...IP is: " + req.ip);

	// Check that params are valid
	if (uname.length >= 20 || addr.length != 76 || uname.match(/[^A-Za-z0-9_\.]/) || addr.match(/\W/)) {
		console.log("Invalid username or address!");
		return res.send(generatePage("error", { error: "Invalid username or address!" }));
	}

	// Check to see if registered, and if so, check password
	if (toxRecords[uname] != undefined && passwordHash.verify(pass, toxRecords[uname].pass) == false) {
		console.log("...Input bassword hash: " + passwordHash.generate(pass));
		console.log("...Saved bassword hash: " + toxRecords[uname].pass);
		return res.send(generatePage("error", { error: "Incorrect password!" }));
	};

	// All good, save user and send user to success page
	toxRecords[uname] = {
		addr: addr,
		pass: passwordHash.generate(pass)
	};

	fs.writeFileSync("./toxRecords.json", JSON.stringify(toxRecords));
	console.log(uname + " has registered or modified ID correctly!");
	res.send(generatePage("success", { fullId: uname + "@" + config.domain }));
});

// DNS listener
dnsServer.listen(53, "", console.log("DNS Server listening..."));
dnsServer.on("query", function(query) {
	// Define some vars
	var name = query.name(),
		type = query.type(),
		username = name.toLowerCase().split("._tox")[0];

	// Log request
	console.log(type + " request for: " + name);

	// Not a TXT lookup, not a ToxDNS lookup. Return. (change this when tox3 I think?)
	if (type != "TXT") return;

	// If user found in records log end send response, else just log
	if (toxRecords[username]) {
		console.log("...Resolved to: " + toxRecords[username].addr);

		var record = new named.TXTRecord("v=tox1;id=" + toxRecords[username].addr);

		query.addAnswer(name, record, 60);
		dnsServer.send(query);
	} else {
		console.log("..." + username + " not found :(");
	}
});