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

webapp.set("view engine", "html");
webapp.engine("html", function(file, data, callback) {
	if (!data) data = {};

	data.domain = config.domain;
	data.name = config.name;
	data.tag = config.tags[Math.floor(Math.random() * config.tags.length)];
	data.footerLinks = config.footerLinks;;

	return callback(null, swig.renderFile(file, data));
});

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

// Static content (css, js, etc)
webapp.use("/static", express.static("static"));

// Pages
webapp.get("/", function(req, res) {
	res.render("index");
});
webapp.get("/about", function(req, res) {
	res.render("about");
});

// Handle postdata for registration
webapp.post("/", function(req, res) {
	console.log("Recieved postdata!");

	// check if all params specified
	if (!req.body.uname || !req.body.addr || !req.body.pass) {
		console.log("Missing parameters!");
		return res.render("error", {
			error: "Missing parameters!"
		});
	}

	// shorten var names
	var uname = req.body.uname.toLowerCase(),
		action = req.body.action,
		addr = req.body.addr,
		pass = req.body.pass;

	// Log some details for debugging
	console.log("...Username is: " + uname);
	console.log("...Action is: " + action);
	console.log("...Address is: " + addr);
	console.log("...IP is: " + req.ip);

	// Check that params are valid
	if (uname.length >= 20 || addr.length != 76 || uname.match(/[^A-Za-z0-9_\.]/) || addr.match(/\W/)) {
		console.log("Invalid username or address!");
		return res.render("error", {
			error: "Invalid username or address!"
		});
	}

	switch (action) {
	case "reg":
		if (toxRecords[uname] != undefined) {
			return res.render("error", {
				error: "Account with that username already exists."
			});
		}

		toxRecords[uname] = {
			addr: addr,
			pass: passwordHash.generate(pass)
		};

		res.render("success", {
			type: action,
			ID: uname + "@" + config.domain
		});
		console.log(uname + " has registered account successfully!");
		break;
	case "regTemp":
		if (toxRecords[uname] != undefined) {
			return res.render("error", {
				error: "Account with that username already exists."
			});
		}

		toxRecords[uname] = {
			addr: addr,
			pass: null
		};

		setTimeout(function() {
			delete toxRecords[uname];
			console.log("Deleting temporary user " + uname);
		}, 86400000, uname);

		res.render("success", {
			type: action,
			ID: uname + "@" + config.domain
		});
		console.log(uname + " has registered temporary account successfully!");
		break;
	case "edit":
		if (toxRecords[uname] == undefined) {
			return res.render("error", {
				error: "Account with that username not found."
			});
		}

		if (passwordHash.verify(pass, toxRecords[uname].pass) == false) {
			return res.render("error", {
				error: "Incorrect password!"
			});
		}

		toxRecords[uname] = {
			addr: addr,
			pass: passwordHash.generate(pass)
		};

		res.render("success", {
			type: action,
			ID: uname + "@" + config.domain,
			addr: addr
		});
		console.log(uname + " has edited account successfully!");
		break;
	case "del":
		if (toxRecords[uname] == undefined) {
			return res.render("error", {
				error: "Account with that username not found."
			});
		}

		if (passwordHash.verify(pass, toxRecords[uname].pass) == false) {
			return res.render("error", {
				error: "Incorrect password!"
			});
		}

		delete toxRecords[uname];

		console.log(uname + " has deleted account successfully!");
		res.render("success", {
			type: action,
			ID: uname + "@" + config.domain
		});
		break;
	}

	fs.writeFileSync("./toxRecords.json", JSON.stringify(toxRecords));
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