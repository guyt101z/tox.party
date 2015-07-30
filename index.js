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

	var tag = config.tags[Math.floor(Math.random() * config.tags.length)];
	data.name = config.name;
	data.tag = tag;

	return swig.renderFile("./views/" + file + ".html", data);
}

// Serve static content and homepage
webapp.use("/static", express.static("static"));
webapp.get("/", function(req, res) {

	// Send page
	res.send(generatePage("index"));
});

// Handle postdata for registration
webapp.post("/", function(req, res) {
	console.dir(req.body);

	// Pick a random tag
	var tag = config.tags[Math.floor(Math.random() * config.tags.length)];

	// check if all params specified
	if (!req.body.uname || !req.body.addr || !req.body.pass) {
		console.log("Missing parameters!");
		return res.send(generatePage("error", { error: "Missing parameters!" }));
	}

	// shorten var names
	var uname = req.body.uname.toLowerCase(),
		addr = req.body.addr,
		pass = req.body.pass;

	// Check that params are valid
	if (uname.length >= 20 || addr.length != 76 || uname.match(/[^A-Za-z0-9_\.]/) || addr.match(/\W/)) {
		console.log("Invalid username or address!");
		console.log("...Username is: " + uname);
		console.log("...Address is: " + addr);
		return res.send(generatePage("error", { error: "Invalid username or address!" }));
	}

	// check to see if registered and if so, check password
	if (toxRecords[uname] != undefined && pass != toxRecords[uname].pass) {
		console.log("Incorrect password, tried \"" + pass + "\", correct is \"" + toxRecords[uname].pass + "\"");
		return res.send(generatePage("error", { error: "Incorrect password!" }));
	};

	// All good, set user and send user to success page
	toxRecords[uname] = {
		addr: addr,
		pass: pass
	};

	fs.writeFileSync("./toxRecords.json", JSON.stringify(toxRecords));
	console.log(uname + " has registered or modified ID correctly!");
	res.send(generatePage("success", { fullId: uname + "@" + config.domain }));
});

// DNS listener
dnsServer.listen(53, "", console.log("Listening..."));
dnsServer.on("query", function(query) {
	var name = query.name();
	var type = query.type();
	var username = name.toLowerCase().split("._tox")[0];

	console.log("Request for: " + username);

	if (type == "TXT" && toxRecords[username]) {
		console.log("...Resolved to: " + toxRecords[username].addr);

		var record = new named.TXTRecord("v=tox1;id=" + toxRecords[username].addr);
		query.addAnswer(name, record, 60);
		dnsServer.send(query);
	} else {
		console.log("...Not found :(");
	}
});