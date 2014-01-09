// Get the oath client (npm install oauth)
var oauth = require("oauth");

// The app key and secret
var key = "111111";
var secret = "xxx";

// Create the oauth client. Set null for the first two arguments since we dont have endpoints
// for getting tokens etc (for 3-legged)
var request = new oauth.OAuth(null, null, key, secret, '1.0', null, 'HMAC-SHA1');

// Connect to the secure endpoint
request.get("http://localhost:1337/private", null, null, function(err, data, res) {
    if (err) {
        console.error("Err", err);
    } else {
        console.log("Success", data);
    }
});
