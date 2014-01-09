var express = require('express');
var app = express();
var passport = require('passport');
var twoLeggedStrategy = require('passport-http-2legged-oauth').Strategy;

// This is standard passport
app.use(passport.initialize());

// And here we start the http server
app.listen(1337);

// We add a route that is open
app.get("/", function(req, res) {
    res.setHeader("content-type", "text/html");
    res.send("Hi. Try <a href='/private'>/private</a> for a private endpoint.");
});

// And we add a secure route. Add the security and that we arent using any sessions (no point in 2-legged)
app.get("/private", [passport.authenticate('oauth', {session: false}), function(req, res) {
    res.send({secret: true});
}]);

// Register our two legged strategy with passport with the two callbacks needed.
// One for checking if we can find the correct user/app by key
// The other to check if the timestamp is ok, ie the request isnt too old
passport.use(new twoLeggedStrategy(checkAppKey, checkTimestampAndNonce));

// Here is our applist. This will normally reside in your database or something alike
var appList = {
    "111111": {
        secret: "xxx"
    }
};

// A function to find the app by key. If we find it, we return the secret used to 
// check if the request is valid
function findApp(key, next) {
    var consumer = appList[key];
    if (consumer) {
        next(null, {secret: consumer.secret});
    } else {
        next(true);
    }
}

// Check if the key is valid and get the secret
function checkAppKey(consumerKey, done) {
    findApp(consumerKey, function(err, consumer) {
        if (err) { return done(err); }
        if (!consumer) { return done(null, false); }

        console.log("Found an app with the suplied key '%s'", consumerKey);

        return done(null, consumer, consumer.secret);
    });
}

// Check if the timestamp is ok (and nonce, but we dont check nonce in this example)
function checkTimestampAndNonce(timestamp, nonce, app, req, done) {

    var timeDelta = Math.round((new Date()).getTime() / 1000) - timestamp;

    // Here we check if the request is too old.. If its too old, return false
    if (timeDelta >= 10) {
        done(null, false);
    }
    else {
        done(null, true);
    }

}



