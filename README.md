# Oauth 2-legged strategy for passport

This oauth strategy is used for a 2-legged scenario (even called 0-legged).
Its a consumer to server authentication where each request is signed as defined in oauth but an empty access_token is used. No user data is exposed, as it is the consumer that has access to the protected resource.

It works as https://github.com/jaredhanson/passport-http-oauth but skips the access_token verification step and accepts empty access_tokens.

The cose base is 98% https://github.com/jaredhanson/passport-http-oauth but adapted for the 2-legged scenario. So thanks jaredhanson for all work!.

To see how it works, you can run the example. Its quite easy to set up:

## Create a server with a secure endpoint

First install all needed dependecies for this example:

    npm install express passport passport-http-2legged-oauth

Now create a file called server.js with the following:

```
var express = require('express');
var app = express();
var passport = require('passport');
var twoLeggedStrategy = require('passport-http-2legged-oauth').Strategy;
```
Initialize passport and start the http server

```
// This is standard passport
app.use(passport.initialize());

// And here we start the http server
app.listen(1337);
```

Now we add a public route and a private route

```
// We add a route that is open
app.get("/", function(req, res) {
    res.setHeader("content-type", "text/html");
    res.send("Hi. Try <a href='/private'>/private</a> for a private endpoint.");
});

// And we add a secure route. Add the security and that we arent using any sessions (no point in 2-legged)
app.get("/private", [passport.authenticate('oauth', {session: false}), function(req, res) {
    res.send({secret: true});
}]);
```

Define a list of apps with keys and secrets. This would normaly be saved in a database, but for the sake of simplicity, we just have an object in this example

```
var appList = {
    "111111": {
        secret: "xxx"
    }
};
```
Register our two legged strategy with passport with the two callbacks needed.
One for checking if we can find the correct user/app by key
The other to check if the timestamp is ok, ie the request isnt too old

```
passport.use(new twoLeggedStrategy(checkAppKey, checkTimestampAndNonce));

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

```

## Create a simple client

Install oauth first

    npm install oauth
    
Then create a file called client.js

Get the required module for oauth

```
var oauth = require("oauth");
```

Define the key and secret for your app

```
var key = "111111";
var secret = "xxx";
```

Create the oauth client. Set null for the first two arguments since we dont have endpoints for getting tokens etc (for 3-legged)

```
var request = new oauth.OAuth(null, null, key, secret, '1.0', null, 'HMAC-SHA1');
```

And now do the actuall request to the private endpoint

```
request.get("http://localhost:1337/private", null, null, function(err, data, res) {
    if (err) {
        console.error("Err", err);
    } else {
        console.log("Success", data);
    }
});
```

If everything goes well, you should get a success message!

