/**
 * Module dependencies.
 */
var passport = require('passport')
, uri = require('url')
, util = require('util')
, utils = require('./utils')
, querystring = require('querystring');

/** 2 Legged Token strategy
 *
 * The code is a copy of https://github.com/jaredhanson/passport-http-oauth and modified to 
 * use a 2legged scenario. It omits the requirement for an none-empty access_token
 *
 * This ouath strategy is used for a 2-legged scenario (even called 0-legged)
 * Its a consumer to server authentication where each request is signed as defined in oauth
 * but an empty access_token is used.
 * No user data is exposed, as it is the consumer that has access to the protected resource.
 *
 * This strategy requires two functions as callbacks, referred to as
 * `consumer` and `validate`.
 *
 * The `consumer` callback accepts `consumerKey` and must call `done` supplying
 * a `consumer` and `consumerSecret`.  The strategy will use the secret to
 * compute the signature, failing authentication if it does not match the
 * request's signature.  If an exception occured, `err` should be set.
 *
 * The `validate` callback is optional, accepting `timestamp` and `nonce` as a
 * means to protect against replay attacks.
 *
 * This strategy is inteded to be employed in routes for protected resources.
 *
 * Examples:
 *
 *     passport.use('token', new TwoLeggedStrategy(
 *       function(consumerKey, done) {
 *         Consumer.findByKey({ key: consumerKey }, function (err, consumer) {
 *           if (err) { return done(err); }
 *           if (!consumer) { return done(null, false); }
 *           return done(null, consumer, consumer.secret);
 *         });
 *       },
 *       function(timestamp, nonce, done) {
 *         // validate the timestamp and nonce as necessary
 *         done(null, true)
 *       }
 *     ));
 *
 * References:
 *  - [Authenticated Requests](http://tools.ietf.org/html/rfc5849#section-3)
 *  - [Accessing Protected Resources](http://oauth.net/core/1.0a/#anchor12)
 *  - [Accessing Protected Resources](http://oauth.net/core/1.0/#anchor13)
 *
 * @param {Object} options
 * @param {Function} consumer
 * @param {Function} verify
 * @api public
 */
function TwoLeggedStrategy(options, consumer, validate) {
    if (typeof options == 'function') {
        validate = consumer;
        //verify = consumer;
        consumer = options;
        options = {};
    }
    if (!consumer) throw new Error('HTTP OAuth token authentication strategy requires a consumer function');
    if (!validate) throw new Error('HTTP OAuth token authentication strategy requires a validate function');

    passport.Strategy.call(this);
    this.name = 'oauth';
    this._consumer = consumer;
    //this._verify = verify;
    this._validate = validate;
    this._host = options.host || null;
    this._realm = options.realm || 'Users';
    this._ignoreVersion = options.ignoreVersion || false;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(TwoLeggedStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP OAuth authorization
 * header, body parameters, or query parameters.
 *
 * @param {Object} req
 * @api protected
 */
TwoLeggedStrategy.prototype.authenticate = function(req) {
    var params = undefined
    , header = null;

    if (req.headers && req.headers['authorization']) {
        var parts = req.headers['authorization'].split(' ');
        if (parts.length >= 2) {
            var scheme = parts[0];
            var credentials = null;

            parts.shift();
            credentials = parts.join(' ');

            if (/OAuth/i.test(scheme)) {
                params = utils.parseHeader(credentials);
                header = params;
            }
        } else {
            return this.fail(400);
        }
    }

    if (req.body && req.body['oauth_signature']) {
        if (params) { return this.fail(400); }
        params = req.body;
    }

    if (req.query && req.query['oauth_signature']) {
        if (params) { return this.fail(400); }
        token = req.query['access_token'];
        params = req.query;
    }

    if (!params) { return this.fail(this._challenge()); }

    if (!params['oauth_consumer_key'] ||
        // Check if it doesnt exists at all
        !(params['oauth_token'] == null) ||
        !params['oauth_signature_method'] ||
        !params['oauth_signature'] ||
        !params['oauth_timestamp'] ||
        !params['oauth_nonce']) {
        return this.fail(this._challenge('parameter_absent'), 400);
    }

    var consumerKey = params['oauth_consumer_key']
    , accessToken = params['oauth_token']
    , signatureMethod = params['oauth_signature_method']
    , signature = params['oauth_signature']
    , timestamp = params['oauth_timestamp']
    , nonce = params['oauth_nonce']
    , version = params['oauth_version']

    if (version && version !== '1.0' && !this._ignoreVersion) {
        return this.fail(this._challenge('version_rejected'), 400);
    }

    var self = this;
    this._consumer(consumerKey, function(err, consumer, consumerSecret) {
        if (err) { return self.error(err); }
        if (!consumer) { return self.fail(self._challenge('consumer_key_rejected')); }

        var tokenSecret = '';
        if (err) { return self.error(err); }

        var info = {};
        info.scheme = 'OAuth';
        info.client =
            info.consumer = consumer;

        var url = utils.originalURL(req, self._host)
        , query = req.query
        , body = req.body;

        var sources = [ header, query ];
        if (req.headers['content-type'] &&
            req.headers['content-type'].slice(0, 'application/x-www-form-urlencoded'.length) === 'application/x-www-form-urlencoded') {
            sources.push(querystring.parse(body));
        }

        var normalizedURL = utils.normalizeURI(url)
        , normalizedParams = utils.normalizeParams.apply(undefined, sources)
        , base = utils.constructBaseString(req.method, normalizedURL, normalizedParams);

        if (signatureMethod == 'HMAC-SHA1') {
            var key = consumerSecret + '&';
            if (tokenSecret) { key += tokenSecret; }
            var computedSignature = utils.hmacsha1(key, base);

            if (signature !== computedSignature) {
                return self.fail(self._challenge('signature_invalid'));
            }
        } else if (signatureMethod == 'PLAINTEXT') {
            var computedSignature = utils.plaintext(consumerSecret, tokenSecret);

            if (signature !== computedSignature) {
                return self.fail(self._challenge('signature_invalid'));
            }
        } else{
            return self.fail(self._challenge('signature_method_rejected'), 400);
        }

        // If execution reaches this point, the request signature has been
        // verified and authentication is successful.
        if (self._validate) {
            // Give the application a chance it validate the timestamp and nonce, if
            // it so desires.
            self._validate(timestamp, nonce, function(err, valid) {
                if (err) { return self.error(err); }
                if (!valid) { return self.fail(self._challenge('nonce_used')); }
                return self.success(consumer, info);
            });
        } else {
            return self.success(consumer, info);
        }

    });
}

/**
 * Authentication challenge.
 *
 * References:
 *  - [Problem Reporting](http://wiki.oauth.net/w/page/12238543/ProblemReporting)
 *
 * @api private
 */
TwoLeggedStrategy.prototype._challenge = function(problem, advice) {
    var challenge = 'OAuth realm="' + this._realm + '"';
    if (problem) {
        challenge += ', oauth_problem="' + utils.encode(problem) + '"';
    }
    if (advice && advice.length) {
        challenge += ', oauth_problem_advice="' + utils.encode(advice) + '"';
    }

    return challenge;
}


/**
 * Expose `TwoLeggedStrategy`.
 */
module.exports = TwoLeggedStrategy;
