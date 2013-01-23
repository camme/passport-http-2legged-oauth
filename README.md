# Oauth 2-legged strategy for passport

This oauth strategy is used for a 2-legged scenario (even called 0-legged).
Its a consumer to server authentication where each request is signed as defined in oauth but an empty access_token is used. No user data is exposed, as it is the consumer that has access to the protected resource.

It works as https://github.com/jaredhanson/passport-http-oauth but skips the access_token verification step and accepts empty access_tokens.

The cose base is 98% https://github.com/jaredhanson/passport-http-oauth but adapted for the 2-legged scenario. So thanks jaredhanson for all work!.

