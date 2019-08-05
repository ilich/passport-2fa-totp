'use strict';

var crypto = require('crypto'),
    util = require('util'),
    base32 = require('thirty-two'),
    qr = require('qr-image');
    
module.exports = {
    register: function (username, issuer) {
        if (!username) {
            throw new TypeError("Username is required");
        }
        
        var secret = base32.encode(crypto.randomBytes(32));
        secret = secret.toString().replace(/=/g, ''); // Google Authenticator ignores '='
        
        var authUrl = util.format('otpauth://totp/%s?secret=%s&issuer=%s', username, secret, issuer);
        var qrCode = qr.imageSync(authUrl, { type: 'svg' });
        
        return {
            secret: secret,
            qr: qrCode
        };
    },
    
    decodeSecret: function (secret) {
        return base32.decode(secret);
    } 
};
