'use strict';

var Strategy = require('./strategy'),
    GoogleAuthenticator = require('./google-authenticator');

exports = module.exports = Strategy;
exports.Strategy = Strategy;
exports.GoogleAuthenticator = GoogleAuthenticator;
