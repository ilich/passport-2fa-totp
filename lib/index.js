'use strict';

var Strategy = require('./strategy'),
    GoogeAuthenticator = require('./google-authenticator');

exports = module.exports = Strategy;
exports.Strategy = Strategy;
exports.GoogeAuthenticator = GoogeAuthenticator;