'use strict';

var passport = require('passport-strategy'),
    util = require('util'),
    totp = require('notp').totp,
    lookup = require('./utils').lookup;

function Strategy(options, verifyUsernameAndPassword, verifyTotpCode) {
    if (typeof options === 'function') {
        verifyTotpCode = verifyUsernameAndPassword;
        verifyUsernameAndPassword = options;
        options = {};
    }
    
    if (options) {
        this._skipTotpVerification = options.skipTotpVerification || false;    
    } else {
        this._skipTotpVerification = false;
    }
    
    if (!verifyUsernameAndPassword) {
        throw new TypeError('2FA TOTP Strategy required username and password verification callback');
    }
    
    if (!this._skipTotpVerification && !verifyTotpCode) {
        throw new TypeError('2FA TOTP Strategy required TOTP code verification callback');
    }
    
    this._usernameField = options.usernameField || 'username';
    this._passwordField = options.passwordField || 'password';
    this._codeField = options.codeField || 'code';
    this._window = options.window || 6;

    passport.Strategy.call(this);
    
    this.name = '2fa-totp';
    this._verifyUsernameAndPassword = verifyUsernameAndPassword;
    this._verifyTotpCode = verifyTotpCode;
    this._passReqToCallback = options.passReqToCallback || false;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
    var MISSING_CREDENTIALS = 'Missing credentials';
    var AUTH_FAILED = 'Invalid username or password';
    options = options || {};
    
    var username = lookup(req.body, this._usernameField) || lookup(req.query, this._usernameField);
    var password = lookup(req.body, this._passwordField) || lookup(req.query, this._passwordField);
    var code = lookup(req.body, this._codeField) || lookup(req.query, this._codeField);
    
    if (!username || !password) {
        return this.fail(options.badRequestMessage || MISSING_CREDENTIALS);
    }
    
    var self = this;
    
    var firstStepAuth = new Promise(function (resolve, reject) {
        // 1st step: check username and password
        
        var verify = function (error, user, info) {
            if (error) {
                return reject({
                    error: true,
                    message: error
                });
            }        
            
            if (!user) {
                return reject({
                    error: false,
                    message: info
                });
            }
            
            resolve(user);
        };
        
        try {
            if (self._passReqToCallback) {
                self._verifyUsernameAndPassword(req, username, password, verify);
            } else {
                self._verifyUsernameAndPassword(username, password, verify);
            }
        } catch (err) {
            reject(err);
        }
        
    });
    
    firstStepAuth.then(function (user) {
        // 2nd step: code verification using TOTP
        
        if (self._skipTotpVerification) {
            self.success(user);
        }
        
        var verify = function (error, secret, period) {
            if (error) {
                return self.error(error);
            }
            
            var isValid = totp.verify(code, secret, {
                window: self._window,
                time: period
            });
            
            if (isValid) {
                self.success(user);    
            } else {
                self.fail(options.badRequestMessage || AUTH_FAILED);
            }
            
        };
        
        try {
            if (self._passReqToCallback) {
                self._verifyTotpCode(req, user, verify);
            } else {
                self._verifyTotpCode(user, verify);
            }
        } catch (err) {
            self.error(err);
        }
        
    }).catch(function (reason) {
        // 1st step failed. Return an error message to the user.
        if (reason.error) {
            self.error(reason.message || AUTH_FAILED);
        } else {
            self.fail(reason.message || AUTH_FAILED);
        }
    });
};

module.exports = Strategy;