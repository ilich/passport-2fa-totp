'use strict';

var expect = require('chai').expect,
    strategy = require('..');

describe('2fa-totp strategy constructor', function () {
    
    it('should export Strategy constructor directly from package', function () {
        expect(strategy).to.be.a('function');
        expect(strategy).to.be.equal(strategy.Strategy);
    });
    
    it('check strategy name and default parameters', function () {
        var passport2faTotp = new strategy.Strategy(function () {}, function () {});
        
        expect(passport2faTotp).to.be.an('object');
        expect(passport2faTotp.name).to.be.equal('2fa-totp');
        expect(passport2faTotp._usernameField).to.be.equal('username');
        expect(passport2faTotp._passwordField).to.be.equal('password');
        expect(passport2faTotp._codeField).to.be.equal('code');
        expect(passport2faTotp._window).to.be.equal(6);
        expect(passport2faTotp._skipTotpVerification).to.be.equal(false);
        expect(passport2faTotp._passReqToCallback).to.be.equal(false);
        expect(passport2faTotp._verifyUsernameAndPassword).to.be.an('function');
        expect(passport2faTotp._verifyTotpCode).to.be.an('function');
    });
    
    it('pass parameters to the strategy', function () {
        var step1 = function () {};
        var step2 = function () {};
        var passport2faTotp = new strategy.Strategy({
            usernameField: "user",
            passwordField: "pwd",
            codeField: "key",
            window: 20,
            skipTotpVerification: false,
            passReqToCallback: true
        }, step1, step2);
        
        expect(passport2faTotp).to.be.an('object');
        expect(passport2faTotp.name).to.be.equal('2fa-totp');
        expect(passport2faTotp._usernameField).to.be.equal('user');
        expect(passport2faTotp._passwordField).to.be.equal('pwd');
        expect(passport2faTotp._codeField).to.be.equal('key');
        expect(passport2faTotp._window).to.be.equal(20);
        expect(passport2faTotp._skipTotpVerification).to.be.equal(false);
        expect(passport2faTotp._passReqToCallback).to.be.equal(true);
        expect(passport2faTotp._verifyUsernameAndPassword).to.be.equal(step1);
        expect(passport2faTotp._verifyTotpCode).to.be.equal(step2);
    });
    
    it('username and password verification callback is required', function () {
        var initStrategy = function () {
            new strategy.Strategy();
        };
        
        expect(initStrategy).to.throw(TypeError, '2FA TOTP Strategy required username and password verification callback');
    });
    
    it('TOTP code verification callback is required', function () {
        var initStrategy = function () {
            new strategy.Strategy(function () {});
        };
        
        expect(initStrategy).to.throw(TypeError, '2FA TOTP Strategy required TOTP code verification callback');
    });
    
    it('TOTP code verification callback can be ignored', function () {
        new strategy.Strategy({
            skipTotpVerification: true    
        }, function () {});
    });
    
});