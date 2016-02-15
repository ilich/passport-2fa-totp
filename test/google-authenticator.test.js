var expect = require('chai').expect,
    base32 = require('thirty-two'),
    GoogleAuthenticator = require('..').GoogeAuthenticator;
    
describe('Google Authenticator utils', function () {
    
    it('register', function () {
        var code = GoogleAuthenticator.register('username');
        
        expect(code).to.be.an('object');
        expect(code.qr).to.be.a('string');
        expect(code.qr).to.have.length.above(0);
        expect(code.secret).to.be.a('string');
        expect(code.secret).to.have.length.above(0);
    });
    
    it('decodeSecret', function () {
        var code = GoogleAuthenticator.register('username');
        var decodedSecret = GoogleAuthenticator.decodeSecret(code.secret);
        var encodedSecret = base32.encode(decodedSecret).toString().replace(/=/g, ''); // Google Authenticator ignores '='
        
        expect(encodedSecret).to.be.equal(code.secret);
    });
    
});