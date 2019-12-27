import { Strategy as BaseStrategy } from 'passport-strategy';
import { Request, Handler } from 'express';
import passport from 'passport';

interface I2FAOptions {
	usernameField?: string;
	passwordField?: string;
	codeField?: string;
	window?: number;
	skipTotpVerification?: boolean;
}
interface I2FAOptionsWithRequest extends I2FAOptions {
	passReqToCallback: true;
}
type VerifyUsernameFn = ((err: Error) => void) & ((err: null, user: any, info?: any) => void);
type VerifyTotpFn = ((err: Error) => void) & ((err: null, secret: Buffer, period: number) => void);
export class Strategy extends BaseStrategy {
	constructor(options: I2FAOptionsWithRequest,
		verifyUsernameAndPassword: (this: Strategy, req: Request, username: string, password: string, verify: VerifyUsernameFn) => void,
		verifyTotpCode: (this: Strategy, req: Request, user: any, verify: VerifyTotpFn) => void);
	constructor(options: I2FAOptions,
		verifyUsernameAndPassword: (this: Strategy, username: string, password: string, verify: VerifyUsernameFn) => void,
		verifyTotpCode: (this: Strategy, user: any, verify: VerifyTotpFn) => void
	);
	authenticate(req: Request, options?: any): any;
}

export class GoogleAuthenticator {
	static register(username: string): any;
	static decodeSecret(secret: string): Buffer;
}

export interface AuthenticateOptionsTOTP extends passport.AuthenticateOptions {
    accessType?: 'offline' | 'online';
    prompt?: string;
    loginHint?: string;
    includeGrantedScopes?: boolean;
    display?: string;
    hostedDomain?: string;
    hd?: string;
    requestVisibleActions?: any;
    openIDRealm?: any;
}
