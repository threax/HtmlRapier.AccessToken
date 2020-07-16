///<amd-module name="hr.accesstoken.manager"/>

import { Fetcher } from 'hr.fetcher';
import * as winfetch from 'hr.windowfetch';
import * as events from 'hr.eventdispatcher';
import * as ep from 'hr.externalpromise';
import * as storage from 'hr.storage';
import * as controller from 'hr.controller';

//From https://github.com/auth0/jwt-decode/blob/master/lib/base64_url_decode.js
function b64DecodeUnicode(str: string) {
    return decodeURIComponent(atob(str).replace(/(.)/g, function (m, p) {
        let code = p.charCodeAt(0).toString(16).toUpperCase();
        if (code.length < 2) {
            code = '0' + code;
        }
        return '%' + code;
    }));
}

function base64UrlDecode(str: string) {
    let output = str.replace(/-/g, "+").replace(/_/g, "/");
    switch (output.length % 4) {
        case 0:
            break;
        case 2:
            output += "==";
            break;
        case 3:
            output += "=";
            break;
        default:
            throw "Illegal base64url string!";
    }

    try {
        return b64DecodeUnicode(output);
    } catch (err) {
        return atob(output);
    }
};

//From https://github.com/auth0/jwt-decode/blob/master/lib/index.js
function parseJwt(token: string, options?: any) {
    if (typeof token !== 'string') {
        throw new Error('Invalid token specified');
    }

    options = options || {};
    const pos = options.header === true ? 0 : 1;
    return JSON.parse(base64UrlDecode(token.split('.')[pos]));
};

export class TokenManager {
    private currentToken: string;
    private startTime: number;
    private currentSub: string;
    private expirationTick: number;
    private needLoginEvent: events.PromiseEventDispatcher<boolean, TokenManager> = new events.PromiseEventDispatcher<boolean, TokenManager>();
    private queuePromise: ep.ExternalPromise<string> = null;
    private _alwaysRequestLogin: boolean = false;
    private _allowServerTokenRefresh: boolean = true;
    private fetcher: Fetcher;

    constructor(private tokenPath: string, private _bearerCookieName: string) {
        this.fetcher = new winfetch.WindowFetch();
    }

    public getToken(): Promise<string> {
        //First check if we should queue the request
        if (this.queuePromise !== null) {
            return this.queuePromise.Promise;
        }

        //Do we need to refresh?
        if (this.needsRefresh()) {
            //If we need to refresh, create the queue and fire the refresh
            this.queuePromise = new ep.ExternalPromise<string>();
            this.doRefreshToken(); //Do NOT await this, we want execution to continue.
            return this.queuePromise.Promise; //Here we return the queued promise that will resolve when doRefreshToken is done.
        }

        //Didn't need refresh, return current token.
        return Promise.resolve(this.currentToken);
    }

    private needsRefresh(): boolean {
        return this.startTime === undefined || Date.now() / 1000 - this.startTime > this.expirationTick;
    }

    private async doRefreshToken(): Promise<void> {
        try {
            await this.readToken();
            this.resolveQueue();
        }
        catch (err) {
            this.rejectQueue(err);
        }
    }

    private async readToken(): Promise<void> {
        if (!this.currentToken) {
            //Read the cookie
            this.readCookieAccessToken();
        }

        //Make sure we managed to get a token, not getting one is valid
        if (this.currentToken) {
            this.processCurrentToken();
        }

        //Double check expiration times and refresh if needed
        const allowTokenRefresh = this.currentToken || this.alwaysRequestLogin; //If we have a token or login is forced a token lookup is allowed
        if (allowTokenRefresh && this.needsRefresh()) { //If token lookup is allowed and a refresh is needed
            if (!await this.readServerAccessToken()) {
                if (!await this.fireNeedLogin()) {
                    this.startTime = undefined;
                    throw new Error("Could not refresh access token or log back in.");
                }
            }
        }

        //The way this is structured no matter what happens on the server we read the current cookie state
        //Its possible no refresh was performed if the user turned that off, but if we had a cookie with a
        //token, go ahead and return that.
        this.readCookieAccessToken();
        if (this.currentToken) {
            this.processCurrentToken();
        }
    }

    private processCurrentToken() {
        const tokenObj = parseJwt(this.currentToken);

        if (this.currentSub !== undefined) {
            if (this.currentSub !== tokenObj.sub) { //Do not combine ifs
                //Subjects do not match, clear tokens
                this.clearToken();
                throw new Error("Sub did not match on new token, likely a different user. Aborting refresh.");
            }
        }
        else {
            this.currentSub = tokenObj.sub;
        }

        this.startTime = tokenObj.nbf;
        this.expirationTick = (tokenObj.exp - this.startTime) / 2; //After half the token time has expired we will turn it in for another one.
    }

    private readCookieAccessToken() {
        this.currentToken = storage.CookieStorageDriver.readRaw(this._bearerCookieName);
        if (this.currentToken === null) {
            this.currentToken = undefined; //Keeps with undefined everywhere else.
        }
    }


    ///Read an access token from the server. If the refresh is successful true will be returned. If something goes wrong false will be returned.
    private async readServerAccessToken(): Promise<boolean> {
        if (this._allowServerTokenRefresh) {
            const request: RequestInit = {
                method: "POST",
                cache: "no-cache",
                headers: {
                    "Content-Type": "application/json; charset=UTF-8"
                },
                credentials: "include"
            };
            const response = await this.fetcher.fetch(this.tokenPath, request);
            return response.ok;
        }
        return true; //Not doing anything means everything is ok.
    }

    private clearToken(): void {
        this.currentToken = undefined;
        this.startTime = undefined;
        this.currentSub = undefined;
    }

    /**
     * Get an event listener for the given status code. Since this fires as part of the
     * fetch request the events can return promises to delay sending the event again
     * until the promise resolves.
     * @param status The status code for the event.
     */
    public get onNeedLogin(): events.EventModifier<events.FuncEventListener<Promise<boolean>, TokenManager>> {
        return this.needLoginEvent.modifier;
    }

    public get alwaysRequestLogin(): boolean {
        return this._alwaysRequestLogin;
    }

    public set alwaysRequestLogin(value: boolean) {
        this._alwaysRequestLogin = value;
    }

    public get bearerCookieName(): string {
        return this._bearerCookieName;
    }

    public set bearerCookieName(value: string) {
        this._bearerCookieName = value;
    }

    public get allowServerTokenRefresh(): boolean {
        return this._allowServerTokenRefresh;
    }

    public set allowServerTokenRefresh(value: boolean) {
        this._allowServerTokenRefresh = value;
    }

    private async fireNeedLogin(): Promise<boolean> {
        const retryResults = await this.needLoginEvent.fire(this);

        if (retryResults) {
            //Take first result that is actually defined
            for (let i = 0; i < retryResults.length; ++i) {
                if (retryResults[i]) {
                    return retryResults[i];
                }
            }
        }

        return false;
    }

    private resolveQueue() {
        const promise = this.queuePromise;
        this.queuePromise = null;
        promise.resolve(this.currentToken);
    }

    private rejectQueue(err: any) {
        const promise = this.queuePromise;
        this.queuePromise = null;
        promise.reject(this.currentToken);
    }
}

export function addServices(services: controller.ServiceCollection, tokenUrl: string, bearerCookieName: string): void {
    services.tryAddShared(TokenManager, (s) => new TokenManager(tokenUrl, bearerCookieName));
}