///<amd-module name="hr.accesstoken.accesstokens"/>

import { Fetcher } from 'hr.fetcher';
import * as events from 'hr.eventdispatcher';
import * as ep from 'hr.externalpromise';
import { IWhitelist } from 'hr.whitelist';
import * as storage from 'hr.storage';

//From https://github.com/auth0/jwt-decode/blob/master/lib/base64_url_decode.js
function b64DecodeUnicode(str: string) {
    return decodeURIComponent(atob(str).replace(/(.)/g, function (m, p) {
        var code = p.charCodeAt(0).toString(16).toUpperCase();
        if (code.length < 2) {
            code = '0' + code;
        }
        return '%' + code;
    }));
}

function base64_url_decode(str: string) {
    var output = str.replace(/-/g, "+").replace(/_/g, "/");
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
    var pos = options.header === true ? 0 : 1;
    return JSON.parse(base64_url_decode(token.split('.')[pos]));
};

interface IServerTokenResult {
    headerName: string;
    accessToken: string;
}

export class TokenManager {
    private currentToken: string;
    private _headerName: string = "bearer";
    private startTime: number;
    private currentSub: string;
    private expirationTick: number;
    private needLoginEvent: events.PromiseEventDispatcher<boolean, TokenManager> = new events.PromiseEventDispatcher<boolean, TokenManager>();
    private queuePromise: ep.ExternalPromise<string> = null;
    private _alwaysRequestLogin: boolean = false;
    private _bearerCookieName: string = null;
    private _allowServerTokenRefresh: boolean = true;

    constructor(private tokenPath: string, private fetcher: Fetcher) {

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
        if (!this._bearerCookieName) {
            throw new Error("You must specify the bearer cookie name to use access token authentication.");
        }

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
            try {
                await this.readServerAccessToken();
            }
            catch (err) {
                //If there was an error, attempt to relogin
                if (!await this.fireNeedLogin()) { //Got false from fireNeedLogin, which means no login was performed, throw an error
                    this.startTime = undefined;
                    throw new Error("Could not refresh access token or log back in.");
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
    }

    private processCurrentToken() {
        var tokenObj = parseJwt(this.currentToken);

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

    private async readServerAccessToken() {
        if (this._allowServerTokenRefresh) {
            let request: RequestInit = {
                method: "POST",
                cache: "no-cache",
                headers: {
                    "Content-Type": "application/json; charset=UTF-8"
                },
                credentials: "include"
            };
            var response = await this.fetcher.fetch(this.tokenPath, request);
            if (response.status < 200 && response.status > 299) {
                throw new Error("Error feteching token from server.")
            }
        }
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

    public get headerName() {
        return this._headerName;
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
        var retryResults = await this.needLoginEvent.fire(this);

        if (retryResults) {
            //Take first result that is actually defined
            for (var i = 0; i < retryResults.length; ++i) {
                if (retryResults[i]) {
                    return retryResults[i];
                }
            }
        }

        return false;
    }

    private resolveQueue() {
        var promise = this.queuePromise;
        this.queuePromise = null;
        promise.resolve(this.currentToken);
    }

    private rejectQueue(err: any) {
        var promise = this.queuePromise;
        this.queuePromise = null;
        promise.reject(this.currentToken);
    }
}

export class AccessTokenFetcher extends Fetcher {
    public static isInstance(t: any): t is AccessTokenFetcher {
        return (<AccessTokenFetcher>t).onNeedLogin !== undefined
            && (<AccessTokenFetcher>t).fetch !== undefined;
    }

    private next: Fetcher;
    private accessWhitelist: IWhitelist;
    private tokenManager: TokenManager;
    private needLoginEvent: events.PromiseEventDispatcher<boolean, AccessTokenFetcher> = new events.PromiseEventDispatcher<boolean, AccessTokenFetcher>();
    private _alwaysRefreshToken: boolean = false;
    private _useToken: boolean = true;
    private _disableOnNoToken: boolean = true;

    constructor(tokenPath: string, accessWhitelist: IWhitelist, next: Fetcher) {
        super();
        this.tokenManager = new TokenManager(tokenPath, next);
        this.tokenManager.onNeedLogin.add((t) => this.fireNeedLogin());
        this.next = next;
        this.accessWhitelist = accessWhitelist;
    }

    public async fetch(url: RequestInfo, init?: RequestInit): Promise<Response> {
        if (this._useToken) {
            //Make sure the request is allowed to send an access token
            var whitelisted: boolean = this.accessWhitelist.isWhitelisted(url);

            //Sometimes we always refresh the token even if the item is not on the whitelist
            //This is configured by the user
            if (whitelisted || this._alwaysRefreshToken) {
                var token: string = await this.tokenManager.getToken();
                if (token) {
                    var headerName: string = this.tokenManager.headerName;
                    if (whitelisted && headerName) {
                        init.headers[headerName] = token;
                    }
                }
                else {
                    //No token, stop trying to use it
                    this._useToken = !this._disableOnNoToken;
                }
            }
        }

        return this.next.fetch(url, init);
    }

    /**
     * This event will fire if the token manager tried to get an access token and failed. You can try
     * to log the user back in at this point.
     */
    public get onNeedLogin(): events.EventModifier<events.FuncEventListener<Promise<boolean>, AccessTokenFetcher>> {
        return this.needLoginEvent;
    }

    public get alwaysRefreshToken(): boolean {
        return this._alwaysRefreshToken;
    }

    public set alwaysRefreshToken(value: boolean) {
        this._alwaysRefreshToken = value;
    }

    public get useToken(): boolean {
        return this._useToken;
    }

    public set useToken(value: boolean) {
        this._useToken = value;
    }

    public get disableOnNoToken(): boolean {
        return this._disableOnNoToken;
    }

    public set disableOnNoToken(value: boolean) {
        this._disableOnNoToken = value;
    }

    public get alwaysRequestLogin(): boolean {
        return this.tokenManager.alwaysRequestLogin;
    }

    public set alwaysRequestLogin(value: boolean) {
        this.tokenManager.alwaysRequestLogin = value;
    }

    public get bearerCookieName(): string {
        return this.tokenManager.bearerCookieName;
    }

    public set bearerCookieName(value: string) {
        this.tokenManager.bearerCookieName = value;
    }

    public get allowServerTokenRefresh(): boolean {
        return this.tokenManager.allowServerTokenRefresh;
    }

    public set allowServerTokenRefresh(value: boolean) {
        this.tokenManager.allowServerTokenRefresh = value;
    }

    private async fireNeedLogin(): Promise<boolean> {
        var retryResults = await this.needLoginEvent.fire(this);

        if (retryResults) {
            for (var i = 0; i < retryResults.length; ++i) {
                if (retryResults[i]) {
                    return retryResults[i];
                }
            }
        }

        return false;
    }
}