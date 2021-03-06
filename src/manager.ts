﻿import { Fetcher } from 'htmlrapier/src/fetcher';
import * as winfetch from 'htmlrapier/src/windowfetch';
import * as events from 'htmlrapier/src/eventdispatcher';
import * as ep from 'htmlrapier/src/externalpromise';
import * as storage from 'htmlrapier/src/storage';
import * as controller from 'htmlrapier/src/controller';

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

export interface AccessToken {
    /**
     * The subject of the token. */
    sub: string;
    /**
     * The start time of the token. */
    nbf: number;
    /**
     * The expiration date of the token. */
    exp: number;
}

export class TokenManager {
    private currentToken: string;
    private startTime: number;
    private currentSub: string;
    private expirationTick: number;
    private needLoginEvent: events.PromiseEventDispatcher<boolean, TokenManager> = new events.PromiseEventDispatcher<boolean, TokenManager>();
    private queuePromise: ep.ExternalPromise<string> = null;
    private fetcher: Fetcher;
    private tokenObj: AccessToken = null;

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

    public async getAccessToken(): Promise<AccessToken | null> {
        //Run getToken to handle the refresh
        await this.getToken();
        return this.tokenObj;
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
        //If we don't have a token yet, try to read one from the cookie
        if (!this.currentToken) {
            this.readCookieAccessToken();
        }

        //Make sure we managed to get a token, not getting one is valid
        if (this.currentToken) {
            this.processCurrentToken();

            //Double check expiration times and refresh if needed
            if (this.needsRefresh()) {
                if (!await this.readServerAccessToken()) {
                    if (!await this.fireNeedLogin()) {
                        this.startTime = undefined;
                        throw new Error("Could not refresh access token or log back in.");
                    }
                }

                //Read the cookie again for the updated information.
                this.readCookieAccessToken();
                if (this.currentToken) {
                    this.processCurrentToken();
                }
            }
        }
    }

    private processCurrentToken() {
        this.tokenObj = parseJwt(this.currentToken);

        if (this.currentSub !== undefined) {
            if (this.currentSub !== this.tokenObj.sub) { //Do not combine ifs
                //Subjects do not match, clear tokens
                this.clearToken();
                throw new Error("Sub did not match on new token, likely a different user. Aborting refresh.");
            }
        }
        else {
            this.currentSub = this.tokenObj.sub;
        }

        this.startTime = this.tokenObj.nbf;
        this.expirationTick = (this.tokenObj.exp - this.startTime) / 2; //After half the token time has expired we will turn it in for another one.
    }

    private readCookieAccessToken() {
        this.currentToken = storage.CookieStorageDriver.readRaw(this._bearerCookieName);
        if (this.currentToken === null) {
            this.currentToken = undefined; //Keeps with undefined everywhere else.
        }
    }


    ///Read an access token from the server. If the refresh is successful true will be returned otherwise false.
    private async readServerAccessToken(): Promise<boolean> {
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