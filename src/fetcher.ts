///<amd-module name="hr.accesstoken.fetcher"/>

import { Fetcher } from 'hr.fetcher';
import * as events from 'hr.eventdispatcher';
import { IWhitelist } from 'hr.whitelist';
import { TokenManager } from 'hr.accesstoken.manager'

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