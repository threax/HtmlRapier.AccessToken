///<amd-module name="hr.accesstoken.fetcher"/>

import { Fetcher } from 'hr.fetcher';
import * as events from 'hr.eventdispatcher';
import { IWhitelist } from 'hr.whitelist';
import { TokenManager } from 'hr.accesstoken.manager';

export class AccessTokenFetcher extends Fetcher {
    private next: Fetcher;
    private accessWhitelist: IWhitelist;
    private _alwaysRefreshToken: boolean = false;
    private _useToken: boolean = true;
    private _disableOnNoToken: boolean = true;

    constructor(private tokenManager: TokenManager, accessWhitelist: IWhitelist, next: Fetcher) {
        super();
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
}