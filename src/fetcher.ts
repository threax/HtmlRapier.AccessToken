///<amd-module name="hr.accesstoken.fetcher"/>

import { Fetcher } from 'hr.fetcher';
import * as events from 'hr.eventdispatcher';
import { IWhitelist } from 'hr.whitelist';
import { TokenManager } from 'hr.accesstoken.manager';

export class AccessTokenFetcher extends Fetcher {
    constructor(private tokenManager: TokenManager, private accessWhitelist: IWhitelist, private next: Fetcher, private headerName: string = "bearer") {
        super();
    }

    public async fetch(url: RequestInfo, init?: RequestInit): Promise<Response> {
        //Make sure the request is allowed to send an access token
        if (this.accessWhitelist.isWhitelisted(url)) {
            var token: string = await this.tokenManager.getToken();
            if (token) {
                init.headers[this.headerName] = token;
            }
        }

        return this.next.fetch(url, init);
    }
}