import { Logger } from 'homebridge';
import * as crypto from 'crypto';
import axios from 'axios';
import * as http from 'http';
import { IKHomeBridgeHomebridgePlatform } from '../platform';
import { TokenManager } from './tokenManager';
import { WebhookServer } from '../webhook/webhookServer';

const SMARTTHINGS_AUTH_URL = 'https://api.smartthings.com/oauth/authorize';
const SMARTTHINGS_TOKEN_URL = 'https://api.smartthings.com/oauth/token';

export class SmartThingsAuth {
  private tokenManager: TokenManager;
  private state: string | null = null;

  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly log: Logger,
    private readonly platform: IKHomeBridgeHomebridgePlatform,
    storagePath: string,
    private readonly webhookServer: WebhookServer,
  ) {
    this.tokenManager = new TokenManager(platform, log, storagePath);
    this.webhookServer.setAuthHandler(this);
  }

  public async handleOAuthCallback(query: any, res: http.ServerResponse): Promise<void> {
    try {
      if (!query.code || !query.state) {
        throw new Error('Missing code or state parameter');
      }

      if (query.state !== this.state) {
        throw new Error('Invalid state parameter');
      }

      const tokens = await this.exchangeCodeForTokens(query.code);
      await this.tokenManager.updateTokens(tokens);

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<h1>Authentication successful!</h1><p>You can close this window and restart Homebridge.</p>');

      this.log.info('Successfully authenticated with SmartThings');
    } catch (error) {
      this.log.error('OAuth callback error:', error);
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end('<h1>Authentication failed</h1><p>Please try again.</p>');
    }
  }

  private async exchangeCodeForTokens(code: string): Promise<any> {
    // Create Basic Auth header from client credentials
    const basicAuth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');

    // Build redirect URI with optional port
    let redirectUri = this.platform.config.server_url;
    if (!redirectUri.endsWith('/')) {
      redirectUri += '/';
    }
    redirectUri += 'oauth/callback';

    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', redirectUri);

    const response = await axios.post(SMARTTHINGS_TOKEN_URL, params, {
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    return response.data;
  }

  public async refreshTokens(): Promise<void> {
    try {
      const refreshToken = this.tokenManager.getRefreshToken();
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const { accessTokenExpiresIn, refreshTokenExpiresIn } = this.tokenManager.getTokenExpiryInfo();
      this.log.debug(`Refreshing tokens - Access token expires in ${Math.floor(accessTokenExpiresIn / 1000)}s, Refresh token expires in ${Math.floor(refreshTokenExpiresIn / (1000 * 60 * 60))}h`);

      // Create Basic Auth header from client credentials
      const basicAuth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');

      const params = new URLSearchParams();
      params.append('grant_type', 'refresh_token');
      params.append('refresh_token', refreshToken);

      const response = await axios.post(SMARTTHINGS_TOKEN_URL, params, {
        headers: {
          'Authorization': `Basic ${basicAuth}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      await this.tokenManager.updateTokens(response.data);
      
      const { accessTokenExpiresIn: newAccessExpiry } = this.tokenManager.getTokenExpiryInfo();
      this.log.info(`Successfully refreshed tokens - New access token expires in ${Math.floor(newAccessExpiry / 1000)}s`);
    } catch (error) {
      this.log.error('Error refreshing tokens:', error);
      if (this.tokenManager.isRefreshTokenValid()) {
        this.log.warn('Refresh token is still valid, will retry refresh later');
      } else {
        this.log.warn('Refresh token is invalid, starting new auth flow');
        this.startAuthFlow();
      }
      throw error;
    }
  }

  public startAuthFlow(): void {
    this.state = crypto.randomBytes(32).toString('hex');
    
    const authUrl = new URL(SMARTTHINGS_AUTH_URL);
    authUrl.searchParams.append('client_id', this.clientId);
    authUrl.searchParams.append('response_type', 'code');

    // Build redirect URI with optional port
    let redirectUri = this.platform.config.server_url;
    if (!redirectUri.endsWith('/')) {
      redirectUri += '/';
    }
    redirectUri += 'oauth/callback';
    
    authUrl.searchParams.append('redirect_uri', redirectUri);
    authUrl.searchParams.append('scope', 'r:devices:* x:devices:* r:locations:*');
    authUrl.searchParams.append('state', this.state);

    this.log.warn('\n=================================================');
    this.log.warn('SmartThings Authentication Required');
    this.log.warn('Please visit this URL to authorize with SmartThings:');
    this.log.warn(authUrl.toString());
    this.log.warn('=================================================\n');
    this.log.warn('Restart Homebridge after authentication');
  }

  public async initialize(): Promise<void> {
    const accessToken = this.tokenManager.getAccessToken();
    
    if (!accessToken || !this.tokenManager.isTokenValid()) {
      if (this.tokenManager.isRefreshTokenValid()) {
        await this.refreshTokens();
      } else {
        this.startAuthFlow();
      }
    }
  }

  public getAccessToken(): string | null {
    return this.tokenManager.getAccessToken();
  }
} 