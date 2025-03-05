import { Logger } from 'homebridge';
import * as fs from 'fs';
import * as path from 'path';
import { IKHomeBridgeHomebridgePlatform } from '../platform';

export interface TokenData {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at: number;
  refresh_token_expires_at: number;
  installed_app_id?: string;
  location_id?: string;
}

export class TokenManager {
  private tokenPath: string;
  private tokenData: TokenData | null = null;
  private refreshTimer: NodeJS.Timeout | null = null;
  private readonly REFRESH_BEFORE_EXPIRY = 5 * 60 * 1000; // Refresh 5 minutes before expiry
  private readonly REFRESH_CHECK_INTERVAL = 60 * 1000; // Check every minute

  constructor(
    private readonly platform: IKHomeBridgeHomebridgePlatform,
    private readonly log: Logger,
    storagePath: string,
  ) {
    this.tokenPath = path.join(storagePath, 'smartthings_tokens.json');
    this.loadTokens();
    this.startRefreshMonitor();
  }

  private startRefreshMonitor(): void {
    // Clear any existing timer
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
    }

    // Start a periodic check for token refresh
    this.refreshTimer = setInterval(() => {
      this.checkAndRefreshTokens();
    }, this.REFRESH_CHECK_INTERVAL);
  }

  private async checkAndRefreshTokens(): Promise<void> {
    if (!this.tokenData) {
      return;
    }

    const now = Date.now();
    const timeUntilExpiry = this.tokenData.expires_at - now;
    const timeUntilRefreshExpiry = this.tokenData.refresh_token_expires_at - now;

    // If refresh token is about to expire, start new auth flow
    if (timeUntilRefreshExpiry <= this.REFRESH_BEFORE_EXPIRY) {
      this.log.warn('Refresh token is about to expire, starting new auth flow');
      this.platform.auth.startAuthFlow();
      return;
    }

    // If access token is about to expire, refresh it
    if (timeUntilExpiry <= this.REFRESH_BEFORE_EXPIRY) {
      this.log.debug('Access token is about to expire, refreshing tokens');
      try {
        await this.platform.auth.refreshTokens();
      } catch (error) {
        this.log.error('Failed to refresh tokens:', error);
      }
    }
  }

  private loadTokens(): void {
    try {
      if (fs.existsSync(this.tokenPath)) {
        const data = fs.readFileSync(this.tokenPath, 'utf8');
        this.tokenData = JSON.parse(data);
        this.log.debug('Loaded existing tokens from storage');

        // Immediately check if tokens need refresh after loading
        this.checkAndRefreshTokens();
      }
    } catch (error) {
      this.log.error('Error loading tokens:', error);
    }
  }

  private saveTokens(): void {
    try {
      if (this.tokenData) {
        fs.writeFileSync(this.tokenPath, JSON.stringify(this.tokenData, null, 2));
        this.log.debug('Saved tokens to storage');
      }
    } catch (error) {
      this.log.error('Error saving tokens:', error);
    }
  }

  public async updateTokens(tokenData: Partial<TokenData>): Promise<void> {
    this.tokenData = {
      ...this.tokenData,
      ...tokenData,
      expires_at: Date.now() + (tokenData.expires_in || 0) * 1000,
      refresh_token_expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000, // 30 days
    } as TokenData;

    // Update platform config for backward compatibility
    if (tokenData.access_token) {
      this.platform.config.AccessToken = tokenData.access_token;
      try {
        // Save the updated config to disk
        const configPath = this.platform.api.user.configPath();
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        
        // Find and update our platform's config
        const platformConfig = config.platforms.find(p => 
          p.platform === 'HomeBridgeSmartThings' && p.name === this.platform.config.name
        );
        
        if (platformConfig) {
          platformConfig.AccessToken = tokenData.access_token;
          fs.writeFileSync(configPath, JSON.stringify(config, null, 4));
          this.log.debug('Updated AccessToken in Homebridge config');
        }
      } catch (error) {
        this.log.error('Error updating platform config:', error);
      }
    }

    this.saveTokens();
  }

  public getAccessToken(): string | null {
    return this.tokenData?.access_token || null;
  }

  public getRefreshToken(): string | null {
    return this.tokenData?.refresh_token || null;
  }

  public isTokenValid(): boolean {
    if (!this.tokenData) return false;
    return Date.now() < (this.tokenData.expires_at - this.REFRESH_BEFORE_EXPIRY);
  }

  public isRefreshTokenValid(): boolean {
    if (!this.tokenData) return false;
    return Date.now() < (this.tokenData.refresh_token_expires_at - this.REFRESH_BEFORE_EXPIRY);
  }

  public clearTokens(): void {
    this.tokenData = null;
    if (fs.existsSync(this.tokenPath)) {
      fs.unlinkSync(this.tokenPath);
    }
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
    }
  }

  public getTokenExpiryInfo(): { accessTokenExpiresIn: number; refreshTokenExpiresIn: number } {
    if (!this.tokenData) {
      return { accessTokenExpiresIn: 0, refreshTokenExpiresIn: 0 };
    }

    const now = Date.now();
    return {
      accessTokenExpiresIn: Math.max(0, this.tokenData.expires_at - now),
      refreshTokenExpiresIn: Math.max(0, this.tokenData.refresh_token_expires_at - now),
    };
  }
} 