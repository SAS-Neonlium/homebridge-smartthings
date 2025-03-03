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

  constructor(
    private readonly platform: IKHomeBridgeHomebridgePlatform,
    private readonly log: Logger,
    storagePath: string,
  ) {
    this.tokenPath = path.join(storagePath, 'smartthings_tokens.json');
    this.loadTokens();
  }

  private loadTokens(): void {
    try {
      if (fs.existsSync(this.tokenPath)) {
        const data = fs.readFileSync(this.tokenPath, 'utf8');
        this.tokenData = JSON.parse(data);
        this.log.debug('Loaded existing tokens from storage');
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
    this.scheduleTokenRefresh();
  }

  public getAccessToken(): string | null {
    return this.tokenData?.access_token || null;
  }

  public getRefreshToken(): string | null {
    return this.tokenData?.refresh_token || null;
  }

  public isTokenValid(): boolean {
    if (!this.tokenData) return false;
    return Date.now() < this.tokenData.expires_at;
  }

  public isRefreshTokenValid(): boolean {
    if (!this.tokenData) return false;
    return Date.now() < this.tokenData.refresh_token_expires_at;
  }

  private scheduleTokenRefresh(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    if (!this.tokenData || !this.tokenData.expires_at) {
      return;
    }

    const timeUntilExpiry = this.tokenData.expires_at - Date.now();
    const refreshTime = Math.max(timeUntilExpiry - 5 * 60 * 1000, 0); // Refresh 5 minutes before expiry

    this.refreshTimer = setTimeout(() => {
      this.platform.auth.refreshTokens();
    }, refreshTime);
  }

  public clearTokens(): void {
    this.tokenData = null;
    if (fs.existsSync(this.tokenPath)) {
      fs.unlinkSync(this.tokenPath);
    }
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
  }
} 