import { storageHelper } from '../../utils/storageHelper'
import { createStorageKey } from '../../utils/urlUtils'
import type { AuthTokens } from '../../types/auth'

export class TokenManager {
  private static readonly ACCESS_TOKEN_KEY = 'access_token'
  private static readonly REFRESH_TOKEN_KEY = 'refresh_token'
  private static readonly ID_TOKEN_KEY = 'id_token'
  private static readonly EXPIRES_AT_KEY = 'expires_at'

  async saveTokens(tokens: AuthTokens, serverUrl: string): Promise<void> {
    const prefix = createStorageKey(serverUrl, 'tokens')

    await Promise.all([
      storageHelper.setItem(`${prefix}_${TokenManager.ACCESS_TOKEN_KEY}`, tokens.accessToken),
      storageHelper.setItem(`${prefix}_${TokenManager.REFRESH_TOKEN_KEY}`, tokens.refreshToken),
      storageHelper.setItem(`${prefix}_${TokenManager.ID_TOKEN_KEY}`, tokens.idToken),
      storageHelper.setItem(`${prefix}_${TokenManager.EXPIRES_AT_KEY}`, tokens.expiresAt.toString())
    ])
  }

  async getValidAccessToken(serverUrl: string): Promise<string | null> {
    const prefix = createStorageKey(serverUrl, 'tokens')
    const expiresAt = await storageHelper.getItem(`${prefix}_${TokenManager.EXPIRES_AT_KEY}`)

    if (!expiresAt || Date.now() >= parseInt(expiresAt) - 60000) { // 1 min buffer
      return await this.refreshAccessToken(serverUrl)
    }

    return await storageHelper.getItem(`${prefix}_${TokenManager.ACCESS_TOKEN_KEY}`)
  }

  async getTokens(serverUrl: string): Promise<AuthTokens | null> {
    const prefix = createStorageKey(serverUrl, 'tokens')

    try {
      const [accessToken, refreshToken, idToken, expiresAt] = await Promise.all([
        storageHelper.getItem(`${prefix}_${TokenManager.ACCESS_TOKEN_KEY}`),
        storageHelper.getItem(`${prefix}_${TokenManager.REFRESH_TOKEN_KEY}`),
        storageHelper.getItem(`${prefix}_${TokenManager.ID_TOKEN_KEY}`),
        storageHelper.getItem(`${prefix}_${TokenManager.EXPIRES_AT_KEY}`)
      ])

      if (!accessToken || !refreshToken || !idToken || !expiresAt) {
        return null
      }

      return {
        accessToken,
        refreshToken,
        idToken,
        expiresAt: parseInt(expiresAt)
      }
    } catch (error) {
      console.warn('Failed to retrieve tokens:', error)
      return null
    }
  }

  async refreshAccessToken(serverUrl: string): Promise<string | null> {
    const prefix = createStorageKey(serverUrl, 'tokens')
    const refreshToken = await storageHelper.getItem(`${prefix}_${TokenManager.REFRESH_TOKEN_KEY}`)

    if (!refreshToken) {
      return null
    }

    try {
      // TODO: Implement token refresh with server
      // For now, return null to force re-authentication
      return null
    } catch (error) {
      console.warn('Token refresh failed:', error)
      await this.clearTokens(serverUrl)
      return null
    }
  }

  async clearTokens(serverUrl: string): Promise<void> {
    const prefix = createStorageKey(serverUrl, 'tokens')

    await Promise.all([
      storageHelper.deleteItem(`${prefix}_${TokenManager.ACCESS_TOKEN_KEY}`).catch(() => {}),
      storageHelper.deleteItem(`${prefix}_${TokenManager.REFRESH_TOKEN_KEY}`).catch(() => {}),
      storageHelper.deleteItem(`${prefix}_${TokenManager.ID_TOKEN_KEY}`).catch(() => {}),
      storageHelper.deleteItem(`${prefix}_${TokenManager.EXPIRES_AT_KEY}`).catch(() => {})
    ])
  }

  async hasValidTokens(serverUrl: string): Promise<boolean> {
    const tokens = await this.getTokens(serverUrl)
    console.log('Token validation - tokens found:', !!tokens, 'for server:', serverUrl)
    if (!tokens) return false

    // Check if tokens are not expired (with 5 minute buffer)
    const isValid = Date.now() < tokens.expiresAt - 300000
    console.log('Token validation - valid:', isValid, 'expires at:', new Date(tokens.expiresAt), 'now:', new Date())
    return isValid
  }
}

export const tokenManager = new TokenManager()