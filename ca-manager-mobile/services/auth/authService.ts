import * as AuthSession from 'expo-auth-session'
import * as WebBrowser from 'expo-web-browser'
import { tokenManager } from './tokenManager'
import { serverService } from '../api/servers'
import { normalizeUrl } from '../../utils/urlUtils'
import { OAUTH_CONFIG, API_CONFIG } from '../../utils/constants'
import type { AuthTokens, AuthUser, OAuthProvider } from '../../types/auth'
import type { ServerConfig } from '../../types/server'

WebBrowser.maybeCompleteAuthSession()

export class AuthService {
  constructor() {
    // We'll log the redirect URI when authentication starts
  }

  private getRedirectUri(): string {
    // Platform.OS is from react-native but we need to handle web differently
    if (typeof window !== 'undefined' && window.location) {
      // We're in a web environment with window available
      const uri = `${window.location.protocol}//${window.location.host}/auth`
      console.log('OAuth Redirect URI (web):', uri)
      return uri
    } else {
      // We're in a mobile environment or SSR
      const uri = AuthSession.makeRedirectUri({
        scheme: 'ca-manager-mobile',
        path: 'auth'
      })
      console.log('OAuth Redirect URI (mobile):', uri)
      return uri
    }
  }

  async authenticateWithServer(serverConfig: ServerConfig): Promise<AuthUser> {
    try {
      const { accessToken, user } = await this.performOAuthFlow(
        serverConfig.url,
        serverConfig.idpType
      )

      const tokens = await this.exchangeTokenWithServer(serverConfig.url, accessToken)
      await tokenManager.saveTokens(tokens, serverConfig.url)

      return user
    } catch (error) {
      console.error('Authentication failed:', error)
      throw new Error(error instanceof Error ? error.message : 'Authentication failed')
    }
  }

  private async performOAuthFlow(serverUrl: string, provider: OAuthProvider): Promise<{ accessToken: string; user: AuthUser }> {
    const discovery = await this.getOAuthDiscovery(serverUrl, provider)
    const redirectUri = this.getRedirectUri()
    console.log('Starting OAuth flow with redirect URI:', redirectUri)

    const request = new AuthSession.AuthRequest({
      clientId: discovery.clientId,
      scopes: [...OAUTH_CONFIG[provider].scopes],
      redirectUri: redirectUri,
      responseType: AuthSession.ResponseType.Code,
      usePKCE: true, // Explicitly enable PKCE
      extraParams: {
        prompt: OAUTH_CONFIG[provider].prompt,
      },
    })

    // Make sure to build the request to generate PKCE values
    await request.makeAuthUrlAsync(discovery)

    // Log PKCE details
    console.log('PKCE Details:', {
      codeVerifier: request.codeVerifier,
      codeChallenge: request.codeChallenge,
      codeChallengeMethod: request.codeChallengeMethod
    })

    console.log('OAuth request details:', {
      clientId: discovery.clientId,
      scopes: OAUTH_CONFIG[provider].scopes,
      redirectUri: redirectUri,
      discoveryUrl: discovery.authorizationEndpoint
    })

    const result = await request.promptAsync(discovery)

    if (result.type !== 'success') {
      throw new Error('OAuth authentication was cancelled or failed')
    }

    if (!result.params.code) {
      throw new Error('Authorization code not received')
    }

    console.log('Exchanging code with verifier:', request.codeVerifier)

    // Try different approach - use the entire request to maintain state
    let tokenResponse
    try {
      // First try with the codeVerifier parameter
      tokenResponse = await AuthSession.exchangeCodeAsync(
        {
          clientId: discovery.clientId,
          code: result.params.code,
          redirectUri: redirectUri,
          codeVerifier: request.codeVerifier,
          extraParams: {},
        },
        discovery
      )
    } catch (error) {
      console.error('Token exchange failed:', error)

      // Alternative: Try passing it in extraParams
      console.log('Trying alternative PKCE approach...')
      tokenResponse = await AuthSession.exchangeCodeAsync(
        {
          clientId: discovery.clientId,
          code: result.params.code,
          redirectUri: redirectUri,
          extraParams: {
            code_verifier: request.codeVerifier,
          },
        },
        discovery
      )
    }

    if (!tokenResponse.accessToken) {
      throw new Error('Access token not received')
    }

    const user = await this.getUserInfo(tokenResponse.accessToken, provider)

    return {
      accessToken: tokenResponse.accessToken,
      user
    }
  }

  private async getOAuthDiscovery(serverUrl: string, provider: OAuthProvider): Promise<AuthSession.DiscoveryDocument & { clientId: string }> {
    const normalizedUrl = normalizeUrl(serverUrl)

    try {
      const response = await fetch(`${normalizedUrl}${API_CONFIG.endpoints.info}`)
      const serverInfo = await response.json()

      if (!serverInfo.oauth_config?.[provider]) {
        throw new Error(`${provider} OAuth not configured on server`)
      }

      const oauthConfig = serverInfo.oauth_config[provider]

      // Remove .well-known/openid_configuration from the end since AuthSession.fetchDiscoveryAsync will add it
      const baseUrl = oauthConfig.discovery_url.replace('/.well-known/openid_configuration', '')

      const discovery = await AuthSession.fetchDiscoveryAsync(baseUrl)

      return {
        ...discovery,
        clientId: oauthConfig.client_id
      }
    } catch (error) {
      throw new Error(`Failed to get OAuth configuration: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  private async getUserInfo(accessToken: string, provider: OAuthProvider): Promise<AuthUser> {
    try {
      const url = provider === 'google'
        ? 'https://www.googleapis.com/oauth2/v2/userinfo'
        : 'https://graph.microsoft.com/v1.0/me'

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json',
        },
      })

      if (!response.ok) {
        throw new Error('Failed to fetch user info')
      }

      const userData = await response.json()

      if (provider === 'google') {
        return {
          id: userData.id,
          email: userData.email,
          name: userData.name,
          picture: userData.picture,
          provider: 'google'
        }
      } else {
        return {
          id: userData.id,
          email: userData.mail || userData.userPrincipalName,
          name: userData.displayName,
          picture: null,
          provider: 'microsoft'
        }
      }
    } catch (error) {
      throw new Error(`Failed to get user information: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  private async exchangeTokenWithServer(serverUrl: string, oauthToken: string): Promise<AuthTokens> {
    const normalizedUrl = normalizeUrl(serverUrl)

    try {
      const response = await fetch(`${normalizedUrl}${API_CONFIG.endpoints.authExchange}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${oauthToken}`,
        },
        body: JSON.stringify({
          oauth_token: oauthToken,
          client_type: 'mobile'
        })
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.message || 'Token exchange failed')
      }

      const data = await response.json()

      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        idToken: data.id_token,
        expiresAt: Date.now() + (data.expires_in * 1000)
      }
    } catch (error) {
      throw new Error(`Token exchange failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  async getValidAccessToken(serverUrl: string): Promise<string | null> {
    return await tokenManager.getValidAccessToken(serverUrl)
  }

  async isAuthenticated(serverUrl: string): Promise<boolean> {
    return await tokenManager.hasValidTokens(serverUrl)
  }

  async logout(serverUrl: string): Promise<void> {
    await tokenManager.clearTokens(serverUrl)
  }

  async logoutAll(): Promise<void> {
    // This would require iterating through all stored server configurations
    // For now, we'll implement server-specific logout only
    console.warn('Global logout not implemented - use server-specific logout')
  }
}

export const authService = new AuthService()