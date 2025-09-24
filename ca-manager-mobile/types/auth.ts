export interface AuthTokens {
  accessToken: string
  refreshToken: string
  idToken: string
  expiresAt: number
}

export interface UserProfile {
  email: string
  name: string
  picture?: string
}

export interface AuthUser {
  id: string
  email: string
  name: string
  picture?: string | null
  provider: OAuthProvider
}

export type OAuthProvider = 'google' | 'microsoft'

export interface AuthState {
  isAuthenticated: boolean
  user: UserProfile | null
  serverConfig: ServerConfig | null
  loading: boolean
  error?: string
}

export interface OAuthRequest {
  clientId: string
  scopes: string[]
  redirectUri: string
  responseType: 'code'
  state?: string
}

export interface OAuthResponse {
  type: 'success' | 'cancel' | 'error'
  params: {
    code?: string
    error?: string
    state?: string
  }
}

import type { ServerConfig } from './server'