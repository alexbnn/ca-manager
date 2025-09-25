import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { authService } from './authService'
import type { AuthUser } from '../../types/auth'
import type { ServerConfig } from '../../types/server'

interface AuthContextType {
  user: AuthUser | null
  serverConfig: ServerConfig | null
  accessToken: string | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (serverConfig: ServerConfig) => Promise<void>
  logout: () => Promise<void>
  checkAuthStatus: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [serverConfig, setServerConfig] = useState<ServerConfig | null>(null)
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  useEffect(() => {
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    try {
      setIsLoading(true)

      // Load active server from storage
      const activeServerConfig = await loadActiveServerConfig()
      console.log('Auth check - loaded server config:', activeServerConfig?.url)

      if (activeServerConfig) {
        setServerConfig(activeServerConfig)

        const authenticated = await authService.isAuthenticated(activeServerConfig.url)
        console.log('Auth check - authenticated:', authenticated)
        setIsAuthenticated(authenticated)

        if (authenticated) {
          // Load user info from storage or derive from tokens
          const userInfo = await loadUserInfo(activeServerConfig.url)
          console.log('Auth check - loaded user:', userInfo?.email)
          setUser(userInfo)

          // Get the valid access token
          const validAccessToken = await authService.getValidAccessToken(activeServerConfig.url)
          console.log('Auth check - access token available:', !!validAccessToken)
          setAccessToken(validAccessToken)
        } else {
          setUser(null)
          setAccessToken(null)
        }
      } else {
        console.log('Auth check - no server config found')
        setIsAuthenticated(false)
        setUser(null)
        setServerConfig(null)
        setAccessToken(null)
      }
    } catch (error) {
      console.warn('Auth status check failed:', error)
      setIsAuthenticated(false)
      setUser(null)
      setServerConfig(null)
      setAccessToken(null)
    } finally {
      setIsLoading(false)
    }
  }

  const login = async (config: ServerConfig) => {
    try {
      setIsLoading(true)

      console.log('Login - starting authentication for:', config.url)
      const authenticatedUser = await authService.authenticateWithServer(config)
      console.log('Login - authentication successful, user:', authenticatedUser.email)

      setUser(authenticatedUser)
      setServerConfig(config)
      setIsAuthenticated(true)

      // Get the access token
      const validAccessToken = await authService.getValidAccessToken(config.url)
      setAccessToken(validAccessToken)

      // Save active server and user info to storage
      await saveActiveServerConfig(config)
      await saveUserInfo(config.url, authenticatedUser)
      console.log('Login - saved server config and user info to storage')

    } catch (error) {
      console.error('Login failed:', error)
      throw error
    } finally {
      setIsLoading(false)
    }
  }

  const logout = async () => {
    console.log('AuthProvider logout function called')
    try {
      setIsLoading(true)
      console.log('Starting logout process, serverConfig:', !!serverConfig)

      if (serverConfig) {
        console.log('Calling authService.logout...')
        await authService.logout(serverConfig.url)
        console.log('Clearing active server config...')
        await clearActiveServerConfig()
        console.log('Clearing user info...')
        await clearUserInfo(serverConfig.url)
      }

      console.log('Clearing auth state...')
      setUser(null)
      setServerConfig(null)
      setAccessToken(null)
      setIsAuthenticated(false)
      console.log('Logout completed successfully')
    } catch (error) {
      console.warn('Logout failed:', error)
      // Still clear local state even if server logout fails
      setUser(null)
      setServerConfig(null)
      setAccessToken(null)
      setIsAuthenticated(false)
    } finally {
      setIsLoading(false)
      console.log('Logout process finished')
    }
  }

  const value: AuthContextType = {
    user,
    serverConfig,
    accessToken,
    isLoading,
    isAuthenticated,
    login,
    logout,
    checkAuthStatus
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Storage helpers for server config and user info
async function loadActiveServerConfig(): Promise<ServerConfig | null> {
  try {
    const AsyncStorage = (await import('@react-native-async-storage/async-storage')).default
    const stored = await AsyncStorage.getItem('active_server')
    return stored ? JSON.parse(stored) : null
  } catch {
    return null
  }
}

async function saveActiveServerConfig(config: ServerConfig): Promise<void> {
  try {
    const AsyncStorage = (await import('@react-native-async-storage/async-storage')).default
    await AsyncStorage.setItem('active_server', JSON.stringify(config))
  } catch (error) {
    console.warn('Failed to save active server config:', error)
  }
}

async function clearActiveServerConfig(): Promise<void> {
  try {
    const AsyncStorage = (await import('@react-native-async-storage/async-storage')).default
    await AsyncStorage.removeItem('active_server')
  } catch (error) {
    console.warn('Failed to clear active server config:', error)
  }
}

async function loadUserInfo(serverUrl: string): Promise<AuthUser | null> {
  try {
    const AsyncStorage = (await import('@react-native-async-storage/async-storage')).default
    const stored = await AsyncStorage.getItem(`user_info_${btoa(serverUrl)}`)
    return stored ? JSON.parse(stored) : null
  } catch {
    return null
  }
}

async function saveUserInfo(serverUrl: string, user: AuthUser): Promise<void> {
  try {
    const AsyncStorage = (await import('@react-native-async-storage/async-storage')).default
    await AsyncStorage.setItem(`user_info_${btoa(serverUrl)}`, JSON.stringify(user))
  } catch (error) {
    console.warn('Failed to save user info:', error)
  }
}

async function clearUserInfo(serverUrl: string): Promise<void> {
  try {
    const AsyncStorage = (await import('@react-native-async-storage/async-storage')).default
    await AsyncStorage.removeItem(`user_info_${btoa(serverUrl)}`)
  } catch (error) {
    console.warn('Failed to clear user info:', error)
  }
}