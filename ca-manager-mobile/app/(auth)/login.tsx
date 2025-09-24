import React, { useState, useEffect } from 'react'
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ActivityIndicator,
  Image,
} from 'react-native'
import { router, useLocalSearchParams } from 'expo-router'
import { SafeAreaView } from 'react-native-safe-area-context'
import { useAuth } from '../../services/auth'
import { UI_CONFIG } from '../../utils/constants'
import type { ServerConfig } from '../../types/server'

export default function LoginScreen() {
  const { serverConfig: serverConfigParam } = useLocalSearchParams()
  const { login } = useAuth()
  const [isLoading, setIsLoading] = useState(false)
  const [serverConfig, setServerConfig] = useState<ServerConfig | null>(null)

  useEffect(() => {
    if (serverConfigParam && typeof serverConfigParam === 'string') {
      try {
        const config = JSON.parse(serverConfigParam) as ServerConfig
        setServerConfig(config)
      } catch (error) {
        Alert.alert('Error', 'Invalid server configuration')
        router.back()
      }
    } else {
      Alert.alert('Error', 'No server configuration provided')
      router.back()
    }
  }, [serverConfigParam])

  const handleLogin = async () => {
    if (!serverConfig) return

    setIsLoading(true)

    try {
      console.log('Starting OAuth login for:', serverConfig)
      await login(serverConfig)
      console.log('OAuth login successful')
      router.replace('/(app)/(tabs)/')
    } catch (error) {
      console.error('OAuth login failed:', error)
      Alert.alert(
        'Login Failed',
        error instanceof Error ? error.message : 'Authentication failed'
      )
    } finally {
      setIsLoading(false)
    }
  }

  const getProviderIcon = (provider: string) => {
    switch (provider) {
      case 'google':
        return '🔵' // Google icon placeholder
      case 'microsoft':
        return '🟪' // Microsoft icon placeholder
      default:
        return '🔐'
    }
  }

  const getProviderName = (provider: string) => {
    switch (provider) {
      case 'google':
        return 'Google Workspace'
      case 'microsoft':
        return 'Microsoft Entra ID'
      default:
        return 'Identity Provider'
    }
  }

  if (!serverConfig) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={UI_CONFIG.colors.primary} />
          <Text style={styles.loadingText}>Loading server configuration...</Text>
        </View>
      </SafeAreaView>
    )
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <View style={styles.header}>
          <View style={styles.serverInfo}>
            {serverConfig.branding?.logo ? (
              <Image source={{ uri: serverConfig.branding.logo }} style={styles.serverLogo} />
            ) : (
              <View style={styles.serverLogoPlaceholder}>
                <Text style={styles.serverLogoText}>🔐</Text>
              </View>
            )}
            <Text style={styles.serverName}>{serverConfig.name}</Text>
            <Text style={styles.serverUrl}>{serverConfig.url}</Text>
          </View>
        </View>

        <View style={styles.loginSection}>
          <Text style={styles.loginTitle}>Sign in to continue</Text>
          <Text style={styles.loginSubtitle}>
            Authenticate with {getProviderName(serverConfig.idpType)} to access your certificates
          </Text>

          <TouchableOpacity
            style={[
              styles.loginButton,
              { backgroundColor: serverConfig.branding?.primaryColor || UI_CONFIG.colors.primary },
              isLoading && styles.disabledButton
            ]}
            onPress={handleLogin}
            disabled={isLoading}
          >
            {isLoading ? (
              <ActivityIndicator color="white" />
            ) : (
              <>
                <Text style={styles.loginButtonIcon}>
                  {getProviderIcon(serverConfig.idpType)}
                </Text>
                <Text style={styles.loginButtonText}>
                  Sign in with {getProviderName(serverConfig.idpType)}
                </Text>
              </>
            )}
          </TouchableOpacity>
        </View>

        <View style={styles.footer}>
          <TouchableOpacity
            style={styles.backButton}
            onPress={() => router.back()}
            disabled={isLoading}
          >
            <Text style={styles.backButtonText}>← Back to Server Entry</Text>
          </TouchableOpacity>

          <View style={styles.securityNote}>
            <Text style={styles.securityText}>
              🔒 Your authentication is secured with industry-standard OAuth 2.0
            </Text>
          </View>
        </View>
      </View>
    </SafeAreaView>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: UI_CONFIG.colors.background,
  },
  content: {
    flex: 1,
    paddingHorizontal: UI_CONFIG.spacing.lg,
    paddingTop: UI_CONFIG.spacing.xl,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    gap: UI_CONFIG.spacing.md,
  },
  loadingText: {
    fontSize: 16,
    color: UI_CONFIG.colors.textSecondary,
  },
  header: {
    alignItems: 'center',
    marginBottom: UI_CONFIG.spacing.xl * 2,
  },
  serverInfo: {
    alignItems: 'center',
  },
  serverLogo: {
    width: 64,
    height: 64,
    borderRadius: UI_CONFIG.borderRadius.lg,
    marginBottom: UI_CONFIG.spacing.md,
  },
  serverLogoPlaceholder: {
    width: 64,
    height: 64,
    backgroundColor: UI_CONFIG.colors.surface,
    borderRadius: UI_CONFIG.borderRadius.lg,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: UI_CONFIG.spacing.md,
  },
  serverLogoText: {
    fontSize: 32,
  },
  serverName: {
    fontSize: 20,
    fontWeight: 'bold',
    color: UI_CONFIG.colors.text,
    marginBottom: UI_CONFIG.spacing.xs,
    textAlign: 'center',
  },
  serverUrl: {
    fontSize: 14,
    color: UI_CONFIG.colors.textSecondary,
    textAlign: 'center',
  },
  loginSection: {
    flex: 1,
    justifyContent: 'flex-start',
  },
  loginTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: UI_CONFIG.colors.text,
    textAlign: 'center',
    marginBottom: UI_CONFIG.spacing.sm,
  },
  loginSubtitle: {
    fontSize: 16,
    color: UI_CONFIG.colors.textSecondary,
    textAlign: 'center',
    lineHeight: 22,
    marginBottom: UI_CONFIG.spacing.xl,
  },
  loginButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: UI_CONFIG.spacing.md,
    paddingHorizontal: UI_CONFIG.spacing.lg,
    borderRadius: UI_CONFIG.borderRadius.lg,
    gap: UI_CONFIG.spacing.sm,
  },
  disabledButton: {
    opacity: 0.6,
  },
  loginButtonIcon: {
    fontSize: 20,
  },
  loginButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  footer: {
    paddingVertical: UI_CONFIG.spacing.lg,
  },
  backButton: {
    alignItems: 'center',
    paddingVertical: UI_CONFIG.spacing.md,
    marginBottom: UI_CONFIG.spacing.lg,
  },
  backButtonText: {
    fontSize: 16,
    color: UI_CONFIG.colors.primary,
    fontWeight: '500',
  },
  securityNote: {
    backgroundColor: UI_CONFIG.colors.surface,
    paddingVertical: UI_CONFIG.spacing.md,
    paddingHorizontal: UI_CONFIG.spacing.md,
    borderRadius: UI_CONFIG.borderRadius.md,
  },
  securityText: {
    fontSize: 12,
    color: UI_CONFIG.colors.textSecondary,
    textAlign: 'center',
    lineHeight: 16,
  },
})