import React, { useState } from 'react'
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ActivityIndicator,
  ScrollView,
  Platform,
} from 'react-native'
import { router } from 'expo-router'
import { SafeAreaView } from 'react-native-safe-area-context'
import { serverService } from '../../services/api/servers'
import { isValidUrl, generateUrlSuggestions } from '../../utils/urlUtils'
import { UI_CONFIG, VALIDATION } from '../../utils/constants'
import type { ServerConfig } from '../../types/server'

export default function ServerEntryScreen() {
  const [url, setUrl] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [showQRScanner, setShowQRScanner] = useState(false)
  const [hasPermission, setHasPermission] = useState<boolean | null>(null)

  const suggestions = generateUrlSuggestions(url)

  const handleConnect = async (serverUrl: string = url) => {
    if (!serverUrl.trim()) {
      Alert.alert('Error', 'Please enter a server URL')
      return
    }

    if (!isValidUrl(serverUrl)) {
      Alert.alert('Invalid URL', 'Please enter a valid URL')
      return
    }

    setIsLoading(true)

    try {
      console.log('Attempting to connect to:', serverUrl)
      const serverConfig = await serverService.validateServer(serverUrl)
      console.log('Server validation successful:', serverConfig)

      router.push({
        pathname: '/(auth)/login',
        params: { serverConfig: JSON.stringify(serverConfig) }
      })
    } catch (error) {
      console.error('Server validation failed:', error)
      Alert.alert(
        'Connection Failed',
        error instanceof Error ? error.message : 'Failed to connect to server'
      )
    } finally {
      setIsLoading(false)
    }
  }

  const handleQRScan = async () => {
    Alert.alert('QR Scanner', 'QR code scanning is not available in Expo Go. Please enter the URL manually or use a development build.')
    return
  }

  const handleQRCodeScanned = ({ data }: { data: string }) => {
    setShowQRScanner(false)

    try {
      const qrData = JSON.parse(data)

      if (qrData.type === 'ca-manager-mobile' && qrData.server_url) {
        setUrl(qrData.server_url)
        handleConnect(qrData.server_url)
      } else {
        Alert.alert('Invalid QR Code', 'This QR code is not from CA Manager')
      }
    } catch {
      if (isValidUrl(data)) {
        setUrl(data)
        handleConnect(data)
      } else {
        Alert.alert('Invalid QR Code', 'Could not parse QR code data')
      }
    }
  }

  // QR Scanner UI removed for Expo Go compatibility

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView style={styles.content} keyboardShouldPersistTaps="handled">
        <View style={styles.header}>
          <Text style={styles.title}>Connect to Server</Text>
          <Text style={styles.subtitle}>
            Enter your CA Manager server URL or scan a QR code
          </Text>
        </View>

        <View style={styles.inputSection}>
          <Text style={styles.label}>Server URL</Text>
          <TextInput
            style={styles.input}
            value={url}
            onChangeText={setUrl}
            placeholder="https://ca.example.com"
            placeholderTextColor={UI_CONFIG.colors.textSecondary}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
            returnKeyType="go"
            onSubmitEditing={() => handleConnect()}
          />

          {suggestions.length > 0 && url.length > 2 && (
            <View style={styles.suggestions}>
              <Text style={styles.suggestionsLabel}>Suggestions:</Text>
              {suggestions.slice(0, 3).map((suggestion, index) => (
                <TouchableOpacity
                  key={index}
                  style={styles.suggestion}
                  onPress={() => setUrl(suggestion)}
                >
                  <Text style={styles.suggestionText}>{suggestion}</Text>
                </TouchableOpacity>
              ))}
            </View>
          )}
        </View>

        <View style={styles.actionSection}>
          <TouchableOpacity
            style={[styles.primaryButton, isLoading && styles.disabledButton]}
            onPress={() => handleConnect()}
            disabled={isLoading}
          >
            {isLoading ? (
              <ActivityIndicator color="white" />
            ) : (
              <Text style={styles.primaryButtonText}>Connect</Text>
            )}
          </TouchableOpacity>

          <View style={styles.divider}>
            <View style={styles.dividerLine} />
            <Text style={styles.dividerText}>OR</Text>
            <View style={styles.dividerLine} />
          </View>

          <TouchableOpacity
            style={styles.secondaryButton}
            onPress={handleQRScan}
            disabled={isLoading}
          >
            <Text style={styles.secondaryButtonText}>📱 Scan QR Code</Text>
          </TouchableOpacity>
        </View>

        <View style={styles.helpSection}>
          <Text style={styles.helpText}>
            Need help? Contact your CA Manager administrator for the server URL or QR code.
          </Text>

          <TouchableOpacity
            style={styles.demoButton}
            onPress={() => router.push('/(auth)/demo')}
          >
            <Text style={styles.demoButtonText}>🧪 Try Demo Mode</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
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
  },
  header: {
    paddingTop: UI_CONFIG.spacing.lg,
    paddingBottom: UI_CONFIG.spacing.xl,
    alignItems: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: UI_CONFIG.colors.text,
    marginBottom: UI_CONFIG.spacing.sm,
  },
  subtitle: {
    fontSize: 16,
    color: UI_CONFIG.colors.textSecondary,
    textAlign: 'center',
    lineHeight: 22,
  },
  inputSection: {
    marginBottom: UI_CONFIG.spacing.xl,
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    color: UI_CONFIG.colors.text,
    marginBottom: UI_CONFIG.spacing.sm,
  },
  input: {
    borderWidth: 1,
    borderColor: '#E0E0E0',
    borderRadius: UI_CONFIG.borderRadius.md,
    paddingHorizontal: UI_CONFIG.spacing.md,
    paddingVertical: UI_CONFIG.spacing.md,
    fontSize: 16,
    color: UI_CONFIG.colors.text,
    backgroundColor: 'white',
  },
  suggestions: {
    marginTop: UI_CONFIG.spacing.sm,
  },
  suggestionsLabel: {
    fontSize: 14,
    color: UI_CONFIG.colors.textSecondary,
    marginBottom: UI_CONFIG.spacing.xs,
  },
  suggestion: {
    paddingVertical: UI_CONFIG.spacing.xs,
    paddingHorizontal: UI_CONFIG.spacing.sm,
    backgroundColor: UI_CONFIG.colors.surface,
    borderRadius: UI_CONFIG.borderRadius.sm,
    marginBottom: UI_CONFIG.spacing.xs,
  },
  suggestionText: {
    fontSize: 14,
    color: UI_CONFIG.colors.primary,
  },
  actionSection: {
    gap: UI_CONFIG.spacing.lg,
  },
  primaryButton: {
    backgroundColor: UI_CONFIG.colors.primary,
    paddingVertical: UI_CONFIG.spacing.md,
    borderRadius: UI_CONFIG.borderRadius.lg,
    alignItems: 'center',
  },
  disabledButton: {
    opacity: 0.6,
  },
  primaryButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  divider: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: UI_CONFIG.spacing.md,
  },
  dividerLine: {
    flex: 1,
    height: 1,
    backgroundColor: '#E0E0E0',
  },
  dividerText: {
    fontSize: 14,
    color: UI_CONFIG.colors.textSecondary,
    fontWeight: '500',
  },
  secondaryButton: {
    borderWidth: 1,
    borderColor: UI_CONFIG.colors.primary,
    paddingVertical: UI_CONFIG.spacing.md,
    borderRadius: UI_CONFIG.borderRadius.lg,
    alignItems: 'center',
  },
  secondaryButtonText: {
    color: UI_CONFIG.colors.primary,
    fontSize: 16,
    fontWeight: '600',
  },
  helpSection: {
    marginTop: UI_CONFIG.spacing.xl,
    paddingVertical: UI_CONFIG.spacing.lg,
    alignItems: 'center',
  },
  helpText: {
    fontSize: 14,
    color: UI_CONFIG.colors.textSecondary,
    textAlign: 'center',
    lineHeight: 20,
    marginBottom: UI_CONFIG.spacing.lg,
  },
  demoButton: {
    backgroundColor: UI_CONFIG.colors.warning,
    paddingVertical: UI_CONFIG.spacing.sm,
    paddingHorizontal: UI_CONFIG.spacing.lg,
    borderRadius: UI_CONFIG.borderRadius.lg,
    alignItems: 'center',
  },
  demoButtonText: {
    color: 'white',
    fontSize: 14,
    fontWeight: '600',
  },
  scannerContainer: {
    flex: 1,
  },
  scannerOverlay: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.5)',
  },
  scannerFrame: {
    width: 200,
    height: 200,
    borderWidth: 2,
    borderColor: 'white',
    borderRadius: UI_CONFIG.borderRadius.lg,
    backgroundColor: 'transparent',
  },
  scannerText: {
    color: 'white',
    fontSize: 16,
    textAlign: 'center',
    marginTop: UI_CONFIG.spacing.lg,
    paddingHorizontal: UI_CONFIG.spacing.lg,
  },
  cancelButton: {
    backgroundColor: 'rgba(255,255,255,0.2)',
    paddingVertical: UI_CONFIG.spacing.md,
    paddingHorizontal: UI_CONFIG.spacing.lg,
    borderRadius: UI_CONFIG.borderRadius.lg,
    marginTop: UI_CONFIG.spacing.xl,
  },
  cancelButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
})