import React from 'react'
import { View, Text, TouchableOpacity, StyleSheet, Alert } from 'react-native'
import { router } from 'expo-router'
import { SafeAreaView } from 'react-native-safe-area-context'
import { useAuth } from '../../services/auth'
import { UI_CONFIG } from '../../utils/constants'
import type { ServerConfig } from '../../types/server'

export default function DemoScreen() {
  const { login } = useAuth()

  const handleDemoLogin = async () => {
    // Create a mock server config for demo purposes
    const mockServerConfig: ServerConfig = {
      url: 'https://demo.ca-manager.local',
      name: 'Demo CA Manager',
      version: '1.0.0',
      idpType: 'google',
      features: ['certificates', 'mobile_supported'],
      branding: {
        primaryColor: UI_CONFIG.colors.primary,
      },
      lastUsed: new Date()
    }

    try {
      console.log('Demo login - bypassing OAuth for testing')

      // For demo, we'll simulate successful authentication
      // In real implementation, this would go through OAuth
      const mockUser = {
        id: 'demo-user-123',
        email: 'demo@example.com',
        name: 'Demo User',
        picture: null,
        provider: 'google' as const
      }

      // Simulate the login flow without OAuth
      await new Promise(resolve => setTimeout(resolve, 1000)) // Simulate network delay

      // Navigate to main app
      router.replace('/(app)/(tabs)/')

    } catch (error) {
      Alert.alert('Demo Login Failed', 'Something went wrong with the demo login')
    }
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <View style={styles.header}>
          <Text style={styles.title}>🧪 Demo Mode</Text>
          <Text style={styles.subtitle}>
            Test the mobile app UI without a real CA Manager server
          </Text>
        </View>

        <View style={styles.info}>
          <Text style={styles.infoTitle}>Demo Features:</Text>
          <Text style={styles.infoItem}>• Mock server connection</Text>
          <Text style={styles.infoItem}>• Simulated OAuth flow</Text>
          <Text style={styles.infoItem}>• Test certificate data</Text>
          <Text style={styles.infoItem}>• Full UI navigation</Text>
        </View>

        <TouchableOpacity style={styles.demoButton} onPress={handleDemoLogin}>
          <Text style={styles.demoButtonText}>Start Demo Login</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.backButton}
          onPress={() => router.back()}
        >
          <Text style={styles.backButtonText}>← Back to Server Entry</Text>
        </TouchableOpacity>
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
  header: {
    alignItems: 'center',
    marginBottom: UI_CONFIG.spacing.xl,
  },
  title: {
    fontSize: 28,
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
  info: {
    backgroundColor: UI_CONFIG.colors.surface,
    padding: UI_CONFIG.spacing.lg,
    borderRadius: UI_CONFIG.borderRadius.lg,
    marginBottom: UI_CONFIG.spacing.xl,
  },
  infoTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: UI_CONFIG.colors.text,
    marginBottom: UI_CONFIG.spacing.md,
  },
  infoItem: {
    fontSize: 16,
    color: UI_CONFIG.colors.textSecondary,
    marginBottom: UI_CONFIG.spacing.xs,
    lineHeight: 22,
  },
  demoButton: {
    backgroundColor: UI_CONFIG.colors.warning,
    paddingVertical: UI_CONFIG.spacing.md,
    borderRadius: UI_CONFIG.borderRadius.lg,
    alignItems: 'center',
    marginBottom: UI_CONFIG.spacing.lg,
  },
  demoButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  backButton: {
    alignItems: 'center',
    paddingVertical: UI_CONFIG.spacing.md,
  },
  backButtonText: {
    fontSize: 16,
    color: UI_CONFIG.colors.primary,
    fontWeight: '500',
  },
})