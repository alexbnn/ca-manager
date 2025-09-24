import React from 'react'
import { View, Text, TouchableOpacity, StyleSheet, Image } from 'react-native'
import { router } from 'expo-router'
import { SafeAreaView } from 'react-native-safe-area-context'
import { UI_CONFIG } from '../../utils/constants'

export default function WelcomeScreen() {
  const handleGetStarted = () => {
    router.push('/(auth)/server-entry')
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <View style={styles.logoSection}>
          <View style={styles.logoPlaceholder}>
            <Text style={styles.logoText}>🔐</Text>
          </View>
          <Text style={styles.title}>CA Manager Mobile</Text>
          <Text style={styles.subtitle}>Secure Certificate Management</Text>
        </View>

        <View style={styles.featuresSection}>
          <FeatureItem
            icon="🔒"
            title="Secure Authentication"
            description="Login with Google Workspace or Microsoft Entra ID"
          />
          <FeatureItem
            icon="📱"
            title="QR Code Setup"
            description="Quick setup by scanning QR codes from your CA Manager"
          />
          <FeatureItem
            icon="📋"
            title="Certificate Management"
            description="View, download, and manage your certificates on the go"
          />
        </View>

        <View style={styles.actionSection}>
          <TouchableOpacity style={styles.primaryButton} onPress={handleGetStarted}>
            <Text style={styles.primaryButtonText}>Get Started</Text>
          </TouchableOpacity>
        </View>
      </View>
    </SafeAreaView>
  )
}

function FeatureItem({ icon, title, description }: { icon: string; title: string; description: string }) {
  return (
    <View style={styles.featureItem}>
      <Text style={styles.featureIcon}>{icon}</Text>
      <View style={styles.featureContent}>
        <Text style={styles.featureTitle}>{title}</Text>
        <Text style={styles.featureDescription}>{description}</Text>
      </View>
    </View>
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
  logoSection: {
    alignItems: 'center',
    marginBottom: UI_CONFIG.spacing.xl * 2,
  },
  logoPlaceholder: {
    width: 80,
    height: 80,
    backgroundColor: UI_CONFIG.colors.primary,
    borderRadius: 20,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: UI_CONFIG.spacing.lg,
  },
  logoText: {
    fontSize: 40,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: UI_CONFIG.colors.text,
    marginBottom: UI_CONFIG.spacing.sm,
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 16,
    color: UI_CONFIG.colors.textSecondary,
    textAlign: 'center',
  },
  featuresSection: {
    flex: 1,
    gap: UI_CONFIG.spacing.lg,
  },
  featureItem: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: UI_CONFIG.spacing.md,
  },
  featureIcon: {
    fontSize: 24,
    width: 32,
    textAlign: 'center',
  },
  featureContent: {
    flex: 1,
  },
  featureTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: UI_CONFIG.colors.text,
    marginBottom: UI_CONFIG.spacing.xs,
  },
  featureDescription: {
    fontSize: 14,
    color: UI_CONFIG.colors.textSecondary,
    lineHeight: 20,
  },
  actionSection: {
    paddingVertical: UI_CONFIG.spacing.xl,
  },
  primaryButton: {
    backgroundColor: UI_CONFIG.colors.primary,
    paddingVertical: UI_CONFIG.spacing.md,
    paddingHorizontal: UI_CONFIG.spacing.lg,
    borderRadius: UI_CONFIG.borderRadius.lg,
    alignItems: 'center',
  },
  primaryButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
})