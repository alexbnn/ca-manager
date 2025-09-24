import React, { useEffect } from 'react'
import { View, ActivityIndicator, StyleSheet } from 'react-native'
import { router } from 'expo-router'
import { useAuth } from '../services/auth'
import { UI_CONFIG } from '../utils/constants'

export default function IndexScreen() {
  const { isAuthenticated, isLoading } = useAuth()

  useEffect(() => {
    if (!isLoading) {
      if (isAuthenticated) {
        router.replace('/(app)/(tabs)/')
      } else {
        router.replace('/(auth)/welcome')
      }
    }
  }, [isAuthenticated, isLoading])

  return (
    <View style={styles.container}>
      <ActivityIndicator size="large" color={UI_CONFIG.colors.primary} />
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: UI_CONFIG.colors.background,
  },
})