import * as SecureStore from 'expo-secure-store'
import { Platform } from 'react-native'

// Helper to determine if we're running on web
const isWeb = Platform.OS === 'web'

// Storage wrapper that works on both web and mobile
export const storageHelper = {
  async setItem(key: string, value: string): Promise<void> {
    if (isWeb) {
      // Use localStorage for web
      try {
        if (typeof window !== 'undefined' && window.localStorage) {
          window.localStorage.setItem(key, value)
        }
      } catch (error) {
        console.warn('Failed to save to localStorage:', error)
      }
    } else {
      // Use SecureStore for mobile
      try {
        await SecureStore.setItemAsync(key, value)
      } catch (error) {
        console.warn('Failed to save to SecureStore:', error)
      }
    }
  },

  async getItem(key: string): Promise<string | null> {
    if (isWeb) {
      // Use localStorage for web
      try {
        if (typeof window !== 'undefined' && window.localStorage) {
          return window.localStorage.getItem(key)
        }
      } catch (error) {
        console.warn('Failed to read from localStorage:', error)
      }
      return null
    } else {
      // Use SecureStore for mobile
      try {
        return await SecureStore.getItemAsync(key)
      } catch (error) {
        console.warn('Failed to read from SecureStore:', error)
        return null
      }
    }
  },

  async deleteItem(key: string): Promise<void> {
    if (isWeb) {
      // Use localStorage for web
      try {
        if (typeof window !== 'undefined' && window.localStorage) {
          window.localStorage.removeItem(key)
        }
      } catch (error) {
        console.warn('Failed to delete from localStorage:', error)
      }
    } else {
      // Use SecureStore for mobile
      try {
        await SecureStore.deleteItemAsync(key)
      } catch (error) {
        console.warn('Failed to delete from SecureStore:', error)
      }
    }
  }
}