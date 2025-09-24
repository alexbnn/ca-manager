import axios, { AxiosError } from 'axios'
import { normalizeUrl } from '../../utils/urlUtils'
import { API_CONFIG } from '../../utils/constants'
import type { ServerConfig, ServerInfo } from '../../types/server'

export class ServerService {
  private createAxiosInstance(baseUrl: string) {
    return axios.create({
      baseURL: baseUrl,
      timeout: API_CONFIG.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    })
  }

  async validateServer(url: string): Promise<ServerConfig> {
    const normalizedUrl = normalizeUrl(url)

    console.log('🔍 Server validation details:', {
      originalUrl: url,
      normalizedUrl,
      endpoint: API_CONFIG.endpoints.info,
      fullUrl: `${normalizedUrl}${API_CONFIG.endpoints.info}`,
      platform: typeof window !== 'undefined' ? 'web' : 'mobile'
    })

    try {
      const api = this.createAxiosInstance(normalizedUrl)
      console.log('📡 Making request to:', `${normalizedUrl}${API_CONFIG.endpoints.info}`)
      const response = await api.get<ServerInfo>(API_CONFIG.endpoints.info)
      console.log('✅ Server response received:', response.status, response.statusText)
      const serverInfo = response.data

      // Validate that the server supports mobile clients
      if (!serverInfo.mobile_supported) {
        throw new Error('Server does not support mobile clients')
      }

      // Validate that server has at least one IDP configured
      if (!serverInfo.idp_types || serverInfo.idp_types.length === 0) {
        throw new Error('Server has no identity providers configured')
      }

      return {
        url: normalizedUrl,
        name: serverInfo.name,
        version: serverInfo.version,
        idpType: serverInfo.idp_types[0] as 'google' | 'microsoft', // Default to first supported
        features: serverInfo.features,
        branding: {
          logo: serverInfo.branding?.logo,
          primaryColor: serverInfo.branding?.primary_color,
        },
        lastUsed: new Date()
      }
    } catch (error) {
      console.error('❌ Server validation failed with error:', {
        error: error,
        message: error instanceof Error ? error.message : 'Unknown error',
        code: error instanceof AxiosError ? error.code : 'N/A',
        status: error instanceof AxiosError ? error.response?.status : 'N/A',
        statusText: error instanceof AxiosError ? error.response?.statusText : 'N/A',
        config: error instanceof AxiosError ? {
          url: error.config?.url,
          method: error.config?.method,
          headers: error.config?.headers,
          timeout: error.config?.timeout
        } : 'N/A'
      })

      if (error instanceof AxiosError) {
        if (error.code === 'ECONNABORTED') {
          throw new Error('Connection timeout. Please check the URL and try again.')
        }
        if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
          throw new Error('Could not connect to server. Please check the URL.')
        }
        if (error.response?.status === 404) {
          throw new Error('CA Manager mobile API not found. Please check the URL.')
        }
        if (error.response && error.response.status >= 500) {
          throw new Error('Server error. Please try again later.')
        }
        // Add specific handling for Network Error
        if (error.message === 'Network Error') {
          throw new Error('Network error - this may be due to certificate issues or network restrictions. Try using a development build instead of Expo Go.')
        }
      }

      if (error instanceof Error) {
        throw error
      }

      throw new Error('Failed to connect to server. Please check the URL and try again.')
    }
  }

  async testConnection(url: string): Promise<boolean> {
    try {
      await this.validateServer(url)
      return true
    } catch {
      return false
    }
  }

  async getQRConfig(url: string, accessToken: string): Promise<any> {
    const normalizedUrl = normalizeUrl(url)

    try {
      const api = this.createAxiosInstance(normalizedUrl)
      const response = await api.get(API_CONFIG.endpoints.qrConfig, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      })

      return response.data
    } catch (error) {
      if (error instanceof AxiosError && error.response?.status === 401) {
        throw new Error('Unauthorized. Please login again.')
      }
      throw new Error('Failed to generate QR configuration')
    }
  }
}

export const serverService = new ServerService()