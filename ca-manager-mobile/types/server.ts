export interface ServerConfig {
  url: string
  name: string
  version: string
  idpType: 'google' | 'microsoft'
  features: string[]
  branding: {
    logo?: string
    primaryColor?: string
  }
  lastUsed: Date
}

export interface ServerInfo {
  name: string
  version: string
  idp_types: string[]
  features: string[]
  mobile_supported: boolean
  branding: {
    logo: string
    primary_color: string
  }
}

export interface QRConfig {
  v: number
  url: string
  name: string
  logo: string
  idp: string
  timestamp: number
}

export interface AppConfig {
  servers: {
    [url: string]: {
      name: string
      lastUsed: Date
      idpType: string
      version: string
      userEmail?: string
    }
  }
  activeServer: string
  settings: {
    biometricEnabled: boolean
    notificationsEnabled: boolean
  }
}