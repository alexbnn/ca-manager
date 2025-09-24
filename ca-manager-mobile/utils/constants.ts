// App Configuration
export const APP_CONFIG = {
  name: 'CA Manager Mobile',
  version: '1.0.0',
  build: '1',
} as const

// API Configuration
export const API_CONFIG = {
  timeout: 30000, // 30 seconds
  retries: 3,
  endpoints: {
    info: '/api/mobile/info',
    qrConfig: '/api/mobile/qr-config',
    authExchange: '/api/mobile/auth/exchange',
    certificates: '/api/certificates',
    certificateRequest: '/api/certificates/request',
    userProfile: '/api/user/profile',
  }
} as const

// OAuth Configuration
export const OAUTH_CONFIG = {
  google: {
    scopes: ['openid', 'profile', 'email'],
    prompt: 'select_account',
  },
  microsoft: {
    scopes: ['openid', 'profile', 'email', 'User.Read'],
    prompt: 'select_account',
  }
} as const

// Storage Keys
export const STORAGE_KEYS = {
  servers: 'servers',
  activeServer: 'active_server',
  settings: 'app_settings',
  // Token keys are generated dynamically per server
} as const

// UI Constants
export const UI_CONFIG = {
  colors: {
    primary: '#4CAF50',
    secondary: '#2196F3',
    success: '#4CAF50',
    warning: '#FF9800',
    error: '#F44336',
    background: '#FFFFFF',
    surface: '#F5F5F5',
    text: '#212121',
    textSecondary: '#757575',
  },
  spacing: {
    xs: 4,
    sm: 8,
    md: 16,
    lg: 24,
    xl: 32,
  },
  borderRadius: {
    sm: 4,
    md: 8,
    lg: 12,
    xl: 16,
  }
} as const

// Certificate Constants
export const CERTIFICATE_CONFIG = {
  defaultKeySize: 2048,
  defaultValidityDays: 365,
  maxValidityDays: 3650,
  supportedFormats: ['p12', 'pem', 'mobileconfig'] as const,
  statusColors: {
    active: UI_CONFIG.colors.success,
    expired: UI_CONFIG.colors.error,
    revoked: UI_CONFIG.colors.warning,
  }
} as const

// QR Code Configuration
export const QR_CONFIG = {
  version: 1,
  maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
} as const

// Validation Constants
export const VALIDATION = {
  url: {
    minLength: 8,
    maxLength: 2048,
  },
  serverName: {
    minLength: 1,
    maxLength: 100,
  },
  email: {
    maxLength: 254,
  },
  commonName: {
    maxLength: 64,
  }
} as const