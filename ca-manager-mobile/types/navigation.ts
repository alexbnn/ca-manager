import type { ServerConfig } from './server'

export type AuthStackParamList = {
  welcome: undefined
  setup: undefined
  'url-entry': undefined
  'qr-scanner': undefined
  'server-confirm': { serverConfig: string }
  'oauth-callback': { code: string; state?: string }
}

export type AppTabParamList = {
  certificates: undefined
  request: undefined
  profile: undefined
  settings: undefined
}

export type AppStackParamList = {
  '(tabs)': undefined
  'certificate/[id]': { id: string }
  modal: { type: string; data?: any }
}

export type RootStackParamList = {
  '(auth)': undefined
  '(app)': undefined
}

declare global {
  namespace ReactNavigation {
    interface RootParamList extends RootStackParamList {}
  }
}