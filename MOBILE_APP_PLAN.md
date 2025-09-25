# CA Manager Mobile App Development Plan

## Overview
Native mobile application for CA Manager that provides certificate management capabilities through iOS and Android devices, with enterprise IDP authentication (Google Workspace/Microsoft Entra ID).

## Technology Stack
- **Framework**: React Native with Expo
- **Authentication**: Expo AuthSession (OAuth2/OIDC)
- **Storage**: Expo SecureStore (encrypted token storage)
- **API**: Existing CA Manager REST API
- **Languages**: TypeScript, React Native
- **Platforms**: iOS 14+, Android 8+

## Architecture

### Multi-Tenant Discovery Flow
```
Mobile App → Discovery Service → Tenant API → Certificate Services
```

### Tenant Discovery Options

#### Option 1: Email Domain Discovery (RECOMMENDED)
1. User enters email: `user@company.com`
2. Extract domain: `company.com`
3. Query discovery service: `https://discovery.camanager.cloud/api/tenant?domain=company.com`
4. Response: `{"api_url": "https://ca.company.com", "idp": "google", "tenant_id": "abc123"}`
5. Configure app with tenant details
6. Proceed with OAuth flow

#### Option 2: Manual URL Entry
- User manually enters CA Manager URL
- Store in secure storage
- Simple but less user-friendly

#### Option 3: QR Code Provisioning
- Admin generates QR from web portal
- Contains: `{"url": "https://ca.company.com", "tenant": "company", "idp": "google"}`
- One-tap setup for users

#### Option 4: MDM Configuration
- Pre-configure via MDM deployment
- iOS: Managed App Configuration
- Android: Managed Configurations

### Data Models

```typescript
interface TenantConfig {
  domain: string
  apiUrl: string
  idpType: 'google' | 'microsoft' | 'okta'
  idpClientId?: string
  customBranding?: {
    logo?: string
    primaryColor?: string
    companyName?: string
  }
}

interface UserSession {
  tenant: TenantConfig
  accessToken: string
  refreshToken: string
  idToken: string
  expiresAt: number
  userProfile: {
    email: string
    name: string
    picture?: string
  }
}
```

## Implementation Phases

### Phase 1: Core Setup & Authentication (Week 1-2)
- [ ] Create Expo project with TypeScript
- [ ] Implement tenant discovery mechanism
- [ ] OAuth2 authentication (Google & Microsoft)
- [ ] Secure token storage and refresh
- [ ] Basic navigation structure

### Phase 2: Certificate Management (Week 3-4)
- [ ] List certificates (active/expired/revoked)
- [ ] Certificate details view
- [ ] Request new certificate
- [ ] Revoke certificate
- [ ] Search and filter functionality

### Phase 3: Certificate Installation (Week 5)
- [ ] P12 download and installation flow
- [ ] Mobileconfig profile installation (iOS)
- [ ] Android KeyChain integration
- [ ] WiFi profile auto-configuration

### Phase 4: Advanced Features (Week 6)
- [ ] Push notifications for expiry
- [ ] Biometric authentication
- [ ] Offline certificate viewing
- [ ] QR code scanner for SCEP
- [ ] Certificate sharing

### Phase 5: Enterprise Features (Week 7)
- [ ] MDM integration
- [ ] Multiple account support
- [ ] Admin notifications
- [ ] Audit log viewing

## Project Structure

```
ca-manager-mobile/
├── app/
│   ├── (auth)/
│   │   ├── _layout.tsx
│   │   ├── welcome.tsx
│   │   ├── discovery.tsx
│   │   ├── login.tsx
│   │   └── callback.tsx
│   ├── (app)/
│   │   ├── _layout.tsx
│   │   ├── (tabs)/
│   │   │   ├── certificates.tsx
│   │   │   ├── request.tsx
│   │   │   ├── profile.tsx
│   │   │   └── settings.tsx
│   │   └── certificate/
│   │       └── [id].tsx
│   └── _layout.tsx
├── components/
│   ├── CertificateCard.tsx
│   ├── CertificateList.tsx
│   ├── IDPButton.tsx
│   ├── TenantSelector.tsx
│   └── LoadingScreen.tsx
├── services/
│   ├── auth/
│   │   ├── google.ts
│   │   ├── microsoft.ts
│   │   └── tokenManager.ts
│   ├── api/
│   │   ├── client.ts
│   │   ├── certificates.ts
│   │   └── tenant.ts
│   └── discovery/
│       └── tenantDiscovery.ts
├── hooks/
│   ├── useAuth.ts
│   ├── useCertificates.ts
│   └── useTenant.ts
├── utils/
│   ├── certificate.ts
│   ├── storage.ts
│   └── platform.ts
├── constants/
│   ├── api.ts
│   └── config.ts
├── app.json
├── eas.json
└── package.json
```

## API Endpoints Required

### Discovery Service
```
GET /api/tenant?domain={domain}
GET /api/tenant/{tenant_id}/branding
```

### Existing CA Manager API
```
GET /api/certificates
POST /api/certificates/request
GET /api/certificates/{id}
DELETE /api/certificates/{id}/revoke
GET /api/certificates/{id}/download/p12
GET /api/certificates/{id}/download/mobileconfig
GET /api/user/profile
```

## Security Considerations

1. **Authentication**
   - OAuth2/OIDC only (no password storage)
   - Biometric lock for app access
   - Token refresh before expiry

2. **Certificate Security**
   - Private keys never stored in app
   - P12 passwords generated server-side
   - Certificates installed to system keychain

3. **Data Protection**
   - All tokens in SecureStore (encrypted)
   - API calls over HTTPS only
   - Certificate pinning for API calls

4. **Privacy**
   - Minimal data collection
   - No analytics without consent
   - GDPR/CCPA compliant

## Platform-Specific Features

### iOS
- Mobileconfig installation via Safari
- Keychain integration
- Face ID/Touch ID
- Managed App Configuration
- Universal Links

### Android
- KeyStore/KeyChain API
- Work Profile support
- Fingerprint authentication
- App Links
- Custom certificate installer

## Deployment Strategy

### App Store
1. Apple Developer account required
2. TestFlight beta testing
3. App Store review process
4. Enterprise distribution option

### Google Play
1. Google Play Console account
2. Internal testing track
3. Staged rollout
4. Managed Google Play for enterprise

## Discovery Service Implementation

### Simple Discovery Service (Node.js/Express)
```javascript
// discovery-service/index.js
const tenants = {
  "bearnetworks.io": {
    api_url: "https://ca.bearnetworks.io",
    idp_type: "google",
    tenant_id: "bear001"
  },
  "contoso.com": {
    api_url: "https://pki.contoso.com",
    idp_type: "microsoft",
    tenant_id: "cont002"
  }
};

app.get('/api/tenant', (req, res) => {
  const domain = req.query.domain;
  const tenant = tenants[domain];

  if (tenant) {
    res.json(tenant);
  } else {
    res.status(404).json({ error: 'Tenant not found' });
  }
});
```

## MVP Features (Version 1.0)
1. Manual URL configuration
2. IDP authentication (Google/Microsoft)
3. View certificates
4. Download P12/mobileconfig
5. Basic certificate request

## Future Enhancements
- SCEP enrollment
- Certificate templates
- Approval workflows
- Team management
- Usage analytics
- Compliance reporting

## Detailed Implementation Plan

### **Phase 1: Project Setup & Infrastructure (Days 1-3)**

#### Day 1: Project Initialization
```bash
# Create Expo project
npx create-expo-app@latest ca-manager-mobile --template tabs --typescript
cd ca-manager-mobile

# Install core dependencies
npx expo install expo-auth-session expo-crypto expo-secure-store
npx expo install expo-barcode-scanner expo-camera expo-linking
npx expo install @react-navigation/native @react-navigation/stack
npm install axios react-query @tanstack/react-query
npm install react-hook-form zod @hookform/resolvers
```

#### Day 2: Project Structure & Navigation
```
ca-manager-mobile/
├── app/
│   ├── (auth)/
│   │   ├── _layout.tsx          # Auth stack navigator
│   │   ├── welcome.tsx          # Welcome/landing screen
│   │   ├── setup.tsx            # URL entry or QR scan choice
│   │   ├── url-entry.tsx        # Manual URL entry
│   │   ├── qr-scanner.tsx       # QR code scanner
│   │   ├── server-confirm.tsx   # Confirm server details
│   │   └── oauth-callback.tsx   # OAuth redirect handler
│   ├── (app)/
│   │   ├── _layout.tsx          # Main app tabs
│   │   ├── (tabs)/
│   │   │   ├── certificates.tsx # Certificate list
│   │   │   ├── request.tsx      # New certificate request
│   │   │   ├── profile.tsx      # User profile
│   │   │   └── settings.tsx     # App settings
│   │   └── certificate/
│   │       └── [id].tsx         # Certificate details
│   └── _layout.tsx              # Root layout with auth check
├── components/
│   ├── ui/                      # Reusable UI components
│   │   ├── Button.tsx
│   │   ├── Input.tsx
│   │   ├── Card.tsx
│   │   └── LoadingSpinner.tsx
│   ├── CertificateCard.tsx      # Certificate list item
│   ├── CertificateStatus.tsx    # Status indicator
│   ├── ServerSelector.tsx       # Multi-server switcher
│   └── QRScanner.tsx           # QR scanner component
├── hooks/
│   ├── useAuth.ts              # Authentication hook
│   ├── useServers.ts           # Server management
│   ├── useCertificates.ts      # Certificate operations
│   └── useSecureStorage.ts     # Secure storage wrapper
├── services/
│   ├── auth/
│   │   ├── authService.ts      # OAuth flow management
│   │   ├── tokenManager.ts     # Token storage/refresh
│   │   └── providers/
│   │       ├── google.ts       # Google OAuth config
│   │       └── microsoft.ts    # Microsoft OAuth config
│   ├── api/
│   │   ├── client.ts           # HTTP client with auth
│   │   ├── certificates.ts     # Certificate API calls
│   │   ├── servers.ts          # Server validation
│   │   └── types.ts            # API type definitions
│   └── storage/
│       ├── secureStorage.ts    # Secure token storage
│       └── appStorage.ts       # App configuration storage
├── utils/
│   ├── validation.ts           # Form validation schemas
│   ├── urlUtils.ts             # URL normalization
│   ├── certificateUtils.ts     # Certificate helpers
│   └── constants.ts            # App constants
└── types/
    ├── auth.ts                 # Auth-related types
    ├── certificate.ts          # Certificate types
    └── server.ts               # Server configuration types
```

#### Day 3: Core Types & Utilities
```typescript
// types/server.ts
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

// types/auth.ts
export interface AuthTokens {
  accessToken: string
  refreshToken: string
  idToken: string
  expiresAt: number
}

export interface UserProfile {
  email: string
  name: string
  picture?: string
}

// types/certificate.ts
export interface Certificate {
  id: string
  commonName: string
  status: 'active' | 'expired' | 'revoked'
  issuedDate: string
  expiryDate: string
  serialNumber: string
  issuer: string
}
```

### **Phase 2: Authentication System (Days 4-7)**

#### Day 4: Server Discovery & Validation
```typescript
// services/api/servers.ts
export class ServerService {
  async validateServer(url: string): Promise<ServerConfig> {
    const normalizedUrl = this.normalizeUrl(url);

    try {
      const response = await fetch(`${normalizedUrl}/api/mobile/info`);
      const serverInfo = await response.json();

      if (!serverInfo.mobile_supported) {
        throw new Error('Server does not support mobile clients');
      }

      return {
        url: normalizedUrl,
        name: serverInfo.name,
        version: serverInfo.version,
        idpType: serverInfo.idp_types[0], // Default to first supported
        features: serverInfo.features,
        branding: serverInfo.branding,
        lastUsed: new Date()
      };
    } catch (error) {
      throw new Error('Could not connect to server');
    }
  }

  private normalizeUrl(url: string): string {
    if (!url.startsWith('http')) {
      url = `https://${url}`;
    }
    return url.replace(/\/$/, ''); // Remove trailing slash
  }
}
```

#### Day 5: OAuth Implementation
```typescript
// services/auth/authService.ts
import * as AuthSession from 'expo-auth-session';
import * as WebBrowser from 'expo-web-browser';

WebBrowser.maybeCompleteAuthSession();

export class AuthService {
  private redirectUri = AuthSession.makeRedirectUri({ useProxy: true });

  async authenticateWithGoogle(serverUrl: string): Promise<AuthTokens> {
    const discovery = AuthSession.useAutoDiscovery('https://accounts.google.com');

    const [request, response, promptAsync] = AuthSession.useAuthRequest(
      {
        clientId: 'YOUR_GOOGLE_CLIENT_ID',
        scopes: ['openid', 'profile', 'email'],
        redirectUri: this.redirectUri,
      },
      discovery
    );

    const result = await promptAsync();

    if (result.type === 'success') {
      return this.exchangeCodeForTokens(result.params.code, serverUrl);
    }

    throw new Error('Authentication cancelled');
  }

  async authenticateWithMicrosoft(serverUrl: string): Promise<AuthTokens> {
    // Similar implementation for Microsoft
  }

  private async exchangeCodeForTokens(code: string, serverUrl: string): Promise<AuthTokens> {
    const response = await fetch(`${serverUrl}/api/mobile/auth/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, redirectUri: this.redirectUri })
    });

    return response.json();
  }
}
```

#### Day 6: Token Management
```typescript
// services/auth/tokenManager.ts
import * as SecureStore from 'expo-secure-store';

export class TokenManager {
  private static readonly ACCESS_TOKEN_KEY = 'access_token';
  private static readonly REFRESH_TOKEN_KEY = 'refresh_token';
  private static readonly EXPIRES_AT_KEY = 'expires_at';

  async saveTokens(tokens: AuthTokens, serverUrl: string): Promise<void> {
    const prefix = this.getKeyPrefix(serverUrl);

    await Promise.all([
      SecureStore.setItemAsync(`${prefix}_${this.ACCESS_TOKEN_KEY}`, tokens.accessToken),
      SecureStore.setItemAsync(`${prefix}_${this.REFRESH_TOKEN_KEY}`, tokens.refreshToken),
      SecureStore.setItemAsync(`${prefix}_${this.EXPIRES_AT_KEY}`, tokens.expiresAt.toString())
    ]);
  }

  async getValidAccessToken(serverUrl: string): Promise<string | null> {
    const prefix = this.getKeyPrefix(serverUrl);
    const expiresAt = await SecureStore.getItemAsync(`${prefix}_${this.EXPIRES_AT_KEY}`);

    if (!expiresAt || Date.now() >= parseInt(expiresAt) - 60000) { // 1 min buffer
      return await this.refreshAccessToken(serverUrl);
    }

    return await SecureStore.getItemAsync(`${prefix}_${this.ACCESS_TOKEN_KEY}`);
  }

  private getKeyPrefix(serverUrl: string): string {
    return Buffer.from(serverUrl).toString('base64').slice(0, 10);
  }
}
```

#### Day 7: Auth Context & Hooks
```typescript
// hooks/useAuth.ts
import { createContext, useContext, useReducer } from 'react';

interface AuthState {
  isAuthenticated: boolean
  user: UserProfile | null
  serverConfig: ServerConfig | null
  loading: boolean
}

export const useAuth = () => {
  const login = async (serverUrl: string, idpType: string) => {
    setLoading(true);
    try {
      const tokens = await authService.authenticate(serverUrl, idpType);
      await tokenManager.saveTokens(tokens, serverUrl);

      const userProfile = await apiClient.getUserProfile();
      setState({ isAuthenticated: true, user: userProfile, loading: false });
    } catch (error) {
      setError(error.message);
      setLoading(false);
    }
  };

  const logout = async () => {
    await tokenManager.clearTokens();
    setState({ isAuthenticated: false, user: null, loading: false });
  };

  return { login, logout, ...state };
};
```

### **Phase 3: Core UI & Certificate Management (Days 8-12)**

#### Day 8: Setup Screens (URL Entry + QR Scanner)
```typescript
// app/(auth)/url-entry.tsx
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const urlSchema = z.object({
  url: z.string().url('Please enter a valid URL')
});

export default function URLEntryScreen() {
  const { control, handleSubmit, formState: { errors } } = useForm({
    resolver: zodResolver(urlSchema)
  });

  const onSubmit = async (data: { url: string }) => {
    try {
      const serverConfig = await serverService.validateServer(data.url);
      router.push({
        pathname: '/server-confirm',
        params: { serverConfig: JSON.stringify(serverConfig) }
      });
    } catch (error) {
      setError(error.message);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Enter Server URL</Text>

      <Controller
        control={control}
        name="url"
        render={({ field }) => (
          <TextInput
            {...field}
            placeholder="https://ca.yourcompany.com"
            style={styles.input}
            autoCapitalize="none"
            autoCorrect={false}
          />
        )}
      />

      {errors.url && <Text style={styles.error}>{errors.url.message}</Text>}

      <Button title="Test Connection" onPress={handleSubmit(onSubmit)} />
    </View>
  );
}
```

#### Day 9: QR Scanner Implementation
```typescript
// components/QRScanner.tsx
import { BarCodeScanner } from 'expo-barcode-scanner';

export function QRScanner({ onScan }: { onScan: (data: any) => void }) {
  const [hasPermission, setHasPermission] = useState<boolean | null>(null);

  useEffect(() => {
    (async () => {
      const { status } = await BarCodeScanner.requestPermissionsAsync();
      setHasPermission(status === 'granted');
    })();
  }, []);

  const handleBarCodeScanned = ({ data }: { data: string }) => {
    try {
      const config = JSON.parse(data);
      if (config.v === 1 && config.url) {
        onScan(config);
      } else {
        throw new Error('Invalid QR format');
      }
    } catch (error) {
      Alert.alert('Error', 'Invalid QR code format');
    }
  };

  if (hasPermission === null) return <Text>Requesting camera permission</Text>;
  if (hasPermission === false) return <Text>No access to camera</Text>;

  return (
    <View style={styles.container}>
      <BarCodeScanner
        onBarCodeScanned={handleBarCodeScanned}
        style={StyleSheet.absoluteFillObject}
      />
      <View style={styles.overlay}>
        <Text style={styles.instruction}>
          Point camera at QR code from your CA Manager
        </Text>
      </View>
    </View>
  );
}
```

#### Day 10-11: Certificate Management Screens
#### Day 12: Certificate Details & Actions

### **Phase 4: Backend API Integration (Days 13-15)**

#### Day 13: Add Mobile Endpoints to CA Manager
```python
# Add to app.py
@app.route('/api/mobile/info', methods=['GET'])
def mobile_info():
    return jsonify({
        'name': get_system_config('organization_name', 'CA Manager'),
        'version': APP_VERSION,
        'idp_types': [get_system_config('idp_type', 'google')],
        'features': ['scep', 'ocsp', 'mobileconfig'],
        'mobile_supported': True,
        'branding': {
            'logo': '/static/logo.png',
            'primary_color': get_system_config('primary_color', '#4CAF50')
        }
    })

@app.route('/api/mobile/qr-config', methods=['GET'])
@require_auth
def mobile_qr_config():
    return jsonify({
        'v': 1,
        'url': request.host_url.rstrip('/'),
        'name': get_system_config('organization_name', 'CA Manager'),
        'logo': f"{request.host_url}static/logo.png",
        'idp': get_system_config('idp_type', 'google'),
        'timestamp': int(time.time())
    })
```

#### Day 14-15: Certificate API Integration & File Downloads

### **Phase 5: Certificate Installation (Days 16-18)**

#### Day 16-17: iOS Mobileconfig Flow
#### Day 18: Android Certificate Installation

### **Phase 6: Testing & Polish (Days 19-21)**

#### Day 19: Device Testing (iOS/Android)
#### Day 20: Error Handling & Edge Cases
#### Day 21: UI Polish & Accessibility

### **Phase 7: Deployment Preparation (Days 22-24)**

#### Day 22: Build Configuration (EAS Build)
#### Day 23: App Store Preparation
#### Day 24: Documentation & Deployment

## Development Timeline
- **Week 1 (Days 1-7)**: Setup & Authentication
- **Week 2 (Days 8-14)**: UI & API Integration
- **Week 3 (Days 15-21)**: Certificate Features & Testing
- **Week 4 (Days 22-24)**: Deployment & Documentation

## Success Metrics
- User adoption rate
- Certificate installation success rate
- Time to certificate (request → installation)
- User satisfaction score
- Support ticket reduction

## Notes
- Start with manual URL entry for MVP
- Add discovery service in v1.1
- Consider white-label options for enterprise
- Plan for offline mode in v2.0