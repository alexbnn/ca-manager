import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  ScrollView,
  Alert,
  Platform,
  ActivityIndicator,
  Linking,
  TouchableOpacity,
} from 'react-native';
import * as FileSystem from 'expo-file-system';
import * as Sharing from 'expo-sharing';
import Constants from 'expo-constants';
import * as Network from 'expo-network';

import { Text, View } from '../../../components/Themed';
import { useAuth } from '../../../services/auth';

interface DeviceInfo {
  username: string;
  deviceOS: string;
  hostname: string;
  macAddress?: string;
  deviceModel: string;
  osVersion: string;
}

interface RegistrationResult {
  success: boolean;
  wifiSSID: string;
  p12DownloadUrl: string;
  mobileconfigDownloadUrl?: string;
  certificateInfo: {
    commonName: string;
    validFrom: string;
    validTo: string;
  };
}

export default function RegisterScreen() {
  const { user, serverConfig, accessToken } = useAuth();
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo | null>(null);
  const [isRegistering, setIsRegistering] = useState(false);
  const [registrationResult, setRegistrationResult] = useState<RegistrationResult | null>(null);

  useEffect(() => {
    collectDeviceInfo();
  }, []);

  const collectDeviceInfo = async () => {
    try {
      // Get network info (MAC address may not be available due to privacy restrictions)
      const networkState = await Network.getNetworkStateAsync();

      const info: DeviceInfo = {
        username: user?.email || '',
        deviceOS: Platform.OS,
        hostname: Constants.deviceName || 'Unknown Device',
        deviceModel: Constants.platform?.ios?.model || Constants.platform?.android?.modelName || 'Unknown',
        osVersion: Platform.Version.toString(),
      };

      // Note: MAC address is typically not accessible on modern mobile devices for privacy reasons
      // We'll note this limitation in the UI
      setDeviceInfo(info);
    } catch (error) {
      console.error('Error collecting device info:', error);
      Alert.alert('Error', 'Failed to collect device information');
    }
  };

  const registerDevice = async () => {
    console.log('Register button pressed');
    console.log('Auth status:', { user: !!user, serverConfig: !!serverConfig, accessToken: !!accessToken });

    if (!user) {
      Alert.alert('Authentication Required', 'No user found. Please login first.');
      return;
    }

    if (!serverConfig) {
      Alert.alert('Configuration Error', 'Server configuration not found. Please check your connection.');
      return;
    }

    if (!accessToken) {
      Alert.alert('Token Missing', 'Access token not found. Please logout and login again to refresh your authentication.');
      return;
    }

    if (!deviceInfo) {
      Alert.alert('Error', 'Device information not collected yet. Please wait and try again.');
      return;
    }

    setIsRegistering(true);

    try {
      console.log('Making registration request to:', `${serverConfig.url}/api/mobile/register-device`);

      const response = await fetch(`${serverConfig.url}/api/mobile/register-device`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify(deviceInfo),
      });

      console.log('Registration response status:', response.status);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('Registration error response:', errorText);
        throw new Error(`Registration failed: ${response.statusText} - ${errorText}`);
      }

      const result: RegistrationResult = await response.json();
      console.log('Registration successful:', result);
      setRegistrationResult(result);

    } catch (error) {
      console.error('Device registration failed:', error);
      Alert.alert('Registration Failed', error instanceof Error ? error.message : 'Unknown error occurred');
    } finally {
      setIsRegistering(false);
    }
  };

  const downloadFile = async (url: string, filename: string) => {
    try {
      const downloadResumable = FileSystem.createDownloadResumable(
        url,
        FileSystem.documentDirectory + filename,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
          },
        }
      );

      const result = await downloadResumable.downloadAsync();

      if (result?.uri) {
        if (await Sharing.isAvailableAsync()) {
          await Sharing.shareAsync(result.uri);
        } else {
          Alert.alert('Download Complete', `File saved to: ${result.uri}`);
        }
      }
    } catch (error) {
      console.error('Download failed:', error);
      Alert.alert('Download Failed', 'Could not download the file');
    }
  };

  const openMobileConfigGuide = () => {
    Alert.alert(
      'Mobile Configuration Installation',
      'To install the mobile configuration:\n\n1. Download the .mobileconfig file\n2. Open it from Files app or share sheet\n3. Go to Settings > General > Profiles\n4. Install the profile\n5. Enter the certificate password: 123456\n\nThe profile will configure your Wi-Fi settings automatically.',
      [{ text: 'OK' }]
    );
  };

  if (!deviceInfo) {
    return (
      <View style={styles.container}>
        <ActivityIndicator size="large" />
        <Text>Collecting device information...</Text>
      </View>
    );
  }

  return (
    <ScrollView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Register Device for Network Access</Text>
        <Text style={styles.subtitle}>
          This will create a certificate for your device and configure network access
        </Text>
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Device Information</Text>

        <View style={styles.infoRow}>
          <Text style={styles.label}>Username:</Text>
          <Text style={styles.value}>{deviceInfo.username}</Text>
        </View>

        <View style={styles.infoRow}>
          <Text style={styles.label}>Device OS:</Text>
          <Text style={styles.value}>{deviceInfo.deviceOS} {deviceInfo.osVersion}</Text>
        </View>

        <View style={styles.infoRow}>
          <Text style={styles.label}>Device Name:</Text>
          <Text style={styles.value}>{deviceInfo.hostname}</Text>
        </View>

        <View style={styles.infoRow}>
          <Text style={styles.label}>Device Model:</Text>
          <Text style={styles.value}>{deviceInfo.deviceModel}</Text>
        </View>

        <View style={styles.infoRow}>
          <Text style={styles.label}>MAC Address:</Text>
          <Text style={styles.value}>
            {deviceInfo.macAddress || 'Not available (privacy protected)'}
          </Text>
        </View>
      </View>

      {!registrationResult ? (
        <View style={styles.section}>
          <TouchableOpacity
            style={[styles.registerButton, isRegistering && styles.disabledButton]}
            onPress={registerDevice}
            disabled={isRegistering}
          >
            <Text style={styles.registerButtonText}>
              {isRegistering ? 'Registering Device...' : 'Register My Device for Network Access'}
            </Text>
          </TouchableOpacity>

          {isRegistering && <ActivityIndicator style={styles.loader} />}
        </View>
      ) : (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>✅ Device Registered Successfully!</Text>

          <View style={styles.resultSection}>
            <Text style={styles.resultTitle}>Network Configuration</Text>
            <Text style={styles.resultText}>Wi-Fi Network: {registrationResult.wifiSSID}</Text>
            <Text style={styles.resultText}>
              Certificate: {registrationResult.certificateInfo.commonName}
            </Text>
            <Text style={styles.resultText}>
              Valid from: {new Date(registrationResult.certificateInfo.validFrom).toLocaleDateString()}
            </Text>
            <Text style={styles.resultText}>
              Valid until: {new Date(registrationResult.certificateInfo.validTo).toLocaleDateString()}
            </Text>
          </View>

          <View style={styles.downloadSection}>
            <Text style={styles.downloadTitle}>Download Configuration Files</Text>

            <Text
              style={styles.downloadButton}
              onPress={() => downloadFile(registrationResult.p12DownloadUrl, 'certificate.p12')}
            >
              Download P12 Certificate
            </Text>

            {Platform.OS === 'ios' && registrationResult.mobileconfigDownloadUrl && (
              <>
                <Text
                  style={styles.downloadButton}
                  onPress={() => downloadFile(registrationResult.mobileconfigDownloadUrl!, 'wifi-config.mobileconfig')}
                >
                  Download Mobile Configuration
                </Text>

                <Text style={styles.helpButton} onPress={openMobileConfigGuide}>
                  📖 Installation Guide
                </Text>
              </>
            )}

            <View style={styles.instructionsBox}>
              <Text style={styles.instructionsTitle}>Next Steps:</Text>
              <Text style={styles.instructionsText}>
                1. Download the files above{'\n'}
                2. {Platform.OS === 'ios'
                   ? 'Install the mobile configuration profile'
                   : 'Import the P12 certificate (password: 123456)'}{'\n'}
                3. Connect to the "{registrationResult.wifiSSID}" network{'\n'}
                4. Your device will automatically authenticate
              </Text>
            </View>
          </View>
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
  },
  header: {
    marginBottom: 30,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  subtitle: {
    fontSize: 16,
    opacity: 0.7,
    lineHeight: 22,
  },
  section: {
    marginBottom: 30,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: '600',
    marginBottom: 15,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  label: {
    fontWeight: '500',
    flex: 1,
  },
  value: {
    flex: 2,
    textAlign: 'right',
  },
  registerButton: {
    backgroundColor: '#007AFF',
    padding: 15,
    borderRadius: 8,
    alignItems: 'center',
  },
  registerButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  disabledButton: {
    backgroundColor: '#999999',
    opacity: 0.6,
  },
  loader: {
    marginTop: 15,
  },
  resultSection: {
    backgroundColor: '#f0f9ff',
    padding: 15,
    borderRadius: 8,
    marginBottom: 20,
  },
  resultTitle: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 10,
  },
  resultText: {
    fontSize: 14,
    marginBottom: 5,
  },
  downloadSection: {
    borderTopWidth: 1,
    borderTopColor: '#eee',
    paddingTop: 20,
  },
  downloadTitle: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 15,
  },
  downloadButton: {
    backgroundColor: '#34D399',
    color: 'white',
    textAlign: 'center',
    padding: 12,
    borderRadius: 8,
    fontSize: 14,
    fontWeight: '500',
    marginBottom: 10,
  },
  helpButton: {
    backgroundColor: '#F3F4F6',
    color: '#374151',
    textAlign: 'center',
    padding: 12,
    borderRadius: 8,
    fontSize: 14,
    marginBottom: 20,
  },
  instructionsBox: {
    backgroundColor: '#FEF3C7',
    padding: 15,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#F59E0B',
  },
  instructionsTitle: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 10,
    color: '#92400E',
  },
  instructionsText: {
    fontSize: 13,
    lineHeight: 18,
    color: '#92400E',
  },
});