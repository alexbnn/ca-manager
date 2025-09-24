import { Stack } from 'expo-router'

export default function AuthLayout() {
  return (
    <Stack
      screenOptions={{
        headerShown: false,
      }}
    >
      <Stack.Screen name="welcome" />
      <Stack.Screen name="server-entry" />
      <Stack.Screen name="login" />
      <Stack.Screen name="demo" />
    </Stack>
  )
}