/**
 * Normalize a URL by adding https:// if no protocol is specified
 * and removing trailing slashes
 */
export function normalizeUrl(url: string): string {
  let normalized = url.trim()

  // Add https:// if no protocol specified
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
    normalized = `https://${normalized}`
  }

  // Remove trailing slash
  normalized = normalized.replace(/\/$/, '')

  return normalized
}

/**
 * Extract domain from URL
 */
export function extractDomain(url: string): string {
  try {
    const urlObj = new URL(normalizeUrl(url))
    return urlObj.hostname
  } catch {
    return ''
  }
}

/**
 * Validate if URL is reachable (basic format check)
 */
export function isValidUrl(url: string): boolean {
  try {
    const normalized = normalizeUrl(url)
    new URL(normalized)
    return true
  } catch {
    return false
  }
}

/**
 * Generate common URL suggestions based on input
 */
export function generateUrlSuggestions(input: string): string[] {
  if (!input || input.length < 3) return []

  const domain = input.replace(/^https?:\/\//, '').replace(/\/$/, '')

  return [
    `https://ca.${domain}`,
    `https://pki.${domain}`,
    `https://certs.${domain}`,
    `https://${domain}/ca`,
    `https://${domain}/pki`
  ]
}

/**
 * Create a storage key from URL for secure storage
 */
export function createStorageKey(url: string, suffix: string = ''): string {
  const normalized = normalizeUrl(url)
  const encoded = btoa(normalized).slice(0, 16) // Base64 encode and truncate
  return suffix ? `${encoded}_${suffix}` : encoded
}