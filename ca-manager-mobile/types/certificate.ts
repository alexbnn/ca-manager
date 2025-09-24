export interface Certificate {
  id: string
  commonName: string
  status: 'active' | 'expired' | 'revoked'
  issuedDate: string
  expiryDate: string
  serialNumber: string
  issuer: string
  keyUsage?: string[]
  extendedKeyUsage?: string[]
  subjectAltName?: string
}

export interface CertificateRequest {
  commonName: string
  emailAddress: string
  organizationalUnit?: string
  organization?: string
  locality?: string
  state?: string
  country?: string
  keySize?: number
  validityDays?: number
}

export interface CertificateDownload {
  format: 'p12' | 'pem' | 'mobileconfig'
  password?: string
  includeChain?: boolean
}

export interface CertificateDetails extends Certificate {
  publicKey: string
  fingerprints: {
    sha1: string
    sha256: string
  }
  extensions: {
    [key: string]: string
  }
  chain: Certificate[]
}

export interface CertificateListResponse {
  certificates: Certificate[]
  total: number
  page: number
  pageSize: number
}

export interface CertificateStats {
  total: number
  active: number
  expired: number
  revoked: number
  expiringSoon: number
}