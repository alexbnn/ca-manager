import { z } from 'zod'

export const urlSchema = z.object({
  url: z.string()
    .min(1, 'URL is required')
    .url('Please enter a valid URL')
    .refine(
      (url) => url.startsWith('https://') || url.startsWith('http://'),
      'URL must start with http:// or https://'
    )
})

export const serverConfigSchema = z.object({
  url: z.string().url(),
  name: z.string().min(1),
  version: z.string().min(1),
  idpType: z.enum(['google', 'microsoft']),
  features: z.array(z.string()),
  branding: z.object({
    logo: z.string().optional(),
    primaryColor: z.string().optional(),
  }),
  lastUsed: z.date()
})

export const certificateRequestSchema = z.object({
  commonName: z.string()
    .min(1, 'Common name is required')
    .email('Must be a valid email address'),
  emailAddress: z.string()
    .email('Must be a valid email address'),
  organizationalUnit: z.string().optional(),
  organization: z.string().optional(),
  locality: z.string().optional(),
  state: z.string().optional(),
  country: z.string().length(2, 'Country must be 2 letters').optional(),
  keySize: z.number().min(2048).max(4096).optional(),
  validityDays: z.number().min(1).max(3650).optional()
})

export const qrConfigSchema = z.object({
  v: z.number().min(1),
  url: z.string().url(),
  name: z.string().min(1),
  logo: z.string().optional(),
  idp: z.enum(['google', 'microsoft']),
  timestamp: z.number()
})

export type URLFormData = z.infer<typeof urlSchema>
export type ServerConfigData = z.infer<typeof serverConfigSchema>
export type CertificateRequestData = z.infer<typeof certificateRequestSchema>
export type QRConfigData = z.infer<typeof qrConfigSchema>