// JA4 TLS fingerprint decoder.
//
// Format: {proto}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
// Example: t13d1516h2_8daaf6152771_b186095e22b6
//
// Field breakdown:
//   proto        - 1 char: t=TCP, q=QUIC
//   version      - 2 digits: 13=TLS 1.3, 12=TLS 1.2, 11=TLS 1.1, 10=TLS 1.0, 00=unknown
//   sni          - 1 char: d=domain (SNI present), i=IP (no SNI)
//   cipher_count - 2 digits: number of cipher suites (zero-padded)
//   ext_count    - 2 digits: number of extensions (zero-padded)
//   alpn         - 2 chars: ALPN value (h2, 01, 00, etc.)
//   cipher_hash  - 12 chars: first 12 of SHA256(sorted cipher list)
//   ext_hash     - 12 chars: first 12 of SHA256(sorted extensions, ALPN removed)

export interface DecodedJa4 {
  protocol: string
  tlsVersion: string
  sni: string
  cipherCount: number
  extensionCount: number
  alpn: string
  cipherHash: string
  extensionHash: string
}

export interface Ja4DecodeResult {
  valid: boolean
  decoded?: DecodedJa4
  error?: string
}

const TLS_VERSIONS: Record<string, string> = {
  '13': 'TLS 1.3',
  '12': 'TLS 1.2',
  '11': 'TLS 1.1',
  '10': 'TLS 1.0',
  's3': 'SSL 3.0',
  '00': 'Unknown',
}

const ALPN_VALUES: Record<string, string> = {
  'h2': 'HTTP/2',
  '01': 'HTTP/1.1',
  '00': 'None',
}

const JA4_RE = /^([tq])(\d{2})([di])(\d{2})(\d{2})(.{2})_([0-9a-f]{12})_([0-9a-f]{12})$/i

export function decodeJa4(input: string): Ja4DecodeResult {
  const value = input.trim().toLowerCase()
  if (!value) return { valid: false, error: 'Enter a JA4 fingerprint' }

  const match = value.match(JA4_RE)
  if (!match) {
    return {
      valid: false,
      error: 'Invalid JA4 format. Expected: t13d1516h2_8daaf6152771_b186095e22b6',
    }
  }

  const [, proto, verCode, sniCode, cipherCountStr, extCountStr, alpn, cipherHash, extHash] = match

  const cipherCount = parseInt(cipherCountStr, 10)
  const extensionCount = parseInt(extCountStr, 10)

  return {
    valid: true,
    decoded: {
      protocol: proto === 't' ? 'TCP' : 'QUIC',
      tlsVersion: TLS_VERSIONS[verCode] || `Unknown (${verCode})`,
      sni: sniCode === 'd' ? 'Domain (SNI present)' : 'IP (no SNI)',
      cipherCount,
      extensionCount,
      alpn: ALPN_VALUES[alpn] || `Other (${alpn})`,
      cipherHash,
      extensionHash: extHash,
    },
  }
}
