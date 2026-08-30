export interface DecodedUniqueId {
  clientIp: string
  clientPort: number
  timestamp: number
  timestampFormatted: string
  requestCounter: number
  pid: number
}

export interface DecodeResult {
  valid: boolean
  decoded?: DecodedUniqueId
  error?: string
}

const UNIQUE_ID_RE =
  /^([0-9a-fA-F]+):([0-9a-fA-F]+)_([0-9a-fA-F]+)_([0-9a-fA-F]+):([0-9a-fA-F]+)$/

function hexToIp(hex: string): string | null {
  if (hex.length % 2 !== 0) return null
  const bytes: number[] = []
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.slice(i, i + 2), 16)
    if (Number.isNaN(byte)) return null
    bytes.push(byte)
  }
  if (bytes.length === 4) {
    // IPv4: 4 bytes -> dotted-decimal
    return bytes.join('.')
  }
  if (bytes.length === 16) {
    // IPv6: 16 bytes -> 8 groups of 2 bytes, compressed with "::"
    const groups: string[] = []
    for (let i = 0; i < 16; i += 2) {
      groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16))
    }
    // Find the longest run of zero groups for "::" compression
    let bestStart = -1
    let bestLen = 0
    let curStart = -1
    let curLen = 0
    for (let i = 0; i < groups.length; i++) {
      if (groups[i] === '0') {
        if (curStart === -1) curStart = i
        curLen++
        if (curLen > bestLen) {
          bestLen = curLen
          bestStart = curStart
        }
      } else {
        curStart = -1
        curLen = 0
      }
    }
    // RFC 5952: only compress runs of 2+ zero groups
    if (bestLen >= 2) {
      const before = groups.slice(0, bestStart).join(':')
      const after = groups.slice(bestStart + bestLen).join(':')
      return `${before}::${after}`
    }
    return groups.join(':')
  }
  return null
}

function hexToDecimal(hex: string): number | null {
  const value = parseInt(hex, 16)
  return Number.isNaN(value) ? null : value
}

export function decodeUniqueId(input: string): DecodeResult {
  const value = input.trim()
  if (!value) return { valid: false, error: 'Enter a unique ID' }

  const match = value.match(UNIQUE_ID_RE)
  if (!match) {
    return {
      valid: false,
      error:
        'Invalid format. Expected CLIENT_IP:PORT_TIMESTAMP_COUNTER:PID',
    }
  }

  const [
    ,
    clientIpHex,
    clientPortHex,
    timestampHex,
    counterHex,
    pidHex,
  ] = match

  const clientIp = hexToIp(clientIpHex)
  const clientPort = hexToDecimal(clientPortHex)
  const timestamp = hexToDecimal(timestampHex)
  const requestCounter = hexToDecimal(counterHex)
  const pid = hexToDecimal(pidHex)

  if (
    clientIp === null ||
    clientPort === null ||
    timestamp === null ||
    requestCounter === null ||
    pid === null
  ) {
    return { valid: false, error: 'One or more fields could not be decoded as hex' }
  }

  return {
    valid: true,
    decoded: {
      clientIp,
      clientPort,
      timestamp,
      timestampFormatted: new Date(timestamp * 1000).toISOString(),
      requestCounter,
      pid,
    },
  }
}
