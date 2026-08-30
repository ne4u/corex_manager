// HTTP Request fingerprint (req_fp) decoder.
//
// Format: 17 underscore-separated fields:
//   {path_b62}_{method2}_{http_ver}_{path_depth}_
//   {param_keys}_{param_types}_{param_lens}_{req_ctype}_
//   {hdr_count}_{hdr_list}_{accept_lang}_{auth_type}_
//   {cookie}_{cookie_fields}_{referer}_
//   {status}_{body_bytes}
//
// Example: 7nQ_ge_11_01_nil_nil_0_0000_05_achru_0000_n_n_nil_n_200_1024

export interface DecodedReqFp {
  pathB62: string
  pathDecoded: string
  method: string
  httpVersion: string
  pathDepth: number
  paramKeys: string
  paramTypes: string
  paramLens: string
  reqContentType: string
  headerCount: number
  headerList: string
  acceptLanguage: string
  authType: string
  cookie: string
  cookieFields: string
  referer: string
  status: number
  bodyBytes: number
}

export interface ReqFpDecodeResult {
  valid: boolean
  decoded?: DecodedReqFp
  error?: string
}

const HTTP_VERSIONS: Record<string, string> = {
  '09': 'HTTP/0.9',
  '10': 'HTTP/1.0',
  '11': 'HTTP/1.1',
  '20': 'HTTP/2',
  '30': 'HTTP/3',
}

const AUTH_TYPES: Record<string, string> = {
  n: 'None',
  b: 'Basic',
  t: 'Bearer / Token',
  d: 'Digest',
  o: 'Other',
}

const COOKIE_FLAGS: Record<string, string> = {
  c: 'Present',
  n: 'Absent',
}

const REFERER_FLAGS: Record<string, string> = {
  n: 'No Referer',
  s: 'Same-domain',
  x: 'Cross-domain',
}

const TYPE_CODES: Record<string, string> = {
  i: 'int', f: 'float', s: 'string', c: 'char', b: 'bool',
  t: 'time', d: 'date', z: 'datetime+tz', e: 'empty',
  o: 'object', l: 'list',
}

// Base62 charset used by the HAProxy req_fp Lua module.
// Path bytes are treated as a big-endian integer and encoded in base62.
const B62_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

/**
 * Decode a base62-encoded path back to its original UTF-8 string.
 * Returns the original input if decoding fails (invalid chars or non-UTF-8).
 */
function base62DecodePath(s: string): string {
  if (!s || s === '0') return ''
  let n = 0n
  for (const c of s) {
    const idx = B62_CHARS.indexOf(c)
    if (idx < 0) return s
    n = n * 62n + BigInt(idx)
  }
  if (n === 0n) return ''
  const bytes: number[] = []
  while (n > 0n) {
    bytes.unshift(Number(n & 0xFFn))
    n = n >> 8n
  }
  try {
    return new TextDecoder().decode(new Uint8Array(bytes))
  } catch {
    return s
  }
}

export function decodeReqFp(input: string): ReqFpDecodeResult {
  const value = input.trim()
  if (!value) return { valid: false, error: 'Enter a request fingerprint' }

  const parts = value.split('_')
  if (parts.length !== 17) {
    return {
      valid: false,
      error: `Invalid format: expected 17 fields separated by "_", got ${parts.length}`,
    }
  }

  const [
    pathB62, method2, httpVer, pathDepthStr,
    paramKeys, paramTypes, paramLens, reqCtype,
    hdrCountStr, hdrList, acceptLang, authType,
    cookie, cookieFields, referer,
    statusStr, bodyBytesStr,
  ] = parts

  const pathDepth = parseInt(pathDepthStr, 10)
  const headerCount = parseInt(hdrCountStr, 10)
  const status = parseInt(statusStr, 10)
  const bodyBytes = parseInt(bodyBytesStr, 10)

  if (isNaN(pathDepth) || isNaN(headerCount) || isNaN(status) || isNaN(bodyBytes)) {
    return { valid: false, error: 'One or more numeric fields could not be parsed' }
  }

  // Decode param types
  const paramTypeLabels = paramTypes === 'nil'
    ? 'None'
    : paramTypes.split('').map((c) => TYPE_CODES[c] || `?(${c})`).join(', ')

  return {
    valid: true,
    decoded: {
      pathB62,
      pathDecoded: base62DecodePath(pathB62),
      method: method2,
      httpVersion: HTTP_VERSIONS[httpVer] || `Unknown (${httpVer})`,
      pathDepth,
      paramKeys: paramKeys === 'nil' ? 'None' : paramKeys,
      paramTypes: paramTypeLabels,
      paramLens: paramLens === '0' ? 'None' : paramLens,
      reqContentType: reqCtype === '0000' ? 'None' : reqCtype,
      headerCount,
      headerList: hdrList === 'nil' ? 'None' : hdrList,
      acceptLanguage: acceptLang === '0000' ? 'None' : acceptLang,
      authType: AUTH_TYPES[authType] || `Unknown (${authType})`,
      cookie: COOKIE_FLAGS[cookie] || `Unknown (${cookie})`,
      cookieFields: cookieFields === 'nil' ? 'None' : cookieFields,
      referer: REFERER_FLAGS[referer] || `Unknown (${referer})`,
      status,
      bodyBytes,
    },
  }
}
