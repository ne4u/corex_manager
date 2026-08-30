export type TokenType =
  | 'FIELD'
  | 'OPERATOR'
  | 'VALUE'
  | 'NOT'
  | 'AND'
  | 'OR'
  | 'LPAREN'
  | 'RPAREN'

export interface Token {
  type: TokenType
  value: string
  pos: number
}

export interface BuilderCondition {
  field: string
  op: string
  value: string
  negated: boolean
}

export interface BuilderGroup {
  conditions: BuilderCondition[]
}

const TWO_CHAR_OPS = new Set(['!=', '!~', '>=', '<='])
const ONE_CHAR_OPS = new Set(['=', '~', '>', '<'])
const WORD_OPERATORS = new Set(['contains', 'starts_with', 'ends_with', 'exists', 'in'])

const KEYWORDS: Record<string, TokenType> = {
  'and': 'AND',
  'or': 'OR',
  'not': 'NOT',
}

export function tokenize(input: string): Token[] {
  const tokens: Token[] = []
  let pos = 0
  const len = input.length

  while (pos < len) {
    // Skip whitespace
    while (pos < len && /\s/.test(input[pos])) pos++
    if (pos >= len) break

    const start = pos
    const char = input[pos]

    // Handle parentheses
    if (char === '(') {
      tokens.push({ type: 'LPAREN', value: '(', pos: start })
      pos++
      continue
    }
    if (char === ')') {
      tokens.push({ type: 'RPAREN', value: ')', pos: start })
      pos++
      continue
    }

    // Handle quoted strings (values)
    if (char === '"' || char === "'") {
      const quote = char
      pos++ // Skip opening quote
      let value = ''
      while (pos < len && input[pos] !== quote) {
        if (input[pos] === '\\' && pos + 1 < len) {
          pos++
          value += input[pos]
        } else {
          value += input[pos]
        }
        pos++
      }
      if (pos < len && input[pos] === quote) {
        pos++ // Skip closing quote
      }
      tokens.push({ type: 'VALUE', value, pos: start })
      continue
    }

    // Handle bracketed literal list values: e.g. [192.168.1.1, 10.0.0.1] or ["US", "CA"]
    // Only if previous token was an OPERATOR (e.g. `in`)
    const lastTok = tokens.length > 0 ? tokens[tokens.length - 1] : null
    if (char === '[' && lastTok && lastTok.type === 'OPERATOR') {
      let bracketVal = '['
      pos++
      let depth = 1
      while (pos < len && depth > 0) {
        if (input[pos] === '[') depth++
        else if (input[pos] === ']') depth--
        bracketVal += input[pos]
        pos++
      }
      tokens.push({ type: 'VALUE', value: bracketVal, pos: start })
      continue
    }

    // Handle two-character operators
    const two = input.slice(pos, pos + 2)
    if (TWO_CHAR_OPS.has(two)) {
      tokens.push({ type: 'OPERATOR', value: two, pos: start })
      pos += 2
      continue
    }

    // Handle single-character operators
    if (ONE_CHAR_OPS.has(char)) {
      tokens.push({ type: 'OPERATOR', value: char, pos: start })
      pos++
      continue
    }

    // Handle list references: $type:name or $name
    if (char === '$') {
      let ref = '$'
      pos++
      while (pos < len && /[a-zA-Z0-9_.:-]/.test(input[pos])) {
        ref += input[pos]
        pos++
      }
      tokens.push({ type: 'VALUE', value: ref, pos: start })
      continue
    }

    // Handle words, identifiers, numbers, keywords, and fields with brackets
    if (/[a-zA-Z0-9_.-]/.test(char)) {
      let word = ''
      while (pos < len && /[a-zA-Z0-9_.-]/.test(input[pos])) {
        word += input[pos]
        pos++
      }

      // Check for attached bracket notation: field["key"]
      while (pos < len && input[pos] === '[') {
        let bracket = '['
        pos++
        while (pos < len && input[pos] !== ']') {
          bracket += input[pos]
          pos++
        }
        if (pos < len && input[pos] === ']') {
          bracket += ']'
          pos++
        }
        word += bracket
      }

      const lowerWord = word.toLowerCase()

      // Check if it's a logical keyword (and, or, not)
      if (KEYWORDS[lowerWord]) {
        tokens.push({ type: KEYWORDS[lowerWord], value: lowerWord, pos: start })
        continue
      }

      // Check if it's a word operator (contains, starts_with, ends_with, exists, in)
      if (WORD_OPERATORS.has(lowerWord)) {
        tokens.push({ type: 'OPERATOR', value: lowerWord, pos: start })
        continue
      }

      // Distinguish between FIELD and VALUE:
      // If the preceding token is an OPERATOR, this is a VALUE
      if (lastTok && lastTok.type === 'OPERATOR') {
        tokens.push({ type: 'VALUE', value: word, pos: start })
      } else {
        tokens.push({ type: 'FIELD', value: word, pos: start })
      }
      continue
    }

    // Safety fallback: guaranteed progression
    if (pos === start) {
      pos++
    }
  }

  return tokens
}

/**
 * Parse a tokenized expression into builder groups (DNF format).
 */
export function parseToGroups(text: string): BuilderGroup[] {
  if (!text || !text.trim()) {
    return [{ conditions: [{ field: 'http.request.uri.path', op: '=', value: '', negated: false }] }]
  }

  const tokens = tokenize(text)
  if (tokens.length === 0) {
    return [{ conditions: [{ field: 'http.request.uri.path', op: '=', value: '', negated: false }] }]
  }

  const groups: BuilderGroup[] = []
  let currentGroup: BuilderCondition[] = []
  let i = 0

  while (i < tokens.length) {
    // Skip opening parentheses
    while (i < tokens.length && tokens[i].type === 'LPAREN') {
      i++
    }
    if (i >= tokens.length) break

    let negated = false
    if (tokens[i].type === 'NOT') {
      negated = true
      i++
      while (i < tokens.length && tokens[i].type === 'LPAREN') {
        i++
      }
    }

    if (i >= tokens.length) break

    // Expect FIELD or VALUE acting as field name
    if (tokens[i].type !== 'FIELD' && tokens[i].type !== 'VALUE') {
      i++
      continue
    }

    const field = tokens[i].value
    i++

    // Skip closing parentheses if any
    while (i < tokens.length && tokens[i].type === 'RPAREN') {
      i++
    }

    let op = 'exists'
    let value = ''

    if (i < tokens.length && tokens[i].type === 'OPERATOR') {
      op = tokens[i].value
      i++

      if (op !== 'exists') {
        if (i < tokens.length && (tokens[i].type === 'VALUE' || tokens[i].type === 'FIELD')) {
          value = tokens[i].value
          i++
        }
      }
    }

    // Skip closing parentheses
    while (i < tokens.length && tokens[i].type === 'RPAREN') {
      i++
    }

    currentGroup.push({ field, op, value, negated })

    // Check for AND / OR delimiters
    if (i < tokens.length && tokens[i].type === 'AND') {
      i++
    } else if (i < tokens.length && tokens[i].type === 'OR') {
      if (currentGroup.length > 0) {
        groups.push({ conditions: currentGroup })
        currentGroup = []
      }
      i++
    }
  }

  if (currentGroup.length > 0) {
    groups.push({ conditions: currentGroup })
  }

  return groups.length > 0
    ? groups
    : [{ conditions: [{ field: 'http.request.uri.path', op: '=', value: '', negated: false }] }]
}

/**
 * Serialize a builder condition back to text format.
 */
export function serializeCondition(c: BuilderCondition): string {
  const parts: string[] = []
  if (c.negated) parts.push('not')
  parts.push(c.field)
  if (c.op === 'exists') {
    parts.push('exists')
  } else {
    parts.push(c.op)
    if (c.value !== undefined && c.value !== '') {
      const val = c.value.trim()
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        parts.push(val)
      } else if (/^-?\d+(\.\d+)?$/.test(val)) {
        parts.push(val)
      } else if (val === 'true' || val === 'false') {
        parts.push(val)
      } else if (val.startsWith('$')) {
        parts.push(val)
      } else if (/^AS\d+$/i.test(val)) {
        parts.push(val)
      } else if (val.startsWith('[') && val.endsWith(']')) {
        parts.push(val)
      } else {
        const escaped = val.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
        parts.push(`"${escaped}"`)
      }
    }
  }
  return parts.join(' ')
}

/**
 * Serialize builder groups back to text format.
 */
export function serializeGroups(groups: BuilderGroup[]): string {
  return groups
    .map(g => g.conditions.map(c => serializeCondition(c)).filter(Boolean).join(' and '))
    .filter(Boolean)
    .join(' or ')
}
