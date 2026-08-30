import { describe, it, expect } from 'vitest'
import { tokenize, parseToGroups, serializeCondition, serializeGroups } from '../index'

describe('expression-parser', () => {
  describe('tokenize', () => {
    it('does not infinite loop on expressions with dots, numbers, and slashes', () => {
      const input = 'http.request.uri.path = "/wp-login.php"'
      const tokens = tokenize(input)
      expect(tokens).toEqual([
        { type: 'FIELD', value: 'http.request.uri.path', pos: 0 },
        { type: 'OPERATOR', value: '=', pos: 22 },
        { type: 'VALUE', value: '/wp-login.php', pos: 24 },
      ])
    })

    it('tokenizes status codes and comparison operators', () => {
      const input = 'http.response.status_code >= 400 and http.response.status_code <= 499'
      const tokens = tokenize(input)
      expect(tokens).toEqual([
        { type: 'FIELD', value: 'http.response.status_code', pos: 0 },
        { type: 'OPERATOR', value: '>=', pos: 26 },
        { type: 'VALUE', value: '400', pos: 29 },
        { type: 'AND', value: 'and', pos: 33 },
        { type: 'FIELD', value: 'http.response.status_code', pos: 37 },
        { type: 'OPERATOR', value: '<=', pos: 63 },
        { type: 'VALUE', value: '499', pos: 66 },
      ])
    })

    it('tokenizes list references and `in` operator', () => {
      const input = 'ip.src in $network:blocklist'
      const tokens = tokenize(input)
      expect(tokens).toEqual([
        { type: 'FIELD', value: 'ip.src', pos: 0 },
        { type: 'OPERATOR', value: 'in', pos: 7 },
        { type: 'VALUE', value: '$network:blocklist', pos: 10 },
      ])
    })

    it('tokenizes bracketed fields and string values', () => {
      const input = 'http.request.headers["user-agent"] contains "bot"'
      const tokens = tokenize(input)
      expect(tokens).toEqual([
        { type: 'FIELD', value: 'http.request.headers["user-agent"]', pos: 0 },
        { type: 'OPERATOR', value: 'contains', pos: 35 },
        { type: 'VALUE', value: 'bot', pos: 44 },
      ])
    })

    it('handles unexpected characters safely without freezing', () => {
      const input = '??? @@@ !!! %%% ^^^'
      const tokens = tokenize(input)
      // Should not throw or loop infinitely
      expect(Array.isArray(tokens)).toBe(true)
    })
  })

  describe('parseToGroups', () => {
    it('parses a single condition expression', () => {
      const groups = parseToGroups('http.request.uri.path = "/wp-login.php"')
      expect(groups).toEqual([
        {
          conditions: [
            { field: 'http.request.uri.path', op: '=', value: '/wp-login.php', negated: false },
          ],
        },
      ])
    })

    it('parses OR groups and AND conditions', () => {
      const expr = 'http.request.method = "POST" and http.request.uri.path = "/login" or http.request.uri.path = "/admin"'
      const groups = parseToGroups(expr)
      expect(groups).toEqual([
        {
          conditions: [
            { field: 'http.request.method', op: '=', value: 'POST', negated: false },
            { field: 'http.request.uri.path', op: '=', value: '/login', negated: false },
          ],
        },
        {
          conditions: [
            { field: 'http.request.uri.path', op: '=', value: '/admin', negated: false },
          ],
        },
      ])
    })

    it('parses parenthesized DNF expressions', () => {
      const expr = '(http.request.method = "POST" and http.request.uri.path = "/login") or (http.request.uri.path = "/admin")'
      const groups = parseToGroups(expr)
      expect(groups).toEqual([
        {
          conditions: [
            { field: 'http.request.method', op: '=', value: 'POST', negated: false },
            { field: 'http.request.uri.path', op: '=', value: '/login', negated: false },
          ],
        },
        {
          conditions: [
            { field: 'http.request.uri.path', op: '=', value: '/admin', negated: false },
          ],
        },
      ])
    })

    it('parses negated conditions', () => {
      const expr = 'not http.request.tls and ip.src in $network:blocklist'
      const groups = parseToGroups(expr)
      expect(groups).toEqual([
        {
          conditions: [
            { field: 'http.request.tls', op: 'exists', value: '', negated: true },
            { field: 'ip.src', op: 'in', value: '$network:blocklist', negated: false },
          ],
        },
      ])
    })

    it('returns default condition row for empty input', () => {
      const groups = parseToGroups('')
      expect(groups).toEqual([
        {
          conditions: [
            { field: 'http.request.uri.path', op: '=', value: '', negated: false },
          ],
        },
      ])
    })
  })

  describe('serializeCondition and serializeGroups', () => {
    it('serializes string conditions with quotes', () => {
      const str = serializeCondition({
        field: 'http.request.uri.path',
        op: '=',
        value: '/wp-login.php',
        negated: false,
      })
      expect(str).toBe('http.request.uri.path = "/wp-login.php"')
    })

    it('serializes numeric conditions without quotes', () => {
      const str = serializeCondition({
        field: 'http.response.status_code',
        op: '>=',
        value: '400',
        negated: false,
      })
      expect(str).toBe('http.response.status_code >= 400')
    })

    it('serializes list references without quotes', () => {
      const str = serializeCondition({
        field: 'ip.src',
        op: 'in',
        value: '$network:bad_ips',
        negated: false,
      })
      expect(str).toBe('ip.src in $network:bad_ips')
    })

    it('serializes boolean conditions without quotes', () => {
      const str = serializeCondition({
        field: 'graphql.valid',
        op: '=',
        value: 'true',
        negated: false,
      })
      expect(str).toBe('graphql.valid = true')
    })

    it('serializes negated conditions', () => {
      const str = serializeCondition({
        field: 'http.request.tls',
        op: 'exists',
        value: '',
        negated: true,
      })
      expect(str).toBe('not http.request.tls exists')
    })

    it('serializes multiple DNF groups', () => {
      const groups = [
        {
          conditions: [
            { field: 'http.request.method', op: '=', value: 'POST', negated: false },
            { field: 'http.request.uri.path', op: '=', value: '/login', negated: false },
          ],
        },
        {
          conditions: [
            { field: 'http.request.uri.path', op: '=', value: '/admin', negated: false },
          ],
        },
      ]
      const serialized = serializeGroups(groups)
      expect(serialized).toBe('http.request.method = "POST" and http.request.uri.path = "/login" or http.request.uri.path = "/admin"')
    })
  })
})
