import { useTranslation } from 'react-i18next'
import { ExternalLink, ShieldCheck, CheckCircle2, XCircle, AlertTriangle, HelpCircle } from 'lucide-react'
import { Badge } from './ui'
import { useDateTime } from '../contexts/DateTimeContext'

interface SslLabsReportProps {
  report: Record<string, any>
}

function gradeColor(grade: string | null | undefined): string {
  if (!grade) return 'text-slate-400'
  if (grade.startsWith('A')) return 'text-green-400'
  if (grade.startsWith('B')) return 'text-amber-400'
  if (grade.startsWith('C') || grade.startsWith('D')) return 'text-orange-400'
  return 'text-red-400'
}

function gradeBg(grade: string | null | undefined): string {
  if (!grade) return 'bg-slate-700 text-slate-300'
  if (grade.startsWith('A')) return 'bg-green-500/20 text-green-400 border-green-500/30'
  if (grade.startsWith('B')) return 'bg-amber-500/20 text-amber-400 border-amber-500/30'
  if (grade.startsWith('C') || grade.startsWith('D')) return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
  return 'bg-red-500/20 text-red-400 border-red-500/30'
}

function vulnIcon(variant: 'success' | 'error' | 'warning' | 'default') {
  const cls = 'h-3 w-3 shrink-0'
  if (variant === 'success') return <CheckCircle2 className={cls} />
  if (variant === 'error') return <XCircle className={cls} />
  if (variant === 'warning') return <AlertTriangle className={cls} />
  return <HelpCircle className={cls} />
}

function boolVulnBadge(value: boolean | undefined, vulnerableLabel: string, safeLabel: string) {
  // For boolean vuln fields: true = vulnerable (bad), false = not vulnerable (good)
  if (value === undefined || value === null) return <span className="text-slate-500">-</span>
  const variant = value ? 'error' : 'success'
  return <Badge variant={variant} size="sm"><span className="inline-flex items-center gap-1">{vulnIcon(variant)}{value ? vulnerableLabel : safeLabel}</span></Badge>
}

function boolSafeBadge(value: boolean | undefined, trueLabel: string, falseLabel: string) {
  // For boolean security-feature fields: true = supported (good), false = not supported (bad)
  if (value === undefined || value === null) return <span className="text-slate-500">-</span>
  const variant = value ? 'success' : 'warning'
  return <Badge variant={variant} size="sm"><span className="inline-flex items-center gap-1">{vulnIcon(variant)}{value ? trueLabel : falseLabel}</span></Badge>
}

function intVulnBadge(value: number | undefined, labels: Record<number, { text: string; variant: 'success' | 'error' | 'warning' | 'default' }>) {
  // For integer vuln fields with specific value mappings per the SSL Labs API docs
  if (value === undefined || value === null) return <span className="text-slate-500">-</span>
  const entry = labels[value]
  if (entry) return <Badge variant={entry.variant} size="sm"><span className="inline-flex items-center gap-1">{vulnIcon(entry.variant)}{entry.text}</span></Badge>
  return <Badge variant="default" size="sm"><span className="inline-flex items-center gap-1">{vulnIcon('default')}{String(value)}</span></Badge>
}

function forwardSecrecyBadge(value: number | undefined) {
  // Bitmask: bit 0 (1) = at least one browser FS, bit 1 (2) = FS with modern, bit 2 (4) = all clients FS
  if (value === undefined || value === null) return <span className="text-slate-500">-</span>
  if (value & 4) return <Badge variant="success" size="sm"><span className="inline-flex items-center gap-1"><CheckCircle2 className="h-3 w-3" />Full (all clients)</span></Badge>
  if (value & 2) return <Badge variant="success" size="sm"><span className="inline-flex items-center gap-1"><CheckCircle2 className="h-3 w-3" />Modern clients</span></Badge>
  if (value & 1) return <Badge variant="warning" size="sm"><span className="inline-flex items-center gap-1"><AlertTriangle className="h-3 w-3" />Partial (some clients)</span></Badge>
  return <Badge variant="error" size="sm"><span className="inline-flex items-center gap-1"><XCircle className="h-3 w-3" />None</span></Badge>
}

export default function SslLabsReport({ report }: SslLabsReportProps) {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()

  const host = report.host || ''
  const endpoints = report.endpoints || []
  const certs = report.certs || []
  const details = endpoints[0]?.details || {}

  const protocols = details.protocols || []
  const suites = details.suites || []
  const namedGroups = details.namedGroups?.list || []
  const sims = details.sims?.results || []
  const httpTransactions = details.httpTransactions || []
  const hsts = details.hstsPolicy
  const hpkp = details.hpkpPolicy
  const certChains = details.certChains || []

  const bestGrade = endpoints
    .map((e: any) => e.grade)
    .filter(Boolean)
    .sort((a: string, b: string) => (a > b ? -1 : 1))[0]

  const ssllabsUrl = `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(host)}`

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="card space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldCheck className="h-6 w-6 text-primary" />
            <div>
              <h3 className="text-xl font-bold">{host}</h3>
              <p className="text-xs text-slate-400">
                {report.engineVersion && `Engine: ${report.engineVersion}`}
                {report.engineVersion && report.criteriaVersion && ' · '}
                {report.criteriaVersion && `Criteria: ${report.criteriaVersion}`}
              </p>
            </div>
          </div>
          {bestGrade && (
            <div className={`px-4 py-2 rounded-lg border text-2xl font-bold ${gradeBg(bestGrade)}`}>
              {bestGrade}
            </div>
          )}
        </div>
        <div className="flex flex-wrap gap-4 text-sm text-slate-400">
          {report.startTime && (
            <div><span className="text-slate-500">Started:</span> {formatDateTime(new Date(report.startTime).toISOString())}</div>
          )}
          {report.testTime && (
            <div><span className="text-slate-500">Completed:</span> {formatDateTime(new Date(report.testTime).toISOString())}</div>
          )}
        </div>
        <a href={ssllabsUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary text-sm hover:underline">
          <ExternalLink className="h-3 w-3" />
          {t('pages:ssllabs.report.viewOnSsllabs')}
        </a>
      </div>

      {/* Endpoints */}
      <div className="card space-y-3">
        <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.endpoints')}</h4>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th>IP</th>
                <th>Server</th>
                <th>Grade</th>
                <th>Status</th>
                <th>ETA</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep: any, i: number) => (
                <tr key={i} className="border-b border-slate-800 last:border-0">
                  <td className="py-2 font-mono text-xs">{ep.ipAddress}</td>
                  <td className="text-slate-400">{ep.serverName || '-'}</td>
                  <td><span className={`font-bold ${gradeColor(ep.grade)}`}>{ep.grade || '-'}</span></td>
                  <td className="text-slate-400">{ep.statusMessage || '-'}</td>
                  <td className="text-slate-400">{ep.eta != null ? `${ep.eta}s` : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Protocols */}
      {protocols.length > 0 && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.protocols')}</h4>
          <div className="flex flex-wrap gap-2">
            {protocols.map((p: any, i: number) => (
              <Badge key={i} variant={p.q === 0 ? 'error' : 'success'} size="sm">{p.name} {p.version}{p.q === 0 ? ' (insecure)' : ''}</Badge>
            ))}
          </div>
        </div>
      )}

      {/* Cipher Suites */}
      {suites.length > 0 && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.cipherSuites')}</h4>
          <div className="space-y-4">
            {suites.map((s: any, i: number) => {
              const proto = protocols.find((p: any) => p.id === s.protocol)
              return (
                <div key={i}>
                  <p className="text-sm font-semibold text-slate-300 mb-2">
                    {proto ? `${proto.name} ${proto.version}` : `Protocol ${s.protocol}`}
                    {s.preference && <span className="text-xs text-slate-500 ms-2">(server preference)</span>}
                  </p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-start">
                      <thead className="text-slate-500 border-b border-slate-800">
                        <tr>
                          <th>Cipher</th>
                          <th>Strength</th>
                          <th>Key Exchange</th>
                          <th>Group</th>
                          <th>Rating</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(s.list || []).map((c: any, j: number) => (
                          <tr key={j} className="border-b border-slate-800/50 last:border-0">
                            <td className="py-1 font-mono text-slate-300">{c.name}</td>
                            <td className="text-slate-400">{c.cipherStrength || '-'}</td>
                            <td className="text-slate-400">{c.kxType || '-'} {c.kxStrength ? `(${c.kxStrength})` : ''}</td>
                            <td className="text-slate-400">{c.namedGroupName || '-'}</td>
                            <td>{c.q === 0 ? <Badge variant="error" size="sm">Insecure</Badge> : c.q === 1 ? <Badge variant="warning" size="sm">Weak</Badge> : <Badge variant="success" size="sm">Strong</Badge>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Named Groups */}
      {namedGroups.length > 0 && (() => {
        const pqcGroups = namedGroups.filter((g: any) => g.namedGroupType === 'PQC')
        const hasPQC = pqcGroups.length > 0
        return (
          <div className="card space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.namedGroups')}</h4>
              {hasPQC && (
                <Badge variant="success" size="md">
                  <span className="inline-flex items-center gap-1">
                    <ShieldCheck className="h-4 w-4" />
                    Post-Quantum Cryptography Supported
                  </span>
                </Badge>
              )}
            </div>
            {hasPQC && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-green-400">
                <ShieldCheck className="h-4 w-4 shrink-0 mt-0.5" />
                <p className="text-xs">
                  This server supports Post-Quantum Cryptography (PQC) key exchange. The following PQC named group{pqcGroups.length > 1 ? 's are' : ' is'} available:
                  {' '}
                  <span className="font-mono font-semibold">{pqcGroups.map((g: any) => g.name).join(', ')}</span>.
                  PQC protects against future quantum computer attacks that could break classical key exchange.
                </p>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-start">
                <thead className="text-slate-400 border-b border-slate-800">
                  <tr><th>Name</th><th>Bits</th><th>Type</th></tr>
                </thead>
                <tbody>
                  {namedGroups.map((g: any, i: number) => (
                    <tr key={i} className="border-b border-slate-800/50 last:border-0">
                      <td className="py-1 font-mono text-xs">{g.name}</td>
                      <td className="text-slate-400">{g.bits}</td>
                      <td><Badge variant={g.namedGroupType === 'PQC' ? 'success' : 'default'} size="sm">{g.namedGroupType || 'ECDHE'}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )
      })()}

      {/* Vulnerabilities */}
      <div className="card space-y-3">
        <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.vulnerabilities')}</h4>
        <div className="grid grid-cols-2 gap-2 text-sm">
          {/* Boolean fields: true = vulnerable */}
          <div className="flex items-center justify-between"><span className="text-slate-400">Heartbleed</span>{boolVulnBadge(details.heartbleed, 'Vulnerable', 'Not vulnerable')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">Heartbeat Supported</span>{boolVulnBadge(details.heartbeat, 'Yes', 'No')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">POODLE (SSL)</span>{boolVulnBadge(details.poodle, 'Vulnerable', 'Not vulnerable')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">BEAST</span>{boolVulnBadge(details.vulnBeast, 'Vulnerable', 'Not vulnerable')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">FREAK</span>{boolVulnBadge(details.freak, 'Vulnerable', 'Not vulnerable')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">Logjam</span>{boolVulnBadge(details.logjam, 'Vulnerable', 'Not vulnerable')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">DROWN</span>{boolVulnBadge(details.drownVulnerable, 'Vulnerable', 'Not vulnerable')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">RC4 Supported</span>{boolVulnBadge(details.supportsRc4, 'Yes', 'No')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">RC4 With Modern</span>{boolVulnBadge(details.rc4WithModern, 'Yes', 'No')}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">TLS FALLBACK_SCSV</span>{boolSafeBadge(details.fallbackScsv, 'Supported', 'Not supported')}</div>

          {/* Integer fields with specific value mappings */}
          <div className="flex items-center justify-between"><span className="text-slate-400">POODLE (TLS)</span>{intVulnBadge(details.poodleTls, {
            [-3]: { text: 'Timeout', variant: 'warning' },
            [-2]: { text: 'TLS not supported', variant: 'default' },
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [2]: { text: 'Vulnerable', variant: 'error' },
          })}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">OpenSSL CCS (CVE-2014-0224)</span>{intVulnBadge(details.openSslCcs, {
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [2]: { text: 'Possibly vulnerable', variant: 'warning' },
            [3]: { text: 'Vulnerable & exploitable', variant: 'error' },
          })}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">Lucky Minus 20 (CVE-2016-2107)</span>{intVulnBadge(details.openSSLLuckyMinus20, {
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [2]: { text: 'Vulnerable & insecure', variant: 'error' },
          })}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">Ticketbleed (CVE-2016-9244)</span>{intVulnBadge(details.ticketbleed, {
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [2]: { text: 'Vulnerable', variant: 'error' },
            [3]: { text: 'Similar bug detected', variant: 'warning' },
          })}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">Bleichenbacher (ROBOT)</span>{intVulnBadge(details.bleichenbacher, {
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [2]: { text: 'Vulnerable (weak)', variant: 'error' },
            [3]: { text: 'Vulnerable (strong)', variant: 'error' },
            [4]: { text: 'Inconsistent results', variant: 'warning' },
          })}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">Zombie POODLE</span>{intVulnBadge(details.zombiePoodle, {
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [2]: { text: 'Vulnerable', variant: 'error' },
            [3]: { text: 'Vulnerable & exploitable', variant: 'error' },
          })}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">Golden Doodle</span>{intVulnBadge(details.goldenDoodle, {
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [4]: { text: 'Vulnerable', variant: 'error' },
            [5]: { text: 'Vulnerable & exploitable', variant: 'error' },
          })}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">Sleeping POODLE</span>{intVulnBadge(details.sleepingPoodle, {
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [10]: { text: 'Vulnerable', variant: 'error' },
            [11]: { text: 'Vulnerable & exploitable', variant: 'error' },
          })}</div>
          <div className="flex items-center justify-between"><span className="text-slate-400">0-Length Padding Oracle (CVE-2019-1559)</span>{intVulnBadge(details.zeroLengthPaddingOracle, {
            [-1]: { text: 'Test failed', variant: 'warning' },
            [0]: { text: 'Unknown', variant: 'default' },
            [1]: { text: 'Not vulnerable', variant: 'success' },
            [6]: { text: 'Vulnerable', variant: 'error' },
            [7]: { text: 'Vulnerable & exploitable', variant: 'error' },
          })}</div>

          {/* Bitmask field */}
          <div className="flex items-center justify-between"><span className="text-slate-400">Forward Secrecy</span>{forwardSecrecyBadge(details.forwardSecrecy)}</div>

          {/* 0-RTT (TLS 1.3 only) */}
          <div className="flex items-center justify-between"><span className="text-slate-400">0-RTT (TLS 1.3)</span>{intVulnBadge(details.zeroRTTEnabled, {
            [-2]: { text: 'Test failed', variant: 'warning' },
            [-1]: { text: 'Not performed', variant: 'default' },
            [0]: { text: 'Not enabled', variant: 'success' },
            [1]: { text: 'Enabled', variant: 'error' },
          })}</div>
        </div>
      </div>

      {/* SNI & Chain Info */}
      {(details.sniRequired != null || certChains.length > 0) && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">Server Configuration</h4>
          <div className="grid grid-cols-2 gap-2 text-sm">
            {details.sniRequired != null && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">SNI Required</span>
                <Badge variant={details.sniRequired ? 'info' : 'success'} size="sm">
                  <span className="inline-flex items-center gap-1">
                    {details.sniRequired ? <AlertTriangle className="h-3 w-3" /> : <CheckCircle2 className="h-3 w-3" />}
                    {details.sniRequired ? 'Yes — site only works with SNI' : 'No — accessible without SNI'}
                  </span>
                </Badge>
              </div>
            )}
            {details.noSniSuites && details.noSniSuites.list && details.noSniSuites.list.length > 0 && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">No-SNI Cipher Suites</span>
                <Badge variant="warning" size="sm">{details.noSniSuites.list.length} suite(s) without SNI</Badge>
              </div>
            )}
          </div>

          {/* Chain issues */}
          {certChains.length > 0 && (
            <div className="border-t border-slate-800 pt-3 space-y-2">
              <p className="text-xs text-slate-500 uppercase tracking-wider">Certificate Chain Issues</p>
              {certChains.map((chain: any, ci: number) => {
                const chainIssues = chain.issues || 0
                const hasIssues = chainIssues > 0
                const noSni = chain.noSni
                return (
                  <div key={ci} className="text-xs space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500">Chain {ci + 1}{noSni ? ' (no SNI)' : ''}:</span>
                      {hasIssues ? (
                        <div className="flex flex-wrap gap-1">
                          {chainIssues & 2 && <Badge variant="warning" size="sm">Incomplete chain</Badge>}
                          {chainIssues & 4 && <Badge variant="warning" size="sm">Unrelated/duplicate certs</Badge>}
                          {chainIssues & 8 && <Badge variant="warning" size="sm">Incorrect order</Badge>}
                          {chainIssues & 16 && <Badge variant="default" size="sm">Self-signed root included</Badge>}
                          {chainIssues & 32 && <Badge variant="error" size="sm">Could not validate chain</Badge>}
                        </div>
                      ) : (
                        <Badge variant="success" size="sm"><span className="inline-flex items-center gap-1"><CheckCircle2 className="h-3 w-3" />No issues</span></Badge>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* Certificate Chain — matching certs only */}
      {(() => {
        const matchingCerts = certs.filter((c: any) => !(c.issues & 8))
        const mismatchedCerts = certs.filter((c: any) => !!(c.issues & 8))
        const renderCert = (cert: any, i: number) => (
          <div key={cert.id || i} className="border border-slate-800 rounded-lg p-3 space-y-2">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm font-semibold text-slate-200">{cert.subject}</p>
                <p className="text-xs text-slate-500">Issuer: {cert.issuerSubject}</p>
              </div>
              <div className="flex flex-wrap gap-1 justify-end">
                {cert.validationType === 'E' && <Badge variant="info" size="sm">EV</Badge>}
                {cert.sct && <span title="Signed Certificate Timestamp — certificate is logged in a Certificate Transparency log"><Badge variant="success" size="sm">SCT</Badge></span>}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs text-slate-400">
              <div><span className="text-slate-500">Key:</span> {cert.keyAlg} {cert.keySize}-bit (strength: {cert.keyStrength})</div>
              <div><span className="text-slate-500">Signature:</span> {cert.sigAlg}</div>
              <div><span className="text-slate-500">Not Before:</span> {cert.notBefore ? formatDateTime(new Date(cert.notBefore).toISOString()) : '-'}</div>
              <div><span className="text-slate-500">Not After:</span> {cert.notAfter ? formatDateTime(new Date(cert.notAfter).toISOString()) : '-'}</div>
              <div><span className="text-slate-500">Serial:</span> <span className="font-mono">{cert.serialNumber}</span></div>
              <div><span className="text-slate-500">SHA256:</span> <span className="font-mono text-[10px]">{cert.sha256Hash?.substring(0, 24)}...</span></div>
              {cert.revocationStatus != null && (
                <div><span className="text-slate-500">Revocation:</span> {intVulnBadge(cert.revocationStatus, {
                  [0]: { text: 'Not checked', variant: 'default' },
                  [1]: { text: 'Revoked', variant: 'error' },
                  [2]: { text: 'Not revoked', variant: 'success' },
                  [3]: { text: 'Check error', variant: 'warning' },
                  [4]: { text: 'No revocation info', variant: 'default' },
                  [5]: { text: 'Internal error', variant: 'warning' },
                })}</div>
              )}
              {cert.issues && cert.issues > 0 && (
                <div className="col-span-2 flex flex-wrap gap-1">
                  {cert.issues & 1 && <Badge variant="error" size="sm">No chain of trust</Badge>}
                  {cert.issues & 2 && <Badge variant="warning" size="sm">Not yet valid</Badge>}
                  {cert.issues & 4 && <Badge variant="error" size="sm">Expired</Badge>}
                  {cert.issues & 8 && <Badge variant="error" size="sm">Hostname mismatch</Badge>}
                  {cert.issues & 16 && <Badge variant="error" size="sm">Revoked</Badge>}
                  {cert.issues & 32 && <Badge variant="warning" size="sm">Bad common name</Badge>}
                  {cert.issues & 64 && <Badge variant="warning" size="sm">Self-signed</Badge>}
                  {cert.issues & 128 && <Badge variant="error" size="sm">Blacklisted</Badge>}
                  {cert.issues & 256 && <Badge variant="error" size="sm">Insecure signature</Badge>}
                  {cert.issues & 512 && <Badge variant="error" size="sm">Insecure key</Badge>}
                </div>
              )}
            </div>
            {cert.altNames && cert.altNames.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {cert.altNames.map((name: string, j: number) => (
                  <Badge key={j} variant="default" size="sm">{name}</Badge>
                ))}
              </div>
            )}
            {/* Trust paths */}
            {certChains.map((chain: any, ci: number) => {
              const trustPaths = chain.trustPaths || []
              const relevantTrust = trustPaths.filter((tp: any) => tp.certIds?.[0] === cert.id)
              if (relevantTrust.length === 0) return null
              return (
                <div key={ci} className="flex flex-wrap gap-2">
                  {relevantTrust.flatMap((tp: any, ti: number) =>
                    (tp.trust || []).map((tr: any, tri: number) => (
                      <Badge key={`${ci}-${ti}-${tri}`} variant={tr.isTrusted ? 'success' : 'error'} size="sm">
                        {tr.rootStore}: {tr.isTrusted ? 'Trusted' : 'Not trusted'}
                      </Badge>
                    ))
                  )}
                </div>
              )
            })}
          </div>
        )
        return (
          <>
            {matchingCerts.length > 0 && (
              <div className="card space-y-3">
                <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.certificateChain')}</h4>
                <div className="space-y-4">
                  {matchingCerts.map((cert: any, i: number) => renderCert(cert, i))}
                </div>
              </div>
            )}
            {mismatchedCerts.length > 0 && (
              <div className="card space-y-3 border-amber-500/30">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-amber-400" />
                  <h4 className="text-sm font-semibold uppercase tracking-wider text-amber-400">Default / Non-SNI Certificate(s)</h4>
                </div>
                <p className="text-xs text-amber-400/70">
                  The server presented this certificate when probed without SNI. This is normal for shared listeners with multiple certificates — the server uses this as the default fallback for non-SNI clients. Modern browsers use SNI and will receive the correct certificate for <span className="font-mono font-semibold">{host}</span>.
                </p>
                <div className="space-y-4">
                  {mismatchedCerts.map((cert: any, i: number) => renderCert(cert, i))}
                </div>
              </div>
            )}
          </>
        )
      })()}

      {/* Certificate Transparency */}
      {details.hasSct != null && details.hasSct > 0 && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">Certificate Transparency (SCT)</h4>
          <p className="text-xs text-slate-500">Signed Certificate Timestamps prove the certificate was publicly logged. Browsers require SCTs for trust.</p>
          <div className="flex flex-wrap gap-2">
            {details.hasSct & 1 && <Badge variant="success" size="sm"><span className="inline-flex items-center gap-1"><CheckCircle2 className="h-3 w-3" />Embedded in certificate</span></Badge>}
            {details.hasSct & 2 && <Badge variant="success" size="sm"><span className="inline-flex items-center gap-1"><CheckCircle2 className="h-3 w-3" />In stapled OCSP response</span></Badge>}
            {details.hasSct & 4 && <Badge variant="success" size="sm"><span className="inline-flex items-center gap-1"><CheckCircle2 className="h-3 w-3" />In TLS extension (ServerHello)</span></Badge>}
          </div>
        </div>
      )}

      {/* HSTS */}
      {hsts && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.hsts')}</h4>
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Status</span>
              <Badge variant={hsts.status === 'present' ? 'success' : hsts.status === 'invalid' || hsts.status === 'disabled' ? 'error' : 'warning'} size="sm">{hsts.status}</Badge>
            </div>
            {hsts.maxAge && <div className="flex justify-between"><span className="text-slate-400">Max Age</span><span>{hsts.maxAge}s</span></div>}
            <div className="flex justify-between"><span className="text-slate-400">Include Subdomains</span>{hsts.includeSubDomains === undefined || hsts.includeSubDomains === null ? <span className="text-slate-500">-</span> : <Badge variant={hsts.includeSubDomains ? 'success' : 'default'} size="sm">{hsts.includeSubDomains ? 'Yes' : 'No'}</Badge>}</div>
            <div className="flex justify-between"><span className="text-slate-400">Preload</span>{hsts.preload === undefined || hsts.preload === null ? <span className="text-slate-500">-</span> : <Badge variant={hsts.preload ? 'success' : 'default'} size="sm">{hsts.preload ? 'Yes' : 'No'}</Badge>}</div>
            {hsts.header && <div className="text-xs font-mono text-slate-500 mt-2">{hsts.header}</div>}
            {hsts.error && <p className="text-xs text-red-400">{hsts.error}</p>}
          </div>
        </div>
      )}

      {/* HPKP */}
      {hpkp && hpkp.status !== 'absent' && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.hpkp')}</h4>
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Status</span>
              <Badge variant={hpkp.status === 'valid' ? 'success' : hpkp.status === 'invalid' || hpkp.status === 'forbidden' ? 'error' : 'warning'} size="sm">{hpkp.status}</Badge>
            </div>
            {hpkp.maxAge != null && <div className="flex justify-between"><span className="text-slate-400">Max Age</span><span>{hpkp.maxAge}s</span></div>}
            {hpkp.includeSubDomains != null && <div className="flex justify-between"><span className="text-slate-400">Include Subdomains</span><Badge variant={hpkp.includeSubDomains ? 'success' : 'default'} size="sm">{hpkp.includeSubDomains ? 'Yes' : 'No'}</Badge></div>}
            {hpkp.reportUri && <div className="flex justify-between"><span className="text-slate-400">Report URI</span><span className="text-xs font-mono text-slate-300">{hpkp.reportUri}</span></div>}
            {hpkp.error && <p className="text-xs text-red-400">{hpkp.error}</p>}
            {hpkp.header && <div className="text-xs font-mono text-slate-500 mt-2">{hpkp.header}</div>}
          </div>
        </div>
      )}

      {/* Client Simulations */}
      {sims.length > 0 && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.clientSimulations')}</h4>
          <div className="overflow-x-auto max-h-96">
            <table className="w-full text-xs text-start">
              <thead className="text-slate-400 border-b border-slate-800 sticky top-0 bg-slate-900">
                <tr>
                  <th>Client</th>
                  <th>Platform</th>
                  <th>Version</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {sims.map((sim: any, i: number) => {
                  const c = sim.client || {}
                  const ok = sim.errorCode === 0
                  return (
                    <tr key={i} className="border-b border-slate-800/50 last:border-0">
                      <td className="py-1">
                        {c.name}
                        {c.isReference && <span className="text-amber-400 ms-1" title="Reference client">*</span>}
                      </td>
                      <td className="text-slate-500">{c.platform || '-'}</td>
                      <td className="text-slate-400">{c.version}</td>
                      <td>
                        {ok ? (
                          <span className="text-green-400 flex items-center gap-1">
                            <CheckCircle2 className="h-3 w-3" />
                            {sim.suiteName || 'OK'}
                          </span>
                        ) : (
                          <span className="text-red-400 flex items-center gap-1">
                            <XCircle className="h-3 w-3" />
                            {sim.errorMessage || `Error ${sim.errorCode}`}
                          </span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* HTTP Transaction */}
      {httpTransactions.length > 0 && (
        <div className="card space-y-3">
          <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.report.httpTransaction')}</h4>
          {httpTransactions.map((txn: any, i: number) => (
            <div key={i} className="space-y-2">
              <div className="text-xs">
                {txn.requestUrl && <p className="text-slate-500 font-mono">{txn.requestUrl}</p>}
                <p className="text-slate-300 font-mono">{txn.requestLine}</p>
                <p className={`font-mono ${txn.statusCode && txn.statusCode >= 400 ? 'text-red-400' : 'text-green-400'}`}>{txn.responseLine}</p>
              </div>
              {txn.responseHeaders && txn.responseHeaders.length > 0 && (
                <div className="text-xs space-y-1">
                  <p className="text-slate-500 uppercase tracking-wider">Response Headers</p>
                  <div className="font-mono text-slate-400 space-y-0.5 max-h-48 overflow-y-auto">
                    {txn.responseHeaders.map((h: any, j: number) => (
                      <div key={j}><span className="text-slate-500">{h.name}:</span> {h.value}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
          {httpTransactions.some((txn: any) => txn.fragileServer) && (
            <p className="text-xs text-amber-400">Warning: server appears fragile (crashes when inspected).</p>
          )}
        </div>
      )}
    </div>
  )
}
