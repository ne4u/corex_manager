import { useState, FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Fingerprint, RotateCcw } from 'lucide-react'
import { decodeJa4, DecodedJa4 } from '../lib/ja4'

interface Ja4DecoderProps {
  className?: string
}

export default function Ja4Decoder({ className }: Ja4DecoderProps) {
  const { t } = useTranslation(['pages', 'common'])
  const [input, setInput] = useState('')
  const [result, setResult] = useState<
    | { decoded: DecodedJa4; error?: undefined }
    | { decoded?: undefined; error: string }
    | null
  >(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const res = decodeJa4(input)
    if (res.valid && res.decoded) {
      setResult({ decoded: res.decoded })
    } else {
      setResult({ error: res.error || t('pages:ja4Decoder.invalidJa4') })
    }
  }

  const handleReset = () => {
    setInput('')
    setResult(null)
  }

  const wrapperClass = `card ${className || ''}`.trim()

  return (
    <div className={wrapperClass}>
      <h3 className="font-semibold mb-4 flex items-center gap-2">
        <Fingerprint className="h-5 w-5 text-primary" />
        {t('pages:ja4Decoder.title')}
      </h3>
      <div className="space-y-4">
        <div>
          <label htmlFor="ja4-input" className="label">
            {t('pages:ja4Decoder.label')}
          </label>
          <form onSubmit={handleSubmit} className="flex gap-2">
            <input
              id="ja4-input"
              type="text"
              className="input font-mono"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={t('pages:ja4Decoder.placeholder')}
            />
            <button type="submit" className="btn-primary shrink-0">
              {t('pages:ja4Decoder.decode')}
            </button>
            <button type="button" onClick={handleReset} className="btn-secondary shrink-0">
              <RotateCcw className="h-4 w-4" />
            </button>
          </form>
        </div>

        {result?.error && <p className="text-sm text-red-400">{result.error}</p>}

        {result?.decoded && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <DecodedField label={t('pages:ja4Decoder.fields.protocol')} value={result.decoded.protocol} />
            <DecodedField label={t('pages:ja4Decoder.fields.tlsVersion')} value={result.decoded.tlsVersion} />
            <DecodedField label={t('pages:ja4Decoder.fields.sni')} value={result.decoded.sni} />
            <DecodedField label={t('pages:ja4Decoder.fields.alpn')} value={result.decoded.alpn} />
            <DecodedField label={t('pages:ja4Decoder.fields.cipherCount')} value={result.decoded.cipherCount.toString()} />
            <DecodedField label={t('pages:ja4Decoder.fields.extensionCount')} value={result.decoded.extensionCount.toString()} />
            <DecodedField
              label={t('pages:ja4Decoder.fields.cipherHash')}
              value={result.decoded.cipherHash}
              sub={t('pages:ja4Decoder.fields.cipherHashSub')}
              className="sm:col-span-2"
            />
            <DecodedField
              label={t('pages:ja4Decoder.fields.extensionHash')}
              value={result.decoded.extensionHash}
              sub={t('pages:ja4Decoder.fields.extensionHashSub')}
              className="sm:col-span-2"
            />
          </div>
        )}
      </div>
    </div>
  )
}

interface DecodedFieldProps {
  label: string
  value: string
  sub?: string
  className?: string
}

function DecodedField({ label, value, sub, className }: DecodedFieldProps) {
  return (
    <div className={`bg-slate-950 rounded-lg p-3 border border-slate-800 ${className || ''}`.trim()}>
      <p className="text-xs text-slate-400 mb-1">{label}</p>
      <p className="font-mono font-medium break-all">{value}</p>
      {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
    </div>
  )
}
