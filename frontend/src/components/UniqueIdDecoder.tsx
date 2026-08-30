import { useState, FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Fingerprint, RotateCcw } from 'lucide-react'
import { decodeUniqueId, DecodedUniqueId } from '../lib/uniqueId'

interface UniqueIdDecoderProps {
  className?: string
}

export default function UniqueIdDecoder({ className }: UniqueIdDecoderProps) {
  const { t } = useTranslation(['pages', 'common'])
  const [input, setInput] = useState('')
  const [result, setResult] = useState<
    | { decoded: DecodedUniqueId; error?: undefined }
    | { decoded?: undefined; error: string }
    | null
  >(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const res = decodeUniqueId(input)
    if (res.valid && res.decoded) {
      setResult({ decoded: res.decoded })
    } else {
      setResult({ error: res.error || t('pages:uniqueIdDecoder.invalidUniqueId') })
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
        {t('pages:uniqueIdDecoder.title')}
      </h3>
      <div className="space-y-4">
        <div>
          <label htmlFor="unique-id-input" className="label">
            {t('pages:uniqueIdDecoder.label')}
          </label>
          <form onSubmit={handleSubmit} className="flex gap-2">
            <input
              id="unique-id-input"
              type="text"
              className="input font-mono"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={t('pages:uniqueIdDecoder.placeholder')}
            />
            <button type="submit" className="btn-primary shrink-0">
              {t('pages:uniqueIdDecoder.decode')}
            </button>
            <button type="button" onClick={handleReset} className="btn-secondary shrink-0">
              <RotateCcw className="h-4 w-4" />
            </button>
          </form>
        </div>

        {result?.error && <p className="text-sm text-red-400">{result.error}</p>}

        {result?.decoded && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <DecodedField label={t('pages:uniqueIdDecoder.fields.clientIp')} value={result.decoded.clientIp} />
            <DecodedField
              label={t('pages:uniqueIdDecoder.fields.clientPort')}
              value={result.decoded.clientPort.toString()}
            />
            <DecodedField
              label={t('pages:uniqueIdDecoder.fields.timestamp')}
              value={result.decoded.timestampFormatted}
              sub={t('pages:uniqueIdDecoder.fields.timestampSub', { value: result.decoded.timestamp })}
              className="sm:col-span-2"
            />
            <DecodedField
              label={t('pages:uniqueIdDecoder.fields.requestCounter')}
              value={result.decoded.requestCounter.toString()}
            />
            <DecodedField label={t('pages:uniqueIdDecoder.fields.processId')} value={result.decoded.pid.toString()} />
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
