import { useState, FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { FileText, RotateCcw } from 'lucide-react'
import { decodeReqFp, DecodedReqFp } from '../lib/reqFp'

interface ReqFpDecoderProps {
  className?: string
}

export default function ReqFpDecoder({ className }: ReqFpDecoderProps) {
  const { t } = useTranslation(['pages', 'common'])
  const [input, setInput] = useState('')
  const [result, setResult] = useState<
    | { decoded: DecodedReqFp; error?: undefined }
    | { decoded?: undefined; error: string }
    | null
  >(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const res = decodeReqFp(input)
    if (res.valid && res.decoded) {
      setResult({ decoded: res.decoded })
    } else {
      setResult({ error: res.error || t('pages:reqFpDecoder.invalidReqFp') })
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
        <FileText className="h-5 w-5 text-primary" />
        Request Fingerprint Decoder
      </h3>
      <div className="space-y-4">
        <div>
          <label htmlFor="reqfp-input" className="label">
            HTTP request fingerprint (17 fields)
          </label>
          <form onSubmit={handleSubmit} className="flex gap-2">
            <input
              id="reqfp-input"
              type="text"
              className="input font-mono"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="7nQ_ge_11_01_nil_nil_0_0000_05_achru_0000_n_n_nil_n_200_1024"
            />
            <button type="submit" className="btn-primary shrink-0">
              Decode
            </button>
            <button type="button" onClick={handleReset} className="btn-secondary shrink-0">
              <RotateCcw className="h-4 w-4" />
            </button>
          </form>
        </div>

        {result?.error && <p className="text-sm text-red-400">{result.error}</p>}

        {result?.decoded && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <DecodedField
              label="Path (base62)"
              value={result.decoded.pathB62}
              sub={result.decoded.pathDecoded ? `decoded: ${result.decoded.pathDecoded}` : undefined}
              className="sm:col-span-2"
            />
            <DecodedField label="Method" value={result.decoded.method} />
            <DecodedField label="HTTP Version" value={result.decoded.httpVersion} />
            <DecodedField label="Path Depth" value={result.decoded.pathDepth.toString()} />
            <DecodedField label="Param Keys" value={result.decoded.paramKeys} />
            <DecodedField label="Param Types" value={result.decoded.paramTypes} />
            <DecodedField label="Param Lengths" value={result.decoded.paramLens} />
            <DecodedField label="Request Content-Type" value={result.decoded.reqContentType} />
            <DecodedField label="Header Count" value={result.decoded.headerCount.toString()} />
            <DecodedField label="Header List" value={result.decoded.headerList} />
            <DecodedField label="Accept-Language" value={result.decoded.acceptLanguage} />
            <DecodedField label="Auth Type" value={result.decoded.authType} />
            <DecodedField label="Cookie" value={result.decoded.cookie} />
            <DecodedField label="Cookie Fields" value={result.decoded.cookieFields} />
            <DecodedField label="Referer" value={result.decoded.referer} />
            <DecodedField label="Response Status" value={result.decoded.status.toString()} />
            <DecodedField
              label="Response Body Bytes"
              value={result.decoded.bodyBytes.toString()}
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
