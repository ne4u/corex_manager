import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Fingerprint, FileText, Gauge, HardDrive, Wand2, ShieldCheck, Image, Network } from 'lucide-react'
import { settings, apiArmor, securityLists } from '../services/api'

export default function FeatureFlags() {
  const { t } = useTranslation(['pages', 'common'])

  const [ja4Enabled, setJa4Enabled] = useState(true)
  const [ja4Saving, setJa4Saving] = useState(false)
  const [ja4Message, setJa4Message] = useState('')

  const [reqFpEnabled, setReqFpEnabled] = useState(false)
  const [reqFpSaving, setReqFpSaving] = useState(false)
  const [reqFpMessage, setReqFpMessage] = useState('')

  const [reqFpParseBody, setReqFpParseBody] = useState(false)
  const [reqFpParseBodySaving, setReqFpParseBodySaving] = useState(false)
  const [reqFpParseBodyMessage, setReqFpParseBodyMessage] = useState('')

  const [reqFpMaxBodyBytes, setReqFpMaxBodyBytes] = useState(1048576)
  const [reqFpMaxBodyBytesSaving, setReqFpMaxBodyBytesSaving] = useState(false)
  const [reqFpMaxBodyBytesMessage, setReqFpMaxBodyBytesMessage] = useState('')

  const [reqFpEnforceMaxBody, setReqFpEnforceMaxBody] = useState(false)
  const [reqFpEnforceMaxBodySaving, setReqFpEnforceMaxBodySaving] = useState(false)
  const [reqFpEnforceMaxBodyMessage, setReqFpEnforceMaxBodyMessage] = useState('')

  const [compressionEnabled, setCompressionEnabled] = useState(false)
  const [compressionSaving, setCompressionSaving] = useState(false)
  const [compressionMessage, setCompressionMessage] = useState('')

  const [diskCacheEnabled, setDiskCacheEnabled] = useState(false)
  const [diskCacheSaving, setDiskCacheSaving] = useState(false)
  const [diskCacheMessage, setDiskCacheMessage] = useState('')

  const [respTransformEnabled, setRespTransformEnabled] = useState(false)
  const [respTransformSaving, setRespTransformSaving] = useState(false)
  const [respTransformMessage, setRespTransformMessage] = useState('')

  const [img2WebpEnabled, setImg2WebpEnabled] = useState(false)
  const [img2WebpSaving, setImg2WebpSaving] = useState(false)
  const [img2WebpMessage, setImg2WebpMessage] = useState('')

  const [apiArmorEnabled, setApiArmorEnabled] = useState(false)
  const [apiArmorSaving, setApiArmorSaving] = useState(false)
  const [apiArmorMessage, setApiArmorMessage] = useState('')

  const [mcpGatewayEnabled, setMcpGatewayEnabled] = useState(false)
  const [mcpGatewaySaving, setMcpGatewaySaving] = useState(false)
  const [mcpGatewayMessage, setMcpGatewayMessage] = useState('')

  const [trustedNetworkLists, setTrustedNetworkLists] = useState<string[]>([])
  const [networkLists, setNetworkLists] = useState<{ id: number; name: string }[]>([])
  const [trustedSaving, setTrustedSaving] = useState(false)
  const [trustedMessage, setTrustedMessage] = useState('')

  useEffect(() => {
    settings.get('ja4_enabled')
      .then((r) => setJa4Enabled((r.data.value || 'true').toLowerCase() === 'true'))
      .catch(() => setJa4Enabled(true))
    settings.get('req_fp_enabled')
      .then((r) => setReqFpEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setReqFpEnabled(false))
    settings.get('req_fp_parse_body')
      .then((r) => setReqFpParseBody((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setReqFpParseBody(false))
    settings.get('req_fp_max_body_bytes')
      .then((r) => setReqFpMaxBodyBytes(Number(r.data.value) || 1048576))
      .catch(() => setReqFpMaxBodyBytes(1048576))
    settings.get('req_fp_enforce_max_body')
      .then((r) => setReqFpEnforceMaxBody((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setReqFpEnforceMaxBody(false))
    settings.get('compression_enabled')
      .then((r) => setCompressionEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setCompressionEnabled(false))
    settings.get('disk_cache_enabled')
      .then((r) => setDiskCacheEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setDiskCacheEnabled(false))
    settings.get('resp_transform_enabled')
      .then((r) => setRespTransformEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setRespTransformEnabled(false))
    settings.get('img_2_webp_enabled')
      .then((r) => setImg2WebpEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setImg2WebpEnabled(false))
    apiArmor.settings.get()
      .then((r) => setApiArmorEnabled(r.data.api_armor_enabled || false))
      .catch(() => setApiArmorEnabled(false))
    settings.get('mcp_gateway_enabled')
      .then((r) => setMcpGatewayEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setMcpGatewayEnabled(false))
    settings.get('restore_client_ip_trusted_network_list')
      .then((r) => {
        const raw = r.data.value || ''
        setTrustedNetworkLists(raw ? raw.split(',').map((s: string) => s.trim()).filter(Boolean) : [])
      })
      .catch(() => setTrustedNetworkLists([]))
    securityLists.network.list()
      .then((r) => setNetworkLists((r.data || []).map((l: any) => ({ id: l.id, name: l.name }))))
      .catch(() => setNetworkLists([]))
  }, [])

  const saveJa4 = async () => {
    setJa4Saving(true)
    setJa4Message('')
    try {
      await settings.update('ja4_enabled', { value: String(ja4Enabled) })
      setJa4Message(ja4Enabled ? t('pages:globalOptions.ja4.enabled') : t('pages:globalOptions.ja4.disabled'))
    } catch (err: any) {
      setJa4Message(err?.response?.data?.detail || t('pages:globalOptions.ja4.failedToSave'))
    } finally {
      setJa4Saving(false)
    }
  }

  const saveReqFp = async () => {
    setReqFpSaving(true)
    setReqFpMessage('')
    try {
      await settings.update('req_fp_enabled', { value: String(reqFpEnabled) })
      setReqFpMessage(reqFpEnabled ? t('pages:globalOptions.reqFp.enabled') : t('pages:globalOptions.reqFp.disabled'))
    } catch (err: any) {
      setReqFpMessage(err?.response?.data?.detail || t('pages:globalOptions.reqFp.failedToSave'))
    } finally {
      setReqFpSaving(false)
    }
  }

  const saveReqFpParseBody = async () => {
    setReqFpParseBodySaving(true)
    setReqFpParseBodyMessage('')
    try {
      await settings.update('req_fp_parse_body', { value: String(reqFpParseBody) })
      setReqFpParseBodyMessage(reqFpParseBody ? t('pages:globalOptions.reqFp.parseBody.enabled') : t('pages:globalOptions.reqFp.parseBody.disabled'))
    } catch (err: any) {
      setReqFpParseBodyMessage(err?.response?.data?.detail || t('pages:globalOptions.reqFp.parseBody.failedToSave'))
    } finally {
      setReqFpParseBodySaving(false)
    }
  }

  const saveReqFpMaxBodyBytes = async () => {
    setReqFpMaxBodyBytesSaving(true)
    setReqFpMaxBodyBytesMessage('')
    try {
      const v = Math.max(0, Math.floor(reqFpMaxBodyBytes))
      await settings.update('req_fp_max_body_bytes', { value: String(v) })
      setReqFpMaxBodyBytes(v)
      setReqFpMaxBodyBytesMessage(t('pages:globalOptions.reqFp.maxBodyBytes.saved'))
    } catch (err: any) {
      setReqFpMaxBodyBytesMessage(err?.response?.data?.detail || t('pages:globalOptions.reqFp.maxBodyBytes.failedToSave'))
    } finally {
      setReqFpMaxBodyBytesSaving(false)
    }
  }

  const saveReqFpEnforceMaxBody = async () => {
    setReqFpEnforceMaxBodySaving(true)
    setReqFpEnforceMaxBodyMessage('')
    try {
      await settings.update('req_fp_enforce_max_body', { value: String(reqFpEnforceMaxBody) })
      setReqFpEnforceMaxBodyMessage(reqFpEnforceMaxBody ? t('pages:globalOptions.reqFp.enforceMaxBody.enabled') : t('pages:globalOptions.reqFp.enforceMaxBody.disabled'))
    } catch (err: any) {
      setReqFpEnforceMaxBodyMessage(err?.response?.data?.detail || t('pages:globalOptions.reqFp.enforceMaxBody.failedToSave'))
    } finally {
      setReqFpEnforceMaxBodySaving(false)
    }
  }

  const saveCompression = async () => {
    setCompressionSaving(true)
    setCompressionMessage('')
    try {
      await settings.update('compression_enabled', { value: String(compressionEnabled) })
      setCompressionMessage(compressionEnabled ? t('pages:globalOptions.compression.enabled') : t('pages:globalOptions.compression.disabled'))
    } catch (err: any) {
      setCompressionMessage(err?.response?.data?.detail || t('pages:globalOptions.compression.failedToSave'))
    } finally {
      setCompressionSaving(false)
    }
  }

  const saveDiskCache = async () => {
    setDiskCacheSaving(true)
    setDiskCacheMessage('')
    try {
      await settings.update('disk_cache_enabled', { value: String(diskCacheEnabled) })
      setDiskCacheMessage(diskCacheEnabled ? t('pages:globalOptions.diskCache.enabled') : t('pages:globalOptions.diskCache.disabled'))
    } catch (err: any) {
      setDiskCacheMessage(err?.response?.data?.detail || t('pages:globalOptions.diskCache.failedToSave'))
    } finally {
      setDiskCacheSaving(false)
    }
  }

  const saveRespTransform = async () => {
    setRespTransformSaving(true)
    setRespTransformMessage('')
    try {
      await settings.update('resp_transform_enabled', { value: String(respTransformEnabled) })
      setRespTransformMessage(respTransformEnabled ? t('pages:globalOptions.respTransform.enabled') : t('pages:globalOptions.respTransform.disabled'))
      // Notify Layout to re-fetch feature flags so the nav menu updates.
      window.dispatchEvent(new Event('feature-flags-changed'))
    } catch (err: any) {
      setRespTransformMessage(err?.response?.data?.detail || t('pages:globalOptions.respTransform.failedToSave'))
    } finally {
      setRespTransformSaving(false)
    }
  }

  const saveImg2Webp = async () => {
    setImg2WebpSaving(true)
    setImg2WebpMessage('')
    try {
      await settings.update('img_2_webp_enabled', { value: String(img2WebpEnabled) })
      setImg2WebpMessage(img2WebpEnabled ? t('pages:globalOptions.img2Webp.enabled') : t('pages:globalOptions.img2Webp.disabled'))
    } catch (err: any) {
      setImg2WebpMessage(err?.response?.data?.detail || t('pages:globalOptions.img2Webp.failedToSave'))
    } finally {
      setImg2WebpSaving(false)
    }
  }

  const saveApiArmor = async () => {
    setApiArmorSaving(true)
    setApiArmorMessage('')
    try {
      await apiArmor.settings.update({ api_armor_enabled: apiArmorEnabled })
      setApiArmorMessage(apiArmorEnabled ? t('pages:globalOptions.apiArmor.enabled') : t('pages:globalOptions.apiArmor.disabled'))
      window.dispatchEvent(new Event('feature-flags-changed'))
    } catch (err: any) {
      setApiArmorMessage(err?.response?.data?.detail || t('pages:globalOptions.apiArmor.failedToSave'))
    } finally {
      setApiArmorSaving(false)
    }
  }

  const saveMcpGateway = async () => {
    setMcpGatewaySaving(true)
    setMcpGatewayMessage('')
    try {
      await settings.update('mcp_gateway_enabled', { value: String(mcpGatewayEnabled) })
      setMcpGatewayMessage(mcpGatewayEnabled ? t('pages:featureFlags.mcpGateway.enabledMsg') : t('pages:featureFlags.mcpGateway.disabledMsg'))
      window.dispatchEvent(new Event('feature-flags-changed'))
    } catch (err: any) {
      setMcpGatewayMessage(err?.response?.data?.detail || t('pages:featureFlags.mcpGateway.saveFailed'))
    } finally {
      setMcpGatewaySaving(false)
    }
  }

  const saveTrustedNetworkList = async () => {
    setTrustedSaving(true)
    setTrustedMessage('')
    try {
      const value = trustedNetworkLists.join(',')
      await settings.update('restore_client_ip_trusted_network_list', { value })
      setTrustedMessage(trustedNetworkLists.length > 0 ? t('pages:featureFlags.restoreClientIp.savedMsg') : t('pages:featureFlags.restoreClientIp.clearedMsg'))
    } catch (err: any) {
      setTrustedMessage(err?.response?.data?.detail || t('pages:featureFlags.restoreClientIp.saveFailed'))
    } finally {
      setTrustedSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Fingerprint className="h-5 w-5 text-primary" /> {t('pages:globalOptions.ja4.title')}</h2>
        <p className="text-sm text-slate-400" dangerouslySetInnerHTML={{ __html: t('pages:globalOptions.ja4.description') }} />
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={ja4Enabled}
            onChange={(e) => setJa4Enabled(e.target.checked)}
          />
          <span className="text-sm">{t('pages:globalOptions.ja4.enable')}</span>
        </label>
        <button
          className="btn-primary"
          onClick={saveJa4}
          disabled={ja4Saving}
        >
          {ja4Saving ? t('common:actions.saving') : t('pages:globalOptions.ja4.save')}
        </button>
        {ja4Message && (
          <p className={`text-sm ${ja4Message === t('pages:globalOptions.ja4.enabled') || ja4Message === t('pages:globalOptions.ja4.disabled') ? 'text-green-400' : 'text-red-400'}`}>
            {ja4Message}
          </p>
        )}
      </div>

      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><FileText className="h-5 w-5 text-primary" /> {t('pages:globalOptions.reqFp.title')}</h2>
        <p className="text-sm text-slate-400" dangerouslySetInnerHTML={{ __html: t('pages:globalOptions.reqFp.description') }} />
        <p className="text-xs text-slate-500">{t('pages:globalOptions.reqFp.requiredByApiArmor')}</p>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={reqFpEnabled}
            onChange={(e) => setReqFpEnabled(e.target.checked)}
          />
          <span className="text-sm">{t('pages:globalOptions.reqFp.enable')}</span>
        </label>
        <button
          className="btn-primary"
          onClick={saveReqFp}
          disabled={reqFpSaving}
        >
          {reqFpSaving ? t('common:actions.saving') : t('pages:globalOptions.reqFp.save')}
        </button>
        {reqFpMessage && (
          <p className={`text-sm ${reqFpMessage === t('pages:globalOptions.reqFp.enabled') || reqFpMessage === t('pages:globalOptions.reqFp.disabled') ? 'text-green-400' : 'text-red-400'}`}>
            {reqFpMessage}
          </p>
        )}
        <div className="border-t border-slate-800 pt-4 space-y-3">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={reqFpParseBody}
              onChange={(e) => setReqFpParseBody(e.target.checked)}
              disabled={!reqFpEnabled}
            />
            <span className="text-sm">{t('pages:globalOptions.reqFp.parseBody.enable')}</span>
          </label>
          <p className="text-xs text-slate-500">
            {t('pages:globalOptions.reqFp.parseBody.description')}
          </p>
          <button
            className="btn-primary"
            onClick={saveReqFpParseBody}
            disabled={reqFpParseBodySaving || !reqFpEnabled}
          >
            {reqFpParseBodySaving ? t('common:actions.saving') : t('pages:globalOptions.reqFp.parseBody.save')}
          </button>
          {reqFpParseBodyMessage && (
            <p className={`text-sm ${reqFpParseBodyMessage === t('pages:globalOptions.reqFp.parseBody.enabled') || reqFpParseBodyMessage === t('pages:globalOptions.reqFp.parseBody.disabled') ? 'text-green-400' : 'text-red-400'}`}>
              {reqFpParseBodyMessage}
            </p>
          )}
        </div>
        <div className="border-t border-slate-800 pt-4 space-y-3">
          <label className="flex items-center gap-2">
            <span className="text-sm">{t('pages:globalOptions.reqFp.maxBodyBytes.label')}</span>
            <input
              type="number"
              min={0}
              step={1024}
              value={reqFpMaxBodyBytes}
              onChange={(e) => setReqFpMaxBodyBytes(Number(e.target.value))}
              disabled={!reqFpEnabled || !reqFpParseBody}
              className="input w-40"
            />
            <span className="text-xs text-slate-500">bytes</span>
          </label>
          <p className="text-xs text-slate-500">
            {t('pages:globalOptions.reqFp.maxBodyBytes.description')}
          </p>
          <button
            className="btn-primary"
            onClick={saveReqFpMaxBodyBytes}
            disabled={reqFpMaxBodyBytesSaving || !reqFpEnabled || !reqFpParseBody}
          >
            {reqFpMaxBodyBytesSaving ? t('common:actions.saving') : t('pages:globalOptions.reqFp.maxBodyBytes.save')}
          </button>
          {reqFpMaxBodyBytesMessage && (
            <p className={`text-sm ${reqFpMaxBodyBytesMessage === t('pages:globalOptions.reqFp.maxBodyBytes.saved') ? 'text-green-400' : 'text-red-400'}`}>
              {reqFpMaxBodyBytesMessage}
            </p>
          )}
        </div>
        <div className="border-t border-slate-800 pt-4 space-y-3">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={reqFpEnforceMaxBody}
              onChange={(e) => setReqFpEnforceMaxBody(e.target.checked)}
              disabled={!reqFpEnabled || !reqFpParseBody}
            />
            <span className="text-sm">{t('pages:globalOptions.reqFp.enforceMaxBody.enable')}</span>
          </label>
          <p className="text-xs text-slate-500">
            {t('pages:globalOptions.reqFp.enforceMaxBody.description')}
          </p>
          <button
            className="btn-primary"
            onClick={saveReqFpEnforceMaxBody}
            disabled={reqFpEnforceMaxBodySaving || !reqFpEnabled || !reqFpParseBody}
          >
            {reqFpEnforceMaxBodySaving ? t('common:actions.saving') : t('pages:globalOptions.reqFp.enforceMaxBody.save')}
          </button>
          {reqFpEnforceMaxBodyMessage && (
            <p className={`text-sm ${reqFpEnforceMaxBodyMessage === t('pages:globalOptions.reqFp.enforceMaxBody.enabled') || reqFpEnforceMaxBodyMessage === t('pages:globalOptions.reqFp.enforceMaxBody.disabled') ? 'text-green-400' : 'text-red-400'}`}>
              {reqFpEnforceMaxBodyMessage}
            </p>
          )}
        </div>
      </div>

      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Gauge className="h-5 w-5 text-primary" /> {t('pages:globalOptions.compression.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('pages:globalOptions.compression.description')}
        </p>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={compressionEnabled}
            onChange={(e) => setCompressionEnabled(e.target.checked)}
          />
          <span className="text-sm">{t('pages:globalOptions.compression.enable')}</span>
        </label>
        <button
          className="btn-primary"
          onClick={saveCompression}
          disabled={compressionSaving}
        >
          {compressionSaving ? t('common:actions.saving') : t('pages:globalOptions.compression.save')}
        </button>
        {compressionMessage && (
          <p className={`text-sm ${compressionMessage === t('pages:globalOptions.compression.enabled') || compressionMessage === t('pages:globalOptions.compression.disabled') ? 'text-green-400' : 'text-red-400'}`}>
            {compressionMessage}
          </p>
        )}
      </div>

      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><HardDrive className="h-5 w-5 text-primary" /> {t('pages:globalOptions.diskCache.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('pages:globalOptions.diskCache.description')}
        </p>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={diskCacheEnabled}
            onChange={(e) => setDiskCacheEnabled(e.target.checked)}
          />
          <span className="text-sm">{t('pages:globalOptions.diskCache.enable')}</span>
        </label>
        <button
          className="btn-primary"
          onClick={saveDiskCache}
          disabled={diskCacheSaving}
        >
          {diskCacheSaving ? t('common:actions.saving') : t('pages:globalOptions.diskCache.save')}
        </button>
        {diskCacheMessage && (
          <p className={`text-sm ${diskCacheMessage === t('pages:globalOptions.diskCache.enabled') || diskCacheMessage === t('pages:globalOptions.diskCache.disabled') ? 'text-green-400' : 'text-red-400'}`}>
            {diskCacheMessage}
          </p>
        )}
      </div>

      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Wand2 className="h-5 w-5 text-primary" /> {t('pages:globalOptions.respTransform.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('pages:globalOptions.respTransform.description')}
        </p>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={respTransformEnabled}
            onChange={(e) => setRespTransformEnabled(e.target.checked)}
          />
          <span className="text-sm">{t('pages:globalOptions.respTransform.enable')}</span>
        </label>
        <button
          className="btn-primary"
          onClick={saveRespTransform}
          disabled={respTransformSaving}
        >
          {respTransformSaving ? t('common:actions.saving') : t('pages:globalOptions.respTransform.save')}
        </button>
        {respTransformMessage && (
          <p className={`text-sm ${respTransformMessage === t('pages:globalOptions.respTransform.enabled') || respTransformMessage === t('pages:globalOptions.respTransform.disabled') ? 'text-green-400' : 'text-red-400'}`}>
            {respTransformMessage}
          </p>
        )}
      </div>

      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Image className="h-5 w-5 text-primary" /> {t('pages:globalOptions.img2Webp.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('pages:globalOptions.img2Webp.description')}
        </p>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={img2WebpEnabled}
            onChange={(e) => setImg2WebpEnabled(e.target.checked)}
          />
          <span className="text-sm">{t('pages:globalOptions.img2Webp.enable')}</span>
        </label>
        <button
          className="btn-primary"
          onClick={saveImg2Webp}
          disabled={img2WebpSaving}
        >
          {img2WebpSaving ? t('common:actions.saving') : t('pages:globalOptions.img2Webp.save')}
        </button>
        {img2WebpMessage && (
          <p className={`text-sm ${img2WebpMessage === t('pages:globalOptions.img2Webp.enabled') || img2WebpMessage === t('pages:globalOptions.img2Webp.disabled') ? 'text-green-400' : 'text-red-400'}`}>
            {img2WebpMessage}
          </p>
        )}
      </div>

      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Network className="h-5 w-5 text-primary" /> {t('pages:featureFlags.mcpGateway.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('pages:featureFlags.mcpGateway.description')}
        </p>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={mcpGatewayEnabled}
            onChange={(e) => setMcpGatewayEnabled(e.target.checked)}
          />
          <span className="text-sm">{t('pages:featureFlags.mcpGateway.enable')}</span>
        </label>
        <button
          className="btn-primary"
          onClick={saveMcpGateway}
          disabled={mcpGatewaySaving}
        >
          {mcpGatewaySaving ? t('common:actions.saving') : t('pages:featureFlags.mcpGateway.save')}
        </button>
        {mcpGatewayMessage && (
          <p className={`text-sm ${mcpGatewayMessage === t('pages:featureFlags.mcpGateway.enabledMsg') || mcpGatewayMessage === t('pages:featureFlags.mcpGateway.disabledMsg') ? 'text-green-400' : 'text-red-400'}`}>
            {mcpGatewayMessage}
          </p>
        )}
      </div>

      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-primary" /> {t('pages:globalOptions.apiArmor.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('pages:globalOptions.apiArmor.description')}
        </p>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={apiArmorEnabled}
            onChange={(e) => setApiArmorEnabled(e.target.checked)}
          />
          <span className="text-sm">{t('pages:globalOptions.apiArmor.enable')}</span>
        </label>
        <button
          className="btn-primary"
          onClick={saveApiArmor}
          disabled={apiArmorSaving}
        >
          {apiArmorSaving ? t('common:actions.saving') : t('pages:globalOptions.apiArmor.save')}
        </button>
        {apiArmorMessage && (
          <p className={`text-sm ${apiArmorMessage === t('pages:globalOptions.apiArmor.enabled') || apiArmorMessage === t('pages:globalOptions.apiArmor.disabled') ? 'text-green-400' : 'text-red-400'}`}>
            {apiArmorMessage}
          </p>
        )}
      </div>

      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Network className="h-5 w-5 text-primary" /> {t('pages:featureFlags.restoreClientIp.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('pages:featureFlags.restoreClientIp.description')}
        </p>
        <div>
          <label className="text-sm">{t('pages:featureFlags.restoreClientIp.trustedNetworkLists')}</label>
          {networkLists.length === 0 ? (
            <p className="text-sm text-slate-500 italic mt-1">{t('pages:featureFlags.restoreClientIp.noNetworkLists')}</p>
          ) : (
            <div className="space-y-1 mt-1 max-h-48 overflow-y-auto border border-slate-700 rounded p-2">
              {networkLists.map((l) => (
                <label key={l.id} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={trustedNetworkLists.includes(l.name)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setTrustedNetworkLists([...trustedNetworkLists, l.name])
                      } else {
                        setTrustedNetworkLists(trustedNetworkLists.filter((n) => n !== l.name))
                      }
                    }}
                  />
                  {l.name}
                </label>
              ))}
            </div>
          )}
        </div>
        {trustedNetworkLists.length === 0 && (
          <p className="text-xs text-amber-400">
            {t('pages:featureFlags.restoreClientIp.noTrustedWarning')}
          </p>
        )}
        <button
          className="btn-primary"
          onClick={saveTrustedNetworkList}
          disabled={trustedSaving}
        >
          {trustedSaving ? t('common:actions.saving') : t('pages:featureFlags.restoreClientIp.save')}
        </button>
        {trustedMessage && (
          <p className={`text-sm ${trustedMessage === t('pages:featureFlags.restoreClientIp.savedMsg') ? 'text-green-400' : 'text-red-400'}`}>
            {trustedMessage}
          </p>
        )}
      </div>
    </div>
  )
}
