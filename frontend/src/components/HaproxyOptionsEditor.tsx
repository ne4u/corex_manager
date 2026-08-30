import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Trash2 } from 'lucide-react'
import { HAPROXY_OPTION_CATALOG, HaproxyOptionCatalogItem } from '../lib/haproxyOptionsCatalog'
import LabelWithTooltip from './LabelWithTooltip'
import InfoTooltip from './InfoTooltip'
import { IconButton } from './ui'

const haproxyOptionTooltipsKeys = {
  target: 'pages:haproxyOptionsEditor.tooltips.target',
  directive: 'pages:haproxyOptionsEditor.tooltips.directive',
  value: 'pages:haproxyOptionsEditor.tooltips.value',
  enabled: 'pages:haproxyOptionsEditor.tooltips.enabled',
}

export interface HaproxyOption {
  target: 'section' | 'bind'
  directive: string
  value: string
  enabled: boolean
}

interface Props {
  scope: 'global' | 'listener' | 'backend'
  value: HaproxyOption[]
  onChange: (opts: HaproxyOption[]) => void
}

export default function HaproxyOptionsEditor({ scope, value, onChange }: Props) {
  const { t } = useTranslation(['pages', 'common'])
  const [showCatalog, setShowCatalog] = useState(false)
  const [filter, setFilter] = useState('')

  const availableCatalog = useMemo(
    () => HAPROXY_OPTION_CATALOG.filter((i) => i.scope.includes(scope) && (i.target ? true : true)),
    [scope]
  )

  const update = (index: number, patch: Partial<HaproxyOption>) => {
    const next = value.map((o, i) => (i === index ? { ...o, ...patch } : o))
    onChange(next)
  }

  const add = (opt?: Partial<HaproxyOption>) => {
    onChange([...value, { target: 'section', directive: '', value: '', enabled: true, ...opt }])
  }

  const remove = (index: number) => {
    onChange(value.filter((_, i) => i !== index))
  }

  const applyCatalog = (item: HaproxyOptionCatalogItem) => {
    add({
      target: item.target || 'section',
      directive: item.directive,
      value: '',
      enabled: true,
    })
    setShowCatalog(false)
  }

  const filteredCatalog = availableCatalog.filter(
    (i) =>
      i.directive.toLowerCase().includes(filter.toLowerCase()) ||
      i.label.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold">{t('pages:haproxyOptionsEditor.title')}</h3>
        <button
          type="button"
          className="btn-secondary text-xs"
          onClick={() => setShowCatalog(!showCatalog)}
        >
          {showCatalog ? t('pages:haproxyOptionsEditor.closeCatalog') : t('pages:haproxyOptionsEditor.addFromCatalog')}
        </button>
      </div>

      {showCatalog && (
        <div className="card space-y-2">
          <input
            type="text"
            className="input w-full"
            placeholder={t('pages:haproxyOptionsEditor.searchPlaceholder')}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <div className="max-h-48 overflow-y-auto space-y-1">
            {filteredCatalog.map((item) => (
              <button
                key={`${item.directive}-${item.target || 'section'}`}
                type="button"
                className="w-full text-start p-2 rounded hover:bg-slate-800 text-sm"
                onClick={() => applyCatalog(item)}
              >
                <span className="font-medium">{item.label}</span>
                <span className="text-slate-400 ms-2">({item.directive})</span>
                <span className="ms-2 inline-flex align-middle">
                  <InfoTooltip content={item.help ?? ''} />
                </span>
              </button>
            ))}
            {filteredCatalog.length === 0 && (
              <p className="text-sm text-slate-500">{t('pages:haproxyOptionsEditor.noMatching')}</p>
            )}
          </div>
        </div>
      )}

      {value.length === 0 && (
        <p className="text-sm text-slate-500">{t('pages:haproxyOptionsEditor.noOptions')}</p>
      )}

      {value.map((opt, index) => (
        <div key={index} className="card p-3 grid grid-cols-12 gap-2 items-end">
          {scope === 'listener' && (
            <div className="col-span-3">
              <LabelWithTooltip tooltip={t(haproxyOptionTooltipsKeys.target)} className="label flex items-center gap-1.5">
                {t('pages:haproxyOptionsEditor.target')}
              </LabelWithTooltip>
              <select
                className="input w-full"
                value={opt.target}
                onChange={(e) => update(index, { target: e.target.value as 'section' | 'bind' })}
              >
                <option value="section">{t('pages:haproxyOptionsEditor.targetSection')}</option>
                <option value="bind">{t('pages:haproxyOptionsEditor.targetBindLine')}</option>
              </select>
            </div>
          )}
          <div className={`${scope === 'listener' ? 'col-span-3' : 'col-span-4'}`}>
            <LabelWithTooltip tooltip={t(haproxyOptionTooltipsKeys.directive)} className="label flex items-center gap-1.5">
              {t('pages:haproxyOptionsEditor.directive')}
            </LabelWithTooltip>
            <input
              type="text"
              className="input w-full"
              value={opt.directive}
              onChange={(e) => update(index, { directive: e.target.value })}
              placeholder={t('pages:haproxyOptionsEditor.directivePlaceholder')}
            />
          </div>
          <div className="col-span-4">
            <LabelWithTooltip tooltip={t(haproxyOptionTooltipsKeys.value)} className="label flex items-center gap-1.5">
              {t('common:table.value')}
            </LabelWithTooltip>
            <input
              type="text"
              className="input w-full"
              value={opt.value}
              onChange={(e) => update(index, { value: e.target.value })}
              placeholder={t('pages:haproxyOptionsEditor.valuePlaceholder')}
            />
          </div>
          <label className="col-span-2 flex items-center gap-2 pb-2 text-slate-400">
            <input
              id={`opt-enabled-${index}`}
              type="checkbox"
              checked={opt.enabled}
              onChange={(e) => update(index, { enabled: e.target.checked })}
            />
            <LabelWithTooltip className="inline-flex items-center gap-1.5" tooltip={t(haproxyOptionTooltipsKeys.enabled)}>
              {t('common:actions.enable')}
            </LabelWithTooltip>
          </label>
          <div className="col-span-1 flex justify-end">
            <IconButton icon={Trash2} variant="danger" aria-label={t('pages:haproxyOptionsEditor.removeOption')} onClick={() => remove(index)} />
          </div>
        </div>
      ))}

      <button type="button" className="btn-secondary text-xs" onClick={() => add()}>
        {t('pages:haproxyOptionsEditor.addCustomOption')}
      </button>
    </div>
  )
}
