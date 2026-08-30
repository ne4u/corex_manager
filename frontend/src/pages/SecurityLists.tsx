import React, { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ListFilter, Pencil, Trash2, RefreshCw, Eye, Network, Hash, Globe2, Fingerprint, FileCode, Rss } from 'lucide-react'
import { securityLists, getErrorDetail } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import CountrySelect from '../components/CountrySelect'
import { IconButton, Tabs } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'

type ListKind = 'network' | 'asn' | 'geo' | 'ja4' | 'pattern'

interface ListRow {
  id: number
  name: string
  description?: string | null
  entry_count: number
  created_at: string
  updated_at: string
}

interface EntryRow {
  id: number
  list_id: number
  value: string
  note?: string | null
  created_at: string
}

interface FeedRow {
  id: number
  name: string
  list_type: 'network' | 'asn' | 'ja4'
  url: string
  update_interval_hours: number
  description?: string | null
  enabled: boolean
  target_list_id: number
  last_updated_at?: string | null
  last_error?: string | null
  last_entry_count?: number | null
  created_at: string
  updated_at: string
}

const apiFor = (kind: ListKind) => securityLists[kind]

export default function SecurityLists() {
  const { t } = useTranslation(['pages', 'common'])
  const [tab, setTab] = useState<ListKind | 'feeds'>('network')
  const { items: networkLists, reload: rNet } = useApiList<ListRow>(securityLists.network.list)
  const { items: asnLists, reload: rAsn } = useApiList<ListRow>(securityLists.asn.list)
  const { items: geoLists, reload: rGeo } = useApiList<ListRow>(securityLists.geo.list)
  const { items: ja4Lists, reload: rJa4 } = useApiList<ListRow>(securityLists.ja4.list)
  const { items: patternLists, reload: rPat } = useApiList<ListRow>(securityLists.pattern.list)
  const { items: feeds, reload: rFeeds } = useApiList<FeedRow>(securityLists.feeds.list)

  const reloadLists = () => { rNet(); rAsn(); rGeo(); rJa4(); rPat() }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <ListFilter className="h-5 w-5 text-primary" /> {t('pages:securityLists.title')}
        </h2>
      </div>
      <Tabs
        tabs={[
          { id: 'network', label: t('pages:securityLists.tabs.network'), icon: Network },
          { id: 'asn', label: t('pages:securityLists.tabs.asn'), icon: Hash },
          { id: 'geo', label: t('pages:securityLists.tabs.geo'), icon: Globe2 },
          { id: 'ja4', label: t('pages:securityLists.tabs.ja4'), icon: Fingerprint },
          { id: 'pattern', label: t('pages:securityLists.tabs.pattern'), icon: FileCode },
          { id: 'feeds', label: t('pages:securityLists.tabs.feeds'), icon: Rss },
        ]}
        active={tab}
        onChange={(id) => setTab(id as ListKind | 'feeds')}
      />

      {tab !== 'feeds' ? (
        <ListTab key={tab} kind={tab as ListKind} lists={tab === 'network' ? networkLists : tab === 'asn' ? asnLists : tab === 'geo' ? geoLists : tab === 'ja4' ? ja4Lists : patternLists} reload={reloadLists} />
      ) : (
        <FeedsTab feeds={feeds} reload={rFeeds} networkLists={networkLists} asnLists={asnLists} ja4Lists={ja4Lists} reloadLists={reloadLists} />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// List tab (Network / ASN / GeoIP)
// ---------------------------------------------------------------------------

function ListTab({ kind, lists, reload }: { kind: ListKind; lists: ListRow[]; reload: () => void }) {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const api = apiFor(kind)
  const [selected, setSelected] = useState<ListRow | null>(null)
  const [entries, setEntries] = useState<EntryRow[]>([])
  const [entriesLoading, setEntriesLoading] = useState(false)
  const [listOpen, setListOpen] = useState(false)
  const [listEditing, setListEditing] = useState<number | null>(null)
  const [listForm, setListForm] = useState({ name: '', description: '' })
  const [entryOpen, setEntryOpen] = useState(false)
  const [entryEditing, setEntryEditing] = useState<number | null>(null)
  const [entryForm, setEntryForm] = useState({ value: '', note: '' })
  const [error, setError] = useState('')

  const [countryOptions, setCountryOptions] = useState<{ code: string; name: string }[]>([])
  const [countryOptionsLoading, setCountryOptionsLoading] = useState(false)
  const countryNameMap = useMemo(() => {
    const map: Record<string, string> = {}
    for (const o of countryOptions) map[o.code] = o.name
    return map
  }, [countryOptions])

  useEffect(() => {
    if (kind !== 'geo') return
    setCountryOptionsLoading(true)
    securityLists.geo.countries()
      .then(r => setCountryOptions(r.data))
      .catch(() => setCountryOptions([]))
      .finally(() => setCountryOptionsLoading(false))
  }, [kind])

  const openEntries = async (l: ListRow) => {
    setSelected(l)
    setEntriesLoading(true)
    try {
      const r = await api.entries.list(l.id)
      setEntries(r.data)
    } catch (e) {
      setEntries([])
    } finally {
      setEntriesLoading(false)
    }
  }

  const openAddList = () => { setListEditing(null); setListForm({ name: '', description: '' }); setListOpen(true) }
  const openEditList = (l: ListRow) => { setListEditing(l.id); setListForm({ name: l.name, description: l.description || '' }); setListOpen(true) }

  const submitList = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      if (listEditing) await api.update(listEditing, listForm)
      else await api.create(listForm)
      setListOpen(false)
      reload()
    } catch (err) {
      setError(getErrorDetail(err))
    }
  }

  const deleteList = async (l: ListRow) => {
    if (!window.confirm(t('pages:securityLists.confirmDeleteList', { name: l.name }))) return
    try {
      await api.remove(l.id)
      if (selected?.id === l.id) setSelected(null)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const openAddEntry = () => { setEntryEditing(null); setEntryForm({ value: '', note: '' }); setEntryOpen(true) }
  const openEditEntry = (en: EntryRow) => { setEntryEditing(en.id); setEntryForm({ value: en.value, note: en.note || '' }); setEntryOpen(true) }

  const submitEntry = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selected) return
    setError('')
    try {
      if (entryEditing) await api.entries.update(selected.id, entryEditing, entryForm)
      else await api.entries.create(selected.id, entryForm)
      setEntryOpen(false)
      const r = await api.entries.list(selected.id)
      setEntries(r.data)
      reload()
    } catch (err) {
      setError(getErrorDetail(err))
    }
  }

  const deleteEntry = async (en: EntryRow) => {
    if (!selected) return
    if (!window.confirm(t('pages:securityLists.confirmDeleteEntry', { value: en.value }))) return
    try {
      await api.entries.remove(selected.id, en.id)
      const r = await api.entries.list(selected.id)
      setEntries(r.data)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Lists panel */}
      <div className="card overflow-x-auto">
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <h3 className="font-semibold">{kind === 'network' ? t('pages:securityLists.tabs.network') : kind === 'asn' ? t('pages:securityLists.tabs.asn') : kind === 'geo' ? t('pages:securityLists.tabs.geo') : kind === 'ja4' ? t('pages:securityLists.tabs.ja4') : t('pages:securityLists.tabs.pattern')} Lists</h3>
          <button onClick={openAddList} className="btn-primary">{t('pages:securityLists.addList')}</button>
        </div>
        <table className="w-full text-sm text-start">
          <thead className="text-slate-400 border-b border-slate-800">
            <tr><th className="p-2">{t('pages:securityLists.tableHeaders.name')}</th><th className="p-2">{t('pages:securityLists.tableHeaders.description')}</th><th className="p-2">{t('pages:securityLists.tableHeaders.entries')}</th><th className="p-2">{t('pages:securityLists.tableHeaders.lastUpdated')}</th><th className="p-2"></th></tr>
          </thead>
          <tbody>
            {lists.map(l => (
              <tr key={l.id} className={`border-b border-slate-800 last:border-0 cursor-pointer hover:bg-slate-800/40 ${selected?.id === l.id ? 'bg-slate-800/60' : ''}`} onClick={() => openEntries(l)}>
                <td className="p-2">{l.name}</td>
                <td className="p-2 text-slate-400">{l.description || '-'}</td>
                <td className="p-2">{l.entry_count}</td>
                <td className="p-2 text-xs text-slate-400">{l.updated_at ? formatDateTime(l.updated_at) : '-'}</td>
                <td className="p-2 space-x-1" onClick={e => e.stopPropagation()}>
                  <IconButton icon={Pencil} aria-label="Edit" onClick={() => openEditList(l)} />
                  <IconButton icon={Trash2} variant="danger" aria-label="Delete" onClick={() => deleteList(l)} />
                </td>
              </tr>
            ))}
            {lists.length === 0 && <tr><td className="p-4 text-slate-500" colSpan={5}>{t('pages:securityLists.noListsYet')}</td></tr>}
          </tbody>
        </table>
      </div>

      {/* Entries panel */}
      <div className="card overflow-x-auto">
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <h3 className="font-semibold">{selected ? t('pages:securityLists.feeds.entriesTitle', { name: selected.name }) : t('pages:securityLists.selectList')}</h3>
          {selected && <button onClick={openAddEntry} className="btn-primary">{t('pages:securityLists.addEntry')}</button>}
        </div>
        {!selected ? (
          <div className="p-4 text-slate-500">{t('pages:securityLists.selectListToView')}</div>
        ) : entriesLoading ? (
          <div className="p-4 text-slate-500">{t('pages:securityLists.loading')}</div>
        ) : (
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr><th className="p-2">{t('pages:securityLists.valueLabels.' + kind)}</th><th className="p-2">{t('pages:securityLists.tableHeaders.note')}</th><th className="p-2"></th></tr>
            </thead>
            <tbody>
              {entries.map(en => {
                const display = kind === 'geo' && countryNameMap[en.value]
                  ? `${countryNameMap[en.value]} (${en.value})`
                  : en.value
                return (
                  <tr key={en.id} className="border-b border-slate-800 last:border-0">
                    <td className="p-2 font-mono">{display}</td>
                    <td className="p-2 text-slate-400">{en.note || '-'}</td>
                    <td className="p-2 space-x-1">
                      <IconButton icon={Pencil} aria-label="Edit" onClick={() => openEditEntry(en)} />
                      <IconButton icon={Trash2} variant="danger" aria-label="Delete" onClick={() => deleteEntry(en)} />
                    </td>
                  </tr>
                )
              })}
              {entries.length === 0 && <tr><td className="p-4 text-slate-500" colSpan={3}>{t('pages:securityLists.noEntriesYet')}</td></tr>}
            </tbody>
          </table>
        )}
      </div>

      {/* List modal */}
      <Modal open={listOpen} onClose={() => setListOpen(false)} title={listEditing ? t('pages:securityLists.listModal.editTitle') : t('pages:securityLists.listModal.addTitle')}>
        <form onSubmit={submitList} className="space-y-3">
          {error && <div className="text-red-400 text-sm">{error}</div>}
          <div><label className="label">{t('pages:securityLists.listModal.name')}</label><input className="input" value={listForm.name} onChange={e => setListForm({ ...listForm, name: e.target.value })} required /></div>
          <div><label className="label">{t('pages:securityLists.listModal.description')}</label><input className="input" value={listForm.description} onChange={e => setListForm({ ...listForm, description: e.target.value })} /></div>
          <button className="btn-primary w-full">{t('pages:securityLists.listModal.save')}</button>
        </form>
      </Modal>

      {/* Entry modal */}
      <Modal open={entryOpen} onClose={() => setEntryOpen(false)} title={entryEditing ? t('pages:securityLists.entryModal.editTitle') : t('pages:securityLists.entryModal.addTitle')}>
        <form onSubmit={submitEntry} className="space-y-3">
          {error && <div className="text-red-400 text-sm">{error}</div>}
          <div>
            <label className="label">{t('pages:securityLists.valueLabels.' + kind)}</label>
            {kind === 'geo' ? (
              <CountrySelect
                value={entryForm.value}
                onChange={code => setEntryForm({ ...entryForm, value: code })}
                options={countryOptions}
                loading={countryOptionsLoading}
                placeholder={t('pages:securityLists.entryModal.searchCountry')}
                required
              />
            ) : (
              <input className="input font-mono" value={entryForm.value} onChange={e => setEntryForm({ ...entryForm, value: e.target.value })} required />
            )}
          </div>
          <div><label className="label">{t('pages:securityLists.entryModal.note')}</label><input className="input" value={entryForm.note} onChange={e => setEntryForm({ ...entryForm, note: e.target.value })} /></div>
          <button className="btn-primary w-full">{t('pages:securityLists.entryModal.save')}</button>
        </form>
      </Modal>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Threat Feeds tab
// ---------------------------------------------------------------------------

function FeedsTab({ feeds, reload, networkLists, asnLists, ja4Lists, reloadLists }: {
  feeds: FeedRow[]
  reload: () => void
  networkLists: ListRow[]
  asnLists: ListRow[]
  ja4Lists: ListRow[]
  reloadLists: () => void
}) {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [error, setError] = useState('')
  const [refreshing, setRefreshing] = useState<number | null>(null)
  const [viewFeed, setViewFeed] = useState<FeedRow | null>(null)
  const [viewEntries, setViewEntries] = useState<EntryRow[]>([])
  const [viewLoading, setViewLoading] = useState(false)
  const initialForm = {
    name: '',
    list_type: 'network' as 'network' | 'asn',
    url: '',
    update_interval_hours: 24,
    description: '',
    enabled: true,
    target_list_id: '' as number | string,
  }
  const [form, setForm] = useState<any>(initialForm)

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (f: FeedRow) => {
    setEditing(f.id)
    setForm({
      name: f.name,
      list_type: f.list_type,
      url: f.url,
      update_interval_hours: f.update_interval_hours,
      description: f.description || '',
      enabled: f.enabled,
      target_list_id: f.target_list_id,
    })
    setOpen(true)
  }

  const openView = async (f: FeedRow) => {
    setViewFeed(f)
    setViewEntries([])
    setViewLoading(true)
    try {
      const api = apiFor(f.list_type as ListKind)
      const r = await api.entries.list(f.target_list_id)
      setViewEntries(r.data)
    } catch {
      setViewEntries([])
    } finally {
      setViewLoading(false)
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    const payload: any = {
      name: form.name,
      list_type: form.list_type,
      url: form.url,
      update_interval_hours: Number(form.update_interval_hours),
      description: form.description || null,
      enabled: form.enabled,
    }
    if (editing) {
      payload.target_list_id = form.target_list_id
    } else {
      payload.target_list_id = form.target_list_id === '' ? null : Number(form.target_list_id)
    }
    try {
      if (editing) await securityLists.feeds.update(editing, payload)
      else await securityLists.feeds.create(payload)
      setOpen(false)
      reload()
      reloadLists()
    } catch (err) {
      setError(getErrorDetail(err))
    }
  }

  const remove = async (f: FeedRow) => {
    const delList = window.confirm(`Delete feed "${f.name}"?\n\nClick OK to also delete the target list and its entries, or Cancel to keep the list.`)
    try {
      await securityLists.feeds.remove(f.id, delList)
      reload()
      reloadLists()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const refreshNow = async (f: FeedRow) => {
    setRefreshing(f.id)
    try {
      await securityLists.feeds.refresh(f.id)
      reload()
      reloadLists()
    } catch (err) {
      alert(getErrorDetail(err))
    } finally {
      setRefreshing(null)
    }
  }

  const targetLists = form.list_type === 'network' ? networkLists : form.list_type === 'asn' ? asnLists : ja4Lists

  return (
    <div className="card overflow-x-auto">
      <div className="flex items-center justify-between p-4 border-b border-slate-800">
        <h3 className="font-semibold">Threat Feeds</h3>
        <button onClick={openAdd} className="btn-primary">Add Feed</button>
      </div>
      <table className="w-full text-sm text-start">
        <thead className="text-slate-400 border-b border-slate-800">
          <tr>
            <th className="p-2">Name</th><th className="p-2">Type</th><th className="p-2">URL</th>
            <th className="p-2">Interval (h)</th><th className="p-2">Enabled</th>
            <th className="p-2">Last Updated</th><th className="p-2">Entries</th><th className="p-2">Error</th><th className="p-2"></th>
          </tr>
        </thead>
        <tbody>
          {feeds.map(f => (
            <tr key={f.id} className="border-b border-slate-800 last:border-0">
              <td className="p-2">{f.name}</td>
              <td className="p-2">{f.list_type}</td>
              <td className="p-2 max-w-xs truncate font-mono text-xs" title={f.url}>{f.url}</td>
              <td className="p-2">{f.update_interval_hours}</td>
              <td className="p-2">{f.enabled ? 'yes' : 'no'}</td>
              <td className="p-2 text-xs text-slate-400">{f.last_updated_at ? formatDateTime(f.last_updated_at) : '-'}</td>
              <td className="p-2">{f.last_entry_count ?? '-'}</td>
              <td className="p-2 max-w-xs truncate text-xs text-red-400" title={f.last_error || ''}>{f.last_error || '-'}</td>
              <td className="p-2 space-x-1 whitespace-nowrap">
                <IconButton icon={Eye} aria-label="View" onClick={() => openView(f)} />
                <IconButton icon={RefreshCw} aria-label="Refresh" onClick={() => refreshNow(f)} disabled={refreshing === f.id} />
                <IconButton icon={Pencil} aria-label="Edit" onClick={() => openEdit(f)} />
                <IconButton icon={Trash2} variant="danger" aria-label="Delete" onClick={() => remove(f)} />
              </td>
            </tr>
          ))}
          {feeds.length === 0 && <tr><td className="p-4 text-slate-500" colSpan={9}>No threat feeds yet.</td></tr>}
        </tbody>
      </table>

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? 'Edit Feed' : 'Add Feed'}>
        <form onSubmit={submit} className="space-y-3">
          {error && <div className="text-red-400 text-sm">{error}</div>}
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">Name</label><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required /></div>
            <div>
              <label className="label">List Type</label>
              <select className="input" value={form.list_type} onChange={e => setForm({ ...form, list_type: e.target.value, target_list_id: '' })} disabled={!!editing}>
                <option value="network">Network</option>
                <option value="asn">ASN</option>
                <option value="ja4">JA4</option>
              </select>
            </div>
            <div className="col-span-2"><label className="label">URL</label><input className="input font-mono text-xs" value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} required /></div>
            <div><label className="label">Update Interval (hours)</label><input type="number" min="1" className="input" value={form.update_interval_hours} onChange={e => setForm({ ...form, update_interval_hours: e.target.value })} required /></div>
            <div>
              <label className="label">Target List</label>
              <select className="input" value={form.target_list_id} onChange={e => setForm({ ...form, target_list_id: e.target.value })}>
                <option value="">Create new list (named after feed)</option>
                {targetLists.map(l => <option key={l.id} value={l.id}>{l.name} ({l.entry_count} entries)</option>)}
              </select>
            </div>
            <div className="col-span-2"><label className="label">Description</label><input className="input" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} /></div>
            <div className="col-span-2 flex items-center gap-2">
              <input type="checkbox" id="feed-enabled" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
              <label htmlFor="feed-enabled">Enabled</label>
            </div>
          </div>
          <button className="btn-primary w-full">Save</button>
        </form>
      </Modal>

      <Modal open={!!viewFeed} onClose={() => setViewFeed(null)} title={viewFeed ? `Entries: ${viewFeed.name}` : 'Entries'}>
        {viewLoading ? (
          <div className="text-slate-500">Loading...</div>
        ) : viewEntries.length === 0 ? (
          <div className="text-slate-500">No entries in this list.</div>
        ) : (
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr><th className="p-2">{viewFeed ? t('pages:securityLists.valueLabels.' + (viewFeed.list_type as ListKind)) : t('pages:securityLists.tableHeaders.value')}</th><th className="p-2">{t('pages:securityLists.tableHeaders.note')}</th></tr>
            </thead>
            <tbody>
              {viewEntries.map(en => (
                <tr key={en.id} className="border-b border-slate-800 last:border-0">
                  <td className="p-2 font-mono break-all">{en.value}</td>
                  <td className="p-2 text-slate-400">{en.note || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Modal>
    </div>
  )
}
