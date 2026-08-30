import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Save, Trash2 } from 'lucide-react'
import Modal from './Modal'
import { IconButton } from './ui'
import {
  Theme,
  ThemeColors,
  colorMetadata,
  colorGroups,
  colorsToHex,
  hexToColors,
  slugifyThemeName,
  blankColors,
  themes as builtinThemes,
} from '../themes/themeDefinitions'

interface CustomThemeEditorProps {
  open: boolean
  onClose: () => void
  /** Theme being edited, or null for a new theme. */
  editingTheme: Theme | null
  /** Called when the user saves the theme. */
  onSave: (theme: Theme) => void
  /** Called when the user deletes the theme (only for existing custom themes). */
  onDelete?: (name: string) => void
  /** All existing theme names (to detect duplicates). */
  existingNames: string[]
}

type HexColors = Record<keyof ThemeColors, string>

export function CustomThemeEditor({
  open,
  onClose,
  editingTheme,
  onSave,
  onDelete,
  existingNames,
}: CustomThemeEditorProps) {
  const { t } = useTranslation(['profile', 'common'])
  const [displayName, setDisplayName] = useState('')
  const [hexColors, setHexColors] = useState<HexColors>(() => colorsToHex(blankColors()))
  const [cloneSource, setCloneSource] = useState<string>('')
  const [nameError, setNameError] = useState('')

  // Reset form when opening
  useEffect(() => {
    if (!open) return
    if (editingTheme) {
      setDisplayName(editingTheme.displayName)
      setHexColors(colorsToHex(editingTheme.colors))
      setCloneSource('')
    } else {
      setDisplayName('')
      setHexColors(colorsToHex(blankColors()))
      setCloneSource('')
    }
    setNameError('')
  }, [open, editingTheme])

  const applyClone = (themeName: string) => {
    setCloneSource(themeName)
    const source = builtinThemes[themeName]
    if (source) {
      setHexColors(colorsToHex(source.colors))
    }
  }

  const updateColor = (key: keyof ThemeColors, hex: string) => {
    setHexColors(prev => ({ ...prev, [key]: hex }))
  }

  const handleSave = () => {
    const trimmed = displayName.trim()
    if (!trimmed) {
      setNameError(t('profile:appearance.themeEditor.nameRequired'))
      return
    }
    const slug = slugifyThemeName(trimmed)
    // Check for duplicate names (allow saving over the same theme being edited)
    const isSelf = editingTheme && slug === editingTheme.name
    if (!isSelf && existingNames.includes(slug)) {
      setNameError(t('profile:appearance.themeEditor.nameExists'))
      return
    }
    const theme: Theme = {
      name: slug,
      displayName: trimmed,
      colors: hexToColors(hexColors),
    }
    onSave(theme)
    onClose()
  }

  const handleDelete = () => {
    if (!editingTheme || !onDelete) return
    if (!window.confirm(t('profile:appearance.themeEditor.deleteConfirm', { name: editingTheme.displayName }))) return
    onDelete(editingTheme.name)
    onClose()
  }

  // Live preview colors
  const previewColors = useMemo(() => hexToColors(hexColors), [hexColors])

  return (
    <Modal open={open} onClose={onClose} title={editingTheme ? t('profile:appearance.themeEditor.editTitle') : t('profile:appearance.createCustom')}>
      <div className="space-y-6">
        {/* Name + clone source */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="label">{t('profile:appearance.themeEditor.themeName')}</label>
            <input
              className="input w-full"
              value={displayName}
              onChange={e => { setDisplayName(e.target.value); setNameError('') }}
              placeholder={t('profile:appearance.themeEditor.themeNamePlaceholder')}
              autoFocus
            />
            {nameError && <p className="text-xs text-red-400 mt-1">{nameError}</p>}
          </div>
          {!editingTheme && (
            <div>
              <label className="label">{t('profile:appearance.themeEditor.cloneFrom')}</label>
              <select
                className="input w-full"
                value={cloneSource}
                onChange={e => applyClone(e.target.value)}
              >
                <option value="">{t('profile:appearance.themeEditor.scratch')}</option>
                {Object.values(builtinThemes).map(t => (
                  <option key={t.name} value={t.name}>{t.displayName}</option>
                ))}
              </select>
            </div>
          )}
        </div>

        {/* Live preview */}
        <div
          className="rounded-lg border p-4 space-y-2"
          style={{
            background: `rgb(${previewColors.bgPrimary})`,
            borderColor: `rgb(${previewColors.borderDefault})`,
          }}
        >
          <div className="flex items-center gap-3">
            <span style={{ color: `rgb(${previewColors.textPrimary})` }} className="text-sm font-semibold">
              {t('profile:appearance.themeEditor.preview.primaryText')}
            </span>
            <span style={{ color: `rgb(${previewColors.textSecondary})` }} className="text-sm">
              {t('profile:appearance.themeEditor.preview.secondaryText')}
            </span>
            <span style={{ color: `rgb(${previewColors.textTertiary})` }} className="text-xs">
              {t('profile:appearance.themeEditor.preview.tertiaryText')}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="px-2 py-0.5 rounded text-xs font-medium"
              style={{
                background: `rgb(${previewColors.accentPrimary})`,
                color: `rgb(${previewColors.bgPrimary})`,
              }}
            >
              {t('profile:appearance.themeEditor.preview.primaryButton')}
            </span>
            <span
              className="px-2 py-0.5 rounded text-xs font-medium border"
              style={{
                borderColor: `rgb(${previewColors.borderDefault})`,
                background: `rgb(${previewColors.bgSecondary})`,
                color: `rgb(${previewColors.textPrimary})`,
              }}
            >
              {t('profile:appearance.themeEditor.preview.secondaryButton')}
            </span>
            <span style={{ color: `rgb(${previewColors.accentSuccess})` }} className="text-xs">{t('profile:appearance.themeEditor.preview.success')}</span>
            <span style={{ color: `rgb(${previewColors.accentWarning})` }} className="text-xs">{t('profile:appearance.themeEditor.preview.warning')}</span>
            <span style={{ color: `rgb(${previewColors.accentError})` }} className="text-xs">{t('profile:appearance.themeEditor.preview.error')}</span>
          </div>
          <div
            className="rounded p-2 text-xs"
            style={{
              background: `rgb(${previewColors.bgSecondary})`,
              border: `1px solid rgb(${previewColors.borderSubtle})`,
              color: `rgb(${previewColors.textSecondary})`,
            }}
          >
            {t('profile:appearance.themeEditor.preview.cardSurface')}
          </div>
        </div>

        {/* Color pickers grouped by category */}
        {colorGroups.map(group => (
          <div key={group}>
            <h4 className="text-sm font-semibold text-slate-300 mb-2">{group}</h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {colorMetadata.filter(m => m.group === group).map(meta => (
                <ColorPickerRow
                  key={meta.key}
                  label={meta.label}
                  hex={hexColors[meta.key]}
                  onChange={hex => updateColor(meta.key, hex)}
                />
              ))}
            </div>
          </div>
        ))}

        {/* Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-800">
          <div>
            {editingTheme && onDelete && (
              <IconButton icon={Trash2} variant="danger" aria-label={t('profile:appearance.deleteTheme')} onClick={handleDelete} />
            )}
          </div>
          <div className="flex items-center gap-2">
            <button className="btn-secondary" onClick={onClose}>{t('common:actions.cancel')}</button>
            <button className="btn-primary flex items-center gap-2" onClick={handleSave}>
              <Save className="w-4 h-4" />
              {editingTheme ? t('profile:appearance.themeEditor.saveChanges') : t('profile:appearance.themeEditor.createTheme')}
            </button>
          </div>
        </div>
      </div>
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// Single color picker row
// ---------------------------------------------------------------------------

interface ColorPickerRowProps {
  label: string
  hex: string
  onChange: (hex: string) => void
}

function ColorPickerRow({ label, hex, onChange }: ColorPickerRowProps) {
  return (
    <div className="flex items-center gap-3">
      <input
        type="color"
        value={hex}
        onChange={e => onChange(e.target.value)}
        className="w-8 h-8 rounded cursor-pointer border border-slate-600 bg-transparent shrink-0"
        title={label}
      />
      <div className="flex-1 min-w-0">
        <div className="text-xs text-slate-400 truncate">{label}</div>
        <input
          type="text"
          value={hex}
          onChange={e => onChange(e.target.value)}
          className="input py-0.5 text-xs font-mono w-full"
          placeholder="#000000"
        />
      </div>
    </div>
  )
}
