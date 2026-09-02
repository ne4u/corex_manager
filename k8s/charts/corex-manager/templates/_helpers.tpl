{{/*
Common labels
*/}}
{{- define "corex-manager.labels" -}}
app.kubernetes.io/name: corex-manager
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: corex-manager
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Selector labels for the corex sidecar Pod
*/}}
{{- define "corex-manager.podSelectorLabels" -}}
app.kubernetes.io/name: corex-manager
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: corex-pod
{{- end }}

{{/*
Full image reference helper
*/}}
{{- define "corex-manager.image" -}}
{{ .repository }}:{{ .tag | default "latest" }}
{{- end }}

{{/*
Namespace helper
*/}}
{{- define "corex-manager.namespace" -}}
{{ .Values.namespaceOverride | default .Release.Namespace }}
{{- end }}

{{/*
PostgreSQL connection string
*/}}
{{- define "corex-manager.databaseUrl" -}}
{{- if .Values.postgres.enabled -}}
postgresql+psycopg://{{ .Values.postgres.user }}:{{ .Values.postgres.password }}@postgres:5432/{{ .Values.postgres.database }}
{{- else -}}
postgresql+psycopg://{{ .Values.postgres.external.user }}:{{ .Values.postgres.external.password }}@{{ .Values.postgres.external.host }}:{{ .Values.postgres.external.port | default 5432 }}/{{ .Values.postgres.external.database }}
{{- end -}}
{{- end }}

{{/*
Valkey URL
*/}}
{{- define "corex-manager.valkeyUrl" -}}
{{- if .Values.valkey.enabled -}}
{{- if .Values.valkey.password -}}
valkey://:{{ .Values.valkey.password }}@valkey:6379/0
{{- else -}}
valkey://valkey:6379/0
{{- end -}}
{{- else -}}
{{- if .Values.valkey.external.password -}}
valkey://:{{ .Values.valkey.external.password }}@{{ .Values.valkey.external.host }}:{{ .Values.valkey.external.port | default 6379 }}/0
{{- else -}}
valkey://{{ .Values.valkey.external.host }}:{{ .Values.valkey.external.port | default 6379 }}/0
{{- end -}}
{{- end -}}
{{- end }}
