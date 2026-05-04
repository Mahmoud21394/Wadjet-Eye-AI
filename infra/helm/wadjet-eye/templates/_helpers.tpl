{{/*
  Wadjet-Eye AI — Helm Template Helpers
  infra/helm/wadjet-eye/templates/_helpers.tpl
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "wadjet-eye.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "wadjet-eye.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "wadjet-eye.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "wadjet-eye.labels" -}}
helm.sh/chart: {{ include "wadjet-eye.chart" . }}
{{ include "wadjet-eye.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: wadjet-eye-platform
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "wadjet-eye.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wadjet-eye.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "wadjet-eye.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "wadjet-eye.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
