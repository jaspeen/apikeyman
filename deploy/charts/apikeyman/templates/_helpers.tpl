{{/*
Expand the name of the chart.
*/}}
{{- define "apikeyman.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "apikeyman.fullname" -}}
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
Create a secret name which can be overridden.
*/}}
{{- define "apikeyman.secretname" -}}
{{- if .Values.secret.nameOverride -}}
{{- .Values.secret.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{ include "apikeyman.fullname" . }}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "apikeyman.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Generate the dsn value
*/}}
{{- define "apikeyman.dsn" -}}
{{- if and .Values.secret.nameOverride (not .Values.secret.enabled) -}}
dsn-loaded-from-env
{{- else if not (empty (.Values.apikeyman.config.dsn)) -}}
{{- .Values.apikeyman.config.dsn }}
{{- end -}}
{{- end -}}

{{/*
Generate the configmap data, redacting secrets
*/}}
{{- define "apikeyman.configmap" -}}
{{- $config := omit .Values.apikeyman.config "dsn" -}}
{{- toYaml $config -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "apikeyman.labels" -}}
helm.sh/chart: {{ include "apikeyman.chart" . }}
{{ include "apikeyman.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "apikeyman.selectorLabels" -}}
app.kubernetes.io/name: {{ include "apikeyman.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "apikeyman.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "apikeyman.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account for the Job to use
*/}}
{{- define "apikeyman.job.serviceAccountName" -}}
{{- if .Values.job.serviceAccount.create }}
{{- printf "%s-job" (default (include "apikeyman.fullname" .) .Values.job.serviceAccount.name) }}
{{- else }}
{{- include "apikeyman.serviceAccountName" . }}
{{- end }}
{{- end }}


{{/*
Checksum annotations generated from configmaps and secrets
*/}}
{{- define "apikeyman.annotations.checksum" -}}
{{- if .Values.configmap.hashSumEnabled }}
checksum/apikeyman-config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- end }}
{{- if and .Values.secret.enabled .Values.secret.hashSumEnabled }}
checksum/apikeyman-secrets: {{ include (print $.Template.BasePath "/secrets.yaml") . | sha256sum }}
{{- end }}
{{- end }}

{{/*
Check the migration type value and fail if unexpected
*/}}
{{- define "apikeyman.automigration.typeVerification" -}}
{{- if and .Values.apikeyman.automigration.enabled  .Values.apikeyman.automigration.type }}
  {{- if and (ne .Values.apikeyman.automigration.type "initContainer") (ne .Values.apikeyman.automigration.type "job") }}
    {{- fail "apikeyman.automigration.type must be either 'initContainer' or 'job'" -}}
  {{- end }}
{{- end }}
{{- end }}
