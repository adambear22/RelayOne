package templates

import "embed"

//go:embed install.sh.tmpl
var InstallScriptTemplate string

//go:embed notifications/*.tmpl
var NotificationTemplateFS embed.FS
