package templates

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xmahdi1/nexus/internal/audit"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type Handler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
}

func NewHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *Handler {
	return &Handler{db: db, encKey: encKey, pool: pool}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	result := Catalog()
	var custom []models.CustomTemplate
	if err := h.db.Find(&custom).Error; err != nil {
		writeErr(w, "Template catalog unavailable.", 503)
		return
	}
	for _, row := range custom {
		template, err := h.openCustom(row)
		if err != nil {
			writeErr(w, "Template definition unavailable.", 503)
			return
		}
		template.Compose = ""
		template.PostDeploy = ""
		for i := range template.Vars {
			template.Vars[i].StoredDefault = template.Vars[i].Default != ""
			template.Vars[i].Default = ""
		}
		result = append(result, template)
	}
	writeJSON(w, result, http.StatusOK)
}

func (h *Handler) openCustom(row models.CustomTemplate) (AppTemplate, error) {
	value, err := nexuscrypto.DecryptTemplateDefinition(h.encKey, row.ID, row.DefinitionEnc)
	if err != nil {
		return AppTemplate{}, fmt.Errorf("protected template unavailable")
	}
	var vars []TemplateVar
	if value.VarsJSON != "" && json.Unmarshal([]byte(value.VarsJSON), &vars) != nil {
		return AppTemplate{}, fmt.Errorf("invalid protected variables")
	}
	return AppTemplate{ID: row.ID, Name: row.Name, Icon: row.Icon, Category: row.Category, Description: row.Description, DocURL: row.DocURL, Vars: vars, PostDeploy: value.PostDeploy, Compose: value.Compose}, nil
}
func (h *Handler) GetCustom(w http.ResponseWriter, r *http.Request) {
	var row models.CustomTemplate
	if err := h.db.First(&row, "id=?", chi.URLParam(r, "id")).Error; err != nil {
		writeErr(w, "Template not found.", 404)
		return
	}
	template, err := h.openCustom(row)
	if err != nil {
		writeErr(w, "Protected template unavailable.", 503)
		return
	}
	writeJSON(w, map[string]any{"id": template.ID, "name": template.Name, "icon": template.Icon, "category": template.Category, "description": template.Description, "docUrl": template.DocURL, "vars": template.Vars, "compose": template.Compose, "postDeploy": template.PostDeploy, "builtIn": false}, 200)
}

func (h *Handler) ListDeployed(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var apps []models.DeployedApp
	h.db.Where("server_id = ?", serverID).Order("deployed_at desc").Find(&apps)
	if len(apps) == 0 {
		writeJSON(w, []models.DeployedApp{}, http.StatusOK)
		return
	}

	if run, err := h.sshRun(r.Context(), serverID); err == nil {
		if out, _ := run(`docker ps -a --format '{{.Names}} {{.State}}' 2>/dev/null`); out != "" {
			type ctr struct{ running bool }
			ctrs := make(map[string]ctr)
			for _, line := range strings.Split(out, "\n") {
				parts := strings.Fields(line)
				if len(parts) == 2 {
					ctrs[parts[0]] = ctr{running: parts[1] == "running"}
				}
			}
			var keep []models.DeployedApp
			for i := range apps {
				var matched *ctr
				for name, c := range ctrs {
					if name == apps[i].Name || strings.HasPrefix(name, apps[i].Name+"-") {
						cp := c
						matched = &cp
						break
					}
				}
				if matched == nil {
					apps[i].Status = "unknown"
					keep = append(keep, apps[i])
					continue
				}
				newStatus := "stopped"
				if matched.running {
					newStatus = "running"
				}
				if apps[i].Status != newStatus {
					apps[i].Status = newStatus
					h.db.Model(&apps[i]).Update("status", newStatus)
				}
				keep = append(keep, apps[i])
			}
			apps = keep
		}
	}

	if apps == nil {
		apps = []models.DeployedApp{}
	}
	writeJSON(w, apps, http.StatusOK)
}

func (h *Handler) Deploy(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var body struct {
		TemplateID string            `json:"templateId"`
		AppName    string            `json:"appName"`
		Variables  map[string]string `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TemplateID == "" {
		writeErr(w, "templateId required", http.StatusBadRequest)
		return
	}
	if body.AppName == "" {
		body.AppName = body.TemplateID
	}
	body.AppName = sanitizeName(body.AppName)
	if !appNameRe.MatchString(body.AppName) {
		writeErr(w, "App name must start with a letter or digit and contain 1 to 64 letters, digits or hyphens.", 400)
		return
	}

	tpl, err := h.resolveTemplate(body.TemplateID)
	if err != nil {
		writeErr(w, "template not found: "+body.TemplateID, http.StatusNotFound)
		return
	}
	for _, v := range tpl.Vars {
		if body.Variables[v.Name] == "" && v.Default != "" {
			if body.Variables == nil {
				body.Variables = map[string]string{}
			}
			body.Variables[v.Name] = v.Default
		}
		if v.Required && body.Variables[v.Name] == "" {
			writeErr(w, fmt.Sprintf("variable %q is required", v.Name), 400)
			return
		}
	}

	if tpl.ID == "vault" && tpl.BuiltIn {
		if err := validateVaultVariables(body.Variables); err != nil {
			writeErr(w, err.Error(), 400)
			return
		}
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		writeErr(w, "Could not allocate deployment identity.", 503)
		return
	}
	appID := hex.EncodeToString(id)
	varsJSON, err := json.Marshal(body.Variables)
	if err != nil {
		writeErr(w, "Invalid deployment variables.", 400)
		return
	}
	encryptedVars, err := nexuscrypto.EncryptDeploymentVariables(h.encKey, appID, serverID, varsJSON)
	clear(varsJSON)
	if err != nil {
		writeErr(w, "Deployment encryption unavailable.", 503)
		return
	}

	compose := renderCompose(tpl.Compose, body.Variables)
	send, err := h.sshInput(r.Context(), serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}

	run := func(command string) (string, error) { return send(command, "") }

	if out, err := run(`PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin" which docker 2>/dev/null || command -v docker 2>/dev/null`); err != nil || out == "" {
		writeErr(w,
			"Docker is not installed on this server.\n\nInstall it with:\n  apt install docker.io\nor:\n  snap install docker\n\nThen restart the Docker service:\n  systemctl start docker",
			http.StatusBadRequest)
		return
	}

	deployPath := fmt.Sprintf("/opt/nexus-apps/%s", body.AppName)
	if _, err := run("umask 077; mkdir -p /opt/nexus-apps && mkdir -- " + shellQuote(deployPath)); err != nil {
		writeErr(w, "App directory could not be reserved; existing files were retained.", http.StatusConflict)
		return
	}
	if _, err := send("umask 077; cat > "+shellQuote(deployPath+"/docker-compose.yml"), compose); err != nil {
		writeErr(w, "write compose failed", http.StatusBadGateway)
		return
	}

	output, deployErr := run(deploymentCommand(deployPath, "up -d"))

	app := models.DeployedApp{
		ID:          appID,
		ServerID:    serverID,
		TemplateID:  body.TemplateID,
		Name:        body.AppName,
		ComposePath: deployPath,
		VarsEnc:     encryptedVars,
		Status:      "running",
		DeployedAt:  time.Now(),
	}
	if errors.Is(deployErr, nexusssh.ErrRemoteUnknown) {
		app.Status = "unknown"
	} else if deployErr != nil {
		app.Status = "failed"
	}
	if err := h.db.Create(&app).Error; err != nil {
		writeErr(w, "Could not store deployment status.", 500)
		return
	}

	audit.MarkResource(r.Context(), "application", app.ID)
	w.Header().Set("Content-Type", "application/json")
	if deployErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": deployErr.Error(), "output": output, "app": app})
		return
	}
	writeJSON(w, map[string]any{
		"app":        app,
		"output":     output,
		"postDeploy": renderCompose(tpl.PostDeploy, body.Variables),
	}, http.StatusCreated)
}

func (h *Handler) Remove(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	appID := chi.URLParam(r, "appId")
	var app models.DeployedApp
	if err := h.db.First(&app, "id = ? AND server_id = ?", appID, serverID).Error; err != nil {
		writeErr(w, "app not found", http.StatusNotFound)
		return
	}
	run, err := h.sshRun(r.Context(), serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	output, err := stopDeployment(run, app.ComposePath)
	if err != nil {
		writeErr(w, "App shutdown failed; files, volumes and the stored record were retained.", 502)
		return
	}
	if err := h.db.Delete(&app).Error; err != nil {
		writeErr(w, "App stopped, but the stored record could not be removed.", 500)
		return
	}

	writeJSON(w, map[string]string{"output": output}, http.StatusOK)
}

func (h *Handler) CreateCustom(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string        `json:"name"`
		Icon        string        `json:"icon"`
		Category    string        `json:"category"`
		Description string        `json:"description"`
		DocURL      string        `json:"docUrl"`
		PostDeploy  string        `json:"postDeploy"`
		Vars        []TemplateVar `json:"vars"`
		Compose     string        `json:"compose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.Compose == "" {
		writeErr(w, "name and compose are required", http.StatusBadRequest)
		return
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		writeErr(w, "Template identity unavailable.", 503)
		return
	}
	varsJSON, _ := json.Marshal(body.Vars)
	encrypted, err := nexuscrypto.EncryptTemplateDefinition(h.encKey, hex.EncodeToString(id), nexuscrypto.TemplateDefinition{Compose: body.Compose, VarsJSON: string(varsJSON), PostDeploy: body.PostDeploy})
	clear(varsJSON)
	if err != nil {
		writeErr(w, "Template encryption unavailable.", 503)
		return
	}
	tpl := models.CustomTemplate{ID: hex.EncodeToString(id), Name: body.Name, Icon: body.Icon, Category: body.Category, Description: body.Description, DocURL: body.DocURL, DefinitionEnc: encrypted, CreatedAt: time.Now()}

	if err := h.db.Create(&tpl).Error; err != nil {
		writeErr(w, "Could not create template.", 503)
		return
	}
	audit.MarkResource(r.Context(), "template", tpl.ID)
	writeJSON(w, tpl, http.StatusCreated)
}

func (h *Handler) UpdateCustom(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var tpl models.CustomTemplate
	if err := h.db.First(&tpl, "id = ?", id).Error; err != nil {
		writeErr(w, "not found", http.StatusNotFound)
		return
	}
	var body struct {
		Name        string        `json:"name"`
		Icon        string        `json:"icon"`
		Category    string        `json:"category"`
		Description string        `json:"description"`
		DocURL      string        `json:"docUrl"`
		PostDeploy  string        `json:"postDeploy"`
		Vars        []TemplateVar `json:"vars"`
		Compose     string        `json:"compose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.Compose == "" {
		writeErr(w, "Name and compose are required.", 400)
		return
	}
	varsJSON, _ := json.Marshal(body.Vars)
	encrypted, err := nexuscrypto.EncryptTemplateDefinition(h.encKey, tpl.ID, nexuscrypto.TemplateDefinition{Compose: body.Compose, VarsJSON: string(varsJSON), PostDeploy: body.PostDeploy})
	clear(varsJSON)
	if err != nil {
		writeErr(w, "Template encryption unavailable.", 503)
		return
	}
	if err := h.db.Model(&tpl).Updates(map[string]any{
		"name": body.Name, "icon": body.Icon, "category": body.Category,
		"description": body.Description, "doc_url": body.DocURL,
		"definition_enc": encrypted,
	}).Error; err != nil {
		writeErr(w, "Could not update template.", 503)
		return
	}
	if err := h.db.First(&tpl, "id=?", id).Error; err != nil {
		writeErr(w, "Could not reload template.", 503)
		return
	}
	writeJSON(w, tpl, 200)
}

func (h *Handler) DeleteCustom(w http.ResponseWriter, r *http.Request) {
	if err := h.db.Delete(&models.CustomTemplate{}, "id = ?", chi.URLParam(r, "id")).Error; err != nil {
		writeErr(w, "Could not delete template.", 503)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) resolveTemplate(id string) (AppTemplate, error) {
	if tpl, ok := CatalogMap()[id]; ok {
		return tpl, nil
	}
	var c models.CustomTemplate
	if err := h.db.First(&c, "id = ?", id).Error; err != nil {
		return AppTemplate{}, fmt.Errorf("not found")
	}
	return h.openCustom(c)
}

func (h *Handler) sshRun(ctx context.Context, serverID string) (func(string) (string, error), error) {
	send, err := h.sshInput(ctx, serverID)
	if err != nil {
		return nil, err
	}
	return func(command string) (string, error) { return send(command, "") }, nil
}
func (h *Handler) sshInput(ctx context.Context, serverID string) (func(string, string) (string, error), error) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("key decrypt failed")
	}
	client, err := h.pool.GetContext(ctx, nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return func(cmd, input string) (string, error) {
		out, err := nexusssh.Run(ctx, client, cmd, strings.NewReader(input), nexusssh.CommandTimeout)
		return strings.TrimSpace(out), err
	}, nil
}

func renderCompose(tpl string, vars map[string]string) string {
	result := tpl
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
	}
	return result
}

func sanitizeName(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		} else if c == ' ' || c == '_' {
			b.WriteRune('-')
		}
	}
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, msg string, status int) {
	writeJSON(w, map[string]string{"error": msg}, status)
}

var appNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func stopDeployment(run func(string) (string, error), directory string) (string, error) {
	if path.Clean(directory) != directory || !strings.HasPrefix(directory, "/opt/nexus-apps/") || path.Dir(directory) != "/opt/nexus-apps" || !appNameRe.MatchString(path.Base(directory)) {
		return "", fmt.Errorf("invalid managed app directory")
	}
	// Keep named volumes, bind-mounted data and the Compose recipe for recovery.
	return run(deploymentCommand(directory, "down"))
}

func deploymentCommand(directory, action string) string {
	// Select the installed adapter before executing a mutation. Never retry a
	// failed v2 mutation through v1, or run a fallback outside the app directory.
	return "cd " + shellQuote(directory) + ` && { export PATH="$PATH:/usr/local/bin:/usr/bin:/bin"; if docker compose version >/dev/null 2>&1; then docker compose ` + action + ` 2>&1; elif command -v docker-compose >/dev/null 2>&1; then docker-compose ` + action + ` 2>&1; else exit 127; fi; }`
}
