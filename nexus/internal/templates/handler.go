package templates

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
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
	db.AutoMigrate(&models.DeployedApp{}, &models.CustomTemplate{})
	return &Handler{db: db, encKey: encKey, pool: pool}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	result := Catalog()
	var custom []models.CustomTemplate
	h.db.Find(&custom)
	for _, c := range custom {
		var vars []TemplateVar
		json.Unmarshal([]byte(c.VarsJSON), &vars)
		result = append(result, AppTemplate{
			ID: c.ID, Name: c.Name, Icon: c.Icon,
			Category: c.Category, Description: c.Description,
			DocURL: c.DocURL, PostDeploy: c.PostDeploy,
			Vars: vars, BuiltIn: false,
		})
	}
	writeJSON(w, result, http.StatusOK)
}

func (h *Handler) ListDeployed(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var apps []models.DeployedApp
	h.db.Where("server_id = ?", serverID).Order("deployed_at desc").Find(&apps)
	if len(apps) == 0 {
		writeJSON(w, []models.DeployedApp{}, http.StatusOK)
		return
	}

	if run, err := h.sshRun(serverID); err == nil {
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
					h.db.Delete(&apps[i])
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

	tpl, err := h.resolveTemplate(body.TemplateID)
	if err != nil {
		writeErr(w, "template not found: "+body.TemplateID, http.StatusNotFound)
		return
	}
	for _, v := range tpl.Vars {
		if v.Required && body.Variables[v.Name] == "" {
			writeErr(w, fmt.Sprintf("variable %q is required", v.Name), http.StatusBadRequest)
			return
		}
		if body.Variables[v.Name] == "" && v.Default != "" {
			if body.Variables == nil {
				body.Variables = map[string]string{}
			}
			body.Variables[v.Name] = v.Default
		}
	}

	compose := renderCompose(tpl.Compose, body.Variables)
	run, err := h.sshRun(serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}

	if out, err := run(`PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin" which docker 2>/dev/null || command -v docker 2>/dev/null`); err != nil || out == "" {
		writeErr(w,
			"Docker is not installed on this server.\n\nInstall it with:\n  apt install docker.io\nor:\n  snap install docker\n\nThen restart the Docker service:\n  systemctl start docker",
			http.StatusBadRequest)
		return
	}

	deployPath := fmt.Sprintf("/opt/nexus-apps/%s", body.AppName)
	if _, err := run(fmt.Sprintf("mkdir -p %s", deployPath)); err != nil {
		writeErr(w, "mkdir failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(compose))
	writeCmd := fmt.Sprintf("printf '%%s' %s | base64 -d > %s/docker-compose.yml", shellQuote(encoded), deployPath)
	if _, err := run(writeCmd); err != nil {
		writeErr(w, "write compose failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	output, deployErr := run(fmt.Sprintf(
		`cd %s && PATH="$PATH:/usr/local/bin:/usr/bin:/bin" docker compose up -d 2>&1 || docker-compose up -d 2>&1`,
		deployPath,
	))

	id := make([]byte, 8)
	rand.Read(id)
	varsJSON, _ := json.Marshal(body.Variables)
	app := models.DeployedApp{
		ID:          hex.EncodeToString(id),
		ServerID:    serverID,
		TemplateID:  body.TemplateID,
		Name:        body.AppName,
		ComposePath: deployPath,
		VarsJSON:    string(varsJSON),
		Status:      "running",
		DeployedAt:  time.Now(),
	}
	if deployErr != nil {
		app.Status = "failed"
	}
	h.db.Create(&app)

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
	run, err := h.sshRun(serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	output, _ := run(fmt.Sprintf(
		`cd %s && PATH="$PATH:/usr/local/bin:/usr/bin:/bin" docker compose down -v 2>&1 || docker-compose down -v 2>&1`,
		app.ComposePath,
	))
	run(fmt.Sprintf("rm -rf %s", app.ComposePath))
	h.db.Delete(&app)
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
	id := make([]byte, 8)
	rand.Read(id)
	varsJSON, _ := json.Marshal(body.Vars)
	tpl := models.CustomTemplate{
		ID: hex.EncodeToString(id), Name: body.Name, Icon: body.Icon,
		Category: body.Category, Description: body.Description,
		DocURL: body.DocURL, PostDeploy: body.PostDeploy,
		VarsJSON: string(varsJSON), Compose: body.Compose,
		CreatedAt: time.Now(),
	}
	h.db.Create(&tpl)
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
	json.NewDecoder(r.Body).Decode(&body)
	varsJSON, _ := json.Marshal(body.Vars)
	h.db.Model(&tpl).Updates(map[string]any{
		"name": body.Name, "icon": body.Icon, "category": body.Category,
		"description": body.Description, "doc_url": body.DocURL,
		"post_deploy": body.PostDeploy, "vars_json": string(varsJSON),
		"compose": body.Compose,
	})
	h.db.First(&tpl, "id = ?", id)
	writeJSON(w, tpl, http.StatusOK)
}

func (h *Handler) DeleteCustom(w http.ResponseWriter, r *http.Request) {
	h.db.Delete(&models.CustomTemplate{}, "id = ?", chi.URLParam(r, "id"))
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
	var vars []TemplateVar
	json.Unmarshal([]byte(c.VarsJSON), &vars)
	return AppTemplate{
		ID: c.ID, Name: c.Name, Icon: c.Icon,
		Category: c.Category, Description: c.Description,
		PostDeploy: c.PostDeploy, Vars: vars, Compose: c.Compose,
	}, nil
}

func (h *Handler) sshRun(serverID string) (func(string) (string, error), error) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("key decrypt failed")
	}
	client, err := h.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return func(cmd string) (string, error) {
		sess, err := client.NewSession()
		if err != nil {
			h.pool.Remove(serverID)
			return "", err
		}
		defer sess.Close()
		out, err := sess.CombinedOutput(cmd)
		return strings.TrimSpace(string(out)), err
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
