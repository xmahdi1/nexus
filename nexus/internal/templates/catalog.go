package templates

type VarType string

const (
	VarString   VarType = "string"
	VarPassword VarType = "password"
	VarNumber   VarType = "number"
	VarSelect   VarType = "select"
)

type TemplateVar struct {
	Name          string   `json:"name"`
	Label         string   `json:"label"`
	Description   string   `json:"description,omitempty"`
	Default       string   `json:"default,omitempty"`
	StoredDefault bool     `json:"storedDefault,omitempty"`
	Required      bool     `json:"required"`
	Type          VarType  `json:"type"`
	Options       []string `json:"options,omitempty"`
}

type AppTemplate struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Icon        string        `json:"icon"`
	IconLight   string        `json:"iconLight,omitempty"`
	Category    string        `json:"category"`
	DocURL      string        `json:"docUrl,omitempty"`
	PostDeploy  string        `json:"postDeploy,omitempty"`
	Vars        []TemplateVar `json:"vars"`
	Compose     string        `json:"-"`
	BuiltIn     bool          `json:"builtIn"`
}

func Catalog() []AppTemplate {
	return []AppTemplate{
		vaultTemplate(),
		{
			ID: "portainer", Name: "Portainer",
			Icon:        "/app-logos/portainer.png",
			Category:    "Management",
			Description: "Docker container management UI with a web interface.",
			DocURL:      "https://docs.portainer.io",
			PostDeploy:  "Open https://YOUR_SERVER:${PORT} to set up your admin account.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "HTTPS Port", Default: "9443", Required: true, Type: VarNumber,
					Description: "Port for the Portainer web UI (HTTPS)"},
			},
			BuiltIn: true,
			Compose: `services:
  portainer:
    image: portainer/portainer-ce:latest
    container_name: portainer
    restart: unless-stopped
    ports:
      - "${PORT}:9443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - portainer_data:/data
volumes:
  portainer_data:
`,
		},
		{
			ID: "n8n", Name: "n8n",
			Icon:        "/app-logos/n8n.png",
			Category:    "Automation",
			Description: "Workflow automation tool. Connect anything to everything.",
			DocURL:      "https://docs.n8n.io",
			PostDeploy:  "Open http://YOUR_SERVER:${PORT} and sign in with your credentials.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "5678", Required: true, Type: VarNumber},
				{Name: "USERNAME", Label: "Admin Username", Default: "admin", Required: true, Type: VarString},
				{Name: "PASSWORD", Label: "Admin Password", Required: true, Type: VarPassword},
				{Name: "TIMEZONE", Label: "Timezone", Default: "Europe/Berlin", Required: false, Type: VarString,
					Description: "e.g. America/New_York, Asia/Tokyo"},
			},
			BuiltIn: true,
			Compose: `services:
  n8n:
    image: n8nio/n8n:latest
    container_name: n8n
    restart: unless-stopped
    ports:
      - "${PORT}:5678"
    environment:
      - GENERIC_TIMEZONE=${TIMEZONE}
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=${USERNAME}
      - N8N_BASIC_AUTH_PASSWORD=${PASSWORD}
    volumes:
      - n8n_data:/home/node/.n8n
volumes:
  n8n_data:
`,
		},
		{
			ID: "nextcloud", Name: "Nextcloud",
			Icon:        "/app-logos/nextcloud.png",
			Category:    "Storage",
			Description: "Self-hosted file storage, calendar, contacts and more.",
			DocURL:      "https://docs.nextcloud.com",
			PostDeploy:  "Open http://YOUR_SERVER:${PORT} and finish setup with your admin credentials.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "8080", Required: true, Type: VarNumber},
				{Name: "ADMIN_USER", Label: "Admin Username", Default: "admin", Required: true, Type: VarString},
				{Name: "ADMIN_PASSWORD", Label: "Admin Password", Required: true, Type: VarPassword},
				{Name: "DB_PASSWORD", Label: "Database Password", Required: true, Type: VarPassword},
			},
			BuiltIn: true,
			Compose: `services:
  nextcloud:
    image: nextcloud:latest
    container_name: nextcloud
    restart: unless-stopped
    ports:
      - "${PORT}:80"
    environment:
      - NEXTCLOUD_ADMIN_USER=${ADMIN_USER}
      - NEXTCLOUD_ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - MYSQL_HOST=nextcloud_db
      - MYSQL_DATABASE=nextcloud
      - MYSQL_USER=nextcloud
      - MYSQL_PASSWORD=${DB_PASSWORD}
    volumes:
      - nextcloud_data:/var/www/html
    depends_on:
      - nextcloud_db
  nextcloud_db:
    image: mariadb:11
    container_name: nextcloud_db
    restart: unless-stopped
    environment:
      - MYSQL_ROOT_PASSWORD=${DB_PASSWORD}
      - MYSQL_DATABASE=nextcloud
      - MYSQL_USER=nextcloud
      - MYSQL_PASSWORD=${DB_PASSWORD}
    volumes:
      - nextcloud_db:/var/lib/mysql
volumes:
  nextcloud_data:
  nextcloud_db:
`,
		},
		{
			ID: "gitea", Name: "Gitea",
			Icon:        "/app-logos/gitea.png",
			Category:    "Development",
			Description: "Lightweight self-hosted Git service.",
			DocURL:      "https://docs.gitea.com",
			PostDeploy:  "Open http://YOUR_SERVER:${HTTP_PORT} to complete installation.",
			Vars: []TemplateVar{
				{Name: "HTTP_PORT", Label: "Web Port", Default: "3000", Required: true, Type: VarNumber},
				{Name: "SSH_PORT", Label: "SSH Port", Default: "2222", Required: true, Type: VarNumber},
				{Name: "DB_PASSWORD", Label: "Database Password", Required: true, Type: VarPassword},
			},
			BuiltIn: true,
			Compose: `services:
  gitea:
    image: gitea/gitea:latest
    container_name: gitea
    restart: unless-stopped
    ports:
      - "${HTTP_PORT}:3000"
      - "${SSH_PORT}:22"
    environment:
      - GITEA__database__DB_TYPE=mysql
      - GITEA__database__HOST=gitea_db:3306
      - GITEA__database__NAME=gitea
      - GITEA__database__USER=gitea
      - GITEA__database__PASSWD=${DB_PASSWORD}
    volumes:
      - gitea_data:/data
    depends_on:
      - gitea_db
  gitea_db:
    image: mariadb:11
    container_name: gitea_db
    restart: unless-stopped
    environment:
      - MYSQL_ROOT_PASSWORD=${DB_PASSWORD}
      - MYSQL_DATABASE=gitea
      - MYSQL_USER=gitea
      - MYSQL_PASSWORD=${DB_PASSWORD}
    volumes:
      - gitea_db:/var/lib/mysql
volumes:
  gitea_data:
  gitea_db:
`,
		},
		{
			ID: "postgresql", Name: "PostgreSQL",
			Icon:        "/app-logos/postgresql.png",
			Category:    "Databases",
			Description: "Powerful open-source relational database.",
			DocURL:      "https://www.postgresql.org/docs",
			PostDeploy:  "Connect on port ${PORT} with user ${DB_USER} and database ${DB_NAME}.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "5432", Required: true, Type: VarNumber},
				{Name: "DB_USER", Label: "Database User", Default: "postgres", Required: true, Type: VarString},
				{Name: "DB_PASSWORD", Label: "Database Password", Required: true, Type: VarPassword},
				{Name: "DB_NAME", Label: "Database Name", Default: "app", Required: true, Type: VarString},
			},
			BuiltIn: true,
			Compose: `services:
  postgres:
    image: postgres:16-alpine
    container_name: postgres
    restart: unless-stopped
    ports:
      - "${PORT}:5432"
    environment:
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=${DB_NAME}
    volumes:
      - postgres_data:/var/lib/postgresql/data
volumes:
  postgres_data:
`,
		},
		{
			ID: "redis", Name: "Redis",
			Icon:        "/app-logos/redis.png",
			Category:    "Databases",
			Description: "In-memory data store used as cache, message broker and queue.",
			PostDeploy:  "Connect on port ${PORT}. Password: ${PASSWORD}",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "6379", Required: true, Type: VarNumber},
				{Name: "PASSWORD", Label: "Password", Required: true, Type: VarPassword},
			},
			BuiltIn: true,
			Compose: `services:
  redis:
    image: redis:7-alpine
    container_name: redis
    restart: unless-stopped
    ports:
      - "${PORT}:6379"
    command: redis-server --requirepass ${PASSWORD}
    volumes:
      - redis_data:/data
volumes:
  redis_data:
`,
		},
		{
			ID: "ollama", Name: "Ollama",
			Icon:        "/app-logos/ollama.png",
			Category:    "AI",
			Description: "Run large language models locally. Supports Llama, Mistral, Gemma and more.",
			DocURL:      "https://ollama.ai",
			PostDeploy:  "Ollama API is at http://YOUR_SERVER:${PORT}. Run: docker exec -it ollama ollama pull llama3",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "API Port", Default: "11434", Required: true, Type: VarNumber},
			},
			BuiltIn: true,
			Compose: `services:
  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    restart: unless-stopped
    ports:
      - "${PORT}:11434"
    volumes:
      - ollama_data:/root/.ollama
volumes:
  ollama_data:
`,
		},
		{
			ID: "ghost", Name: "Ghost",
			Icon:        "/app-logos/ghost.png",
			IconLight:   "/app-logos/ghost-light.png",
			Category:    "CMS",
			Description: "Professional publishing platform for blogs and newsletters.",
			DocURL:      "https://ghost.org/docs",
			PostDeploy:  "Open http://YOUR_SERVER:${PORT}/ghost to set up your blog.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "2368", Required: true, Type: VarNumber},
				{Name: "URL", Label: "Site URL", Default: "http://localhost:2368", Required: true, Type: VarString,
					Description: "Full URL where Ghost will be accessed"},
				{Name: "DB_PASSWORD", Label: "Database Password", Required: true, Type: VarPassword},
			},
			BuiltIn: true,
			Compose: `services:
  ghost:
    image: ghost:5-alpine
    container_name: ghost
    restart: unless-stopped
    ports:
      - "${PORT}:2368"
    environment:
      - url=${URL}
      - database__client=mysql
      - database__connection__host=ghost_db
      - database__connection__database=ghost
      - database__connection__user=ghost
      - database__connection__password=${DB_PASSWORD}
    volumes:
      - ghost_data:/var/lib/ghost/content
    depends_on:
      - ghost_db
  ghost_db:
    image: mysql:8.0
    container_name: ghost_db
    restart: unless-stopped
    environment:
      - MYSQL_ROOT_PASSWORD=${DB_PASSWORD}
      - MYSQL_DATABASE=ghost
      - MYSQL_USER=ghost
      - MYSQL_PASSWORD=${DB_PASSWORD}
    volumes:
      - ghost_db:/var/lib/mysql
volumes:
  ghost_data:
  ghost_db:
`,
		},
		{
			ID: "plausible", Name: "Plausible Analytics",
			Icon:        "/app-logos/plausible.png",
			Category:    "Analytics",
			Description: "Privacy-friendly, lightweight web analytics.",
			DocURL:      "https://plausible.io/docs",
			PostDeploy:  "Open http://YOUR_SERVER:${PORT} and sign in with ${ADMIN_EMAIL}.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "8000", Required: true, Type: VarNumber},
				{Name: "BASE_URL", Label: "Base URL", Default: "http://localhost:8000", Required: true, Type: VarString},
				{Name: "ADMIN_EMAIL", Label: "Admin Email", Required: true, Type: VarString},
				{Name: "ADMIN_PASSWORD", Label: "Admin Password", Required: true, Type: VarPassword},
				{Name: "SECRET_KEY", Label: "Secret Key (64 chars)", Required: true, Type: VarPassword,
					Description: "Run: openssl rand -base64 48"},
			},
			BuiltIn: true,
			Compose: `services:
  plausible:
    image: ghcr.io/plausible/community-edition:v2
    container_name: plausible
    restart: unless-stopped
    ports:
      - "${PORT}:8000"
    environment:
      - BASE_URL=${BASE_URL}
      - SECRET_KEY_BASE=${SECRET_KEY}
    command: sh -c "sleep 10 && /entrypoint.sh db createdb && /entrypoint.sh db migrate && /entrypoint.sh run"
    depends_on:
      - plausible_db
      - plausible_events_db
  plausible_db:
    image: postgres:16-alpine
    container_name: plausible_db
    restart: unless-stopped
    environment:
      - POSTGRES_PASSWORD=postgres
    volumes:
      - plausible_db:/var/lib/postgresql/data
  plausible_events_db:
    image: clickhouse/clickhouse-server:23.3-alpine
    container_name: plausible_events_db
    restart: unless-stopped
    volumes:
      - plausible_events:/var/lib/clickhouse
volumes:
  plausible_db:
  plausible_events:
`,
		},
		{
			ID: "vaultwarden", Name: "Vaultwarden",
			Icon:        "/app-logos/vaultwarden.png",
			IconLight:   "/app-logos/vaultwarden-light.png",
			Category:    "Security",
			Description: "Unofficial Bitwarden-compatible server. Self-host your passwords.",
			DocURL:      "https://github.com/dani-garcia/vaultwarden/wiki",
			PostDeploy:  "Open http://YOUR_SERVER:${PORT}. Set ADMIN_TOKEN to access /admin panel.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "8080", Required: true, Type: VarNumber},
				{Name: "DOMAIN", Label: "Domain URL", Default: "http://localhost:8080", Required: false, Type: VarString},
				{Name: "ADMIN_TOKEN", Label: "Admin Token", Required: false, Type: VarPassword,
					Description: "Leave empty to disable admin panel"},
				{Name: "SIGNUPS_ALLOWED", Label: "Allow Signups", Default: "true", Required: true, Type: VarSelect,
					Options: []string{"true", "false"}},
			},
			BuiltIn: true,
			Compose: `services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    restart: unless-stopped
    ports:
      - "${PORT}:80"
    environment:
      - DOMAIN=${DOMAIN}
      - ADMIN_TOKEN=${ADMIN_TOKEN}
      - SIGNUPS_ALLOWED=${SIGNUPS_ALLOWED}
    volumes:
      - vaultwarden_data:/data
volumes:
  vaultwarden_data:
`,
		},
		{
			ID: "uptime-kuma", Name: "Uptime Kuma",
			Icon:        "/app-logos/uptime-kuma.png",
			Category:    "Monitoring",
			Description: "Easy-to-use self-hosted monitoring tool.",
			DocURL:      "https://github.com/louislam/uptime-kuma/wiki",
			PostDeploy:  "Open http://YOUR_SERVER:${PORT} to set up monitoring.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "3001", Required: true, Type: VarNumber},
			},
			BuiltIn: true,
			Compose: `services:
  uptime-kuma:
    image: louislam/uptime-kuma:latest
    container_name: uptime-kuma
    restart: unless-stopped
    ports:
      - "${PORT}:3001"
    volumes:
      - uptime_kuma_data:/app/data
volumes:
  uptime_kuma_data:
`,
		},
		{
			ID: "nginx-proxy-manager", Name: "Nginx Proxy Manager",
			Icon:        "/app-logos/nginx-proxy-manager.png",
			Category:    "Networking",
			Description: "Easy nginx reverse proxy with SSL and a beautiful UI.",
			DocURL:      "https://nginxproxymanager.com/guide",
			PostDeploy:  "Open http://YOUR_SERVER:${ADMIN_PORT}. Default: admin@example.com / changeme",
			Vars: []TemplateVar{
				{Name: "HTTP_PORT", Label: "HTTP Port", Default: "80", Required: true, Type: VarNumber},
				{Name: "HTTPS_PORT", Label: "HTTPS Port", Default: "443", Required: true, Type: VarNumber},
				{Name: "ADMIN_PORT", Label: "Admin UI Port", Default: "81", Required: true, Type: VarNumber},
			},
			BuiltIn: true,
			Compose: `services:
  npm:
    image: jc21/nginx-proxy-manager:latest
    container_name: nginx-proxy-manager
    restart: unless-stopped
    ports:
      - "${HTTP_PORT}:80"
      - "${HTTPS_PORT}:443"
      - "${ADMIN_PORT}:81"
    volumes:
      - npm_data:/data
      - npm_letsencrypt:/etc/letsencrypt
volumes:
  npm_data:
  npm_letsencrypt:
`,
		},
		{
			ID: "mariadb", Name: "MariaDB",
			Icon:        "/app-logos/mariadb.png",
			Category:    "Databases",
			Description: "Community-developed fork of MySQL. Drop-in replacement.",
			PostDeploy:  "Connect on port ${PORT} as root or user ${DB_USER}.",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "3306", Required: true, Type: VarNumber},
				{Name: "ROOT_PASSWORD", Label: "Root Password", Required: true, Type: VarPassword},
				{Name: "DB_USER", Label: "Database User", Default: "app", Required: true, Type: VarString},
				{Name: "DB_PASSWORD", Label: "User Password", Required: true, Type: VarPassword},
				{Name: "DB_NAME", Label: "Database Name", Default: "app", Required: true, Type: VarString},
			},
			BuiltIn: true,
			Compose: `services:
  mariadb:
    image: mariadb:11
    container_name: mariadb
    restart: unless-stopped
    ports:
      - "${PORT}:3306"
    environment:
      - MARIADB_ROOT_PASSWORD=${ROOT_PASSWORD}
      - MARIADB_USER=${DB_USER}
      - MARIADB_PASSWORD=${DB_PASSWORD}
      - MARIADB_DATABASE=${DB_NAME}
    volumes:
      - mariadb_data:/var/lib/mysql
volumes:
  mariadb_data:
`,
		},
		{
			ID: "mongodb", Name: "MongoDB",
			Icon:        "/app-logos/mongodb.png",
			Category:    "Databases",
			Description: "Document-oriented NoSQL database.",
			PostDeploy:  "Connect on port ${PORT} with: mongodb://${ROOT_USER}:${ROOT_PASSWORD}@host:${PORT}/",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "27017", Required: true, Type: VarNumber},
				{Name: "ROOT_USER", Label: "Root Username", Default: "admin", Required: true, Type: VarString},
				{Name: "ROOT_PASSWORD", Label: "Root Password", Required: true, Type: VarPassword},
			},
			BuiltIn: true,
			Compose: `services:
  mongodb:
    image: mongo:7
    container_name: mongodb
    restart: unless-stopped
    ports:
      - "${PORT}:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=${ROOT_USER}
      - MONGO_INITDB_ROOT_PASSWORD=${ROOT_PASSWORD}
    volumes:
      - mongodb_data:/data/db
volumes:
  mongodb_data:
`,
		},
		{
			ID: "minio", Name: "MinIO",
			Icon:        "/app-logos/minio.png",
			IconLight:   "/app-logos/minio-light.png",
			Category:    "Storage",
			Description: "High-performance S3-compatible object storage.",
			DocURL:      "https://min.io/docs",
			PostDeploy:  "Console at http://YOUR_SERVER:${CONSOLE_PORT}. API at port ${API_PORT}.",
			Vars: []TemplateVar{
				{Name: "API_PORT", Label: "API Port", Default: "9000", Required: true, Type: VarNumber},
				{Name: "CONSOLE_PORT", Label: "Console Port", Default: "9001", Required: true, Type: VarNumber},
				{Name: "ROOT_USER", Label: "Root Username", Default: "minioadmin", Required: true, Type: VarString},
				{Name: "ROOT_PASSWORD", Label: "Root Password", Required: true, Type: VarPassword,
					Description: "Minimum 8 characters"},
			},
			BuiltIn: true,
			Compose: `services:
  minio:
    image: minio/minio:latest
    container_name: minio
    restart: unless-stopped
    ports:
      - "${API_PORT}:9000"
      - "${CONSOLE_PORT}:9001"
    environment:
      - MINIO_ROOT_USER=${ROOT_USER}
      - MINIO_ROOT_PASSWORD=${ROOT_PASSWORD}
    command: server /data --console-address ":9001"
    volumes:
      - minio_data:/data
volumes:
  minio_data:
`,
		},
		{
			ID: "grafana", Name: "Grafana",
			Icon:        "/app-logos/grafana.png",
			Category:    "Monitoring",
			Description: "Open-source analytics and visualization platform.",
			DocURL:      "https://grafana.com/docs",
			PostDeploy:  "Open http://YOUR_SERVER:${PORT}. Default login: admin / ${ADMIN_PASSWORD}",
			Vars: []TemplateVar{
				{Name: "PORT", Label: "Port", Default: "3000", Required: true, Type: VarNumber},
				{Name: "ADMIN_PASSWORD", Label: "Admin Password", Default: "admin", Required: true, Type: VarPassword},
			},
			BuiltIn: true,
			Compose: `services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "${PORT}:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${ADMIN_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
volumes:
  grafana_data:
`,
		},
	}
}

func CatalogMap() map[string]AppTemplate {
	m := map[string]AppTemplate{}
	for _, t := range Catalog() {
		m[t.ID] = t
	}
	return m
}
