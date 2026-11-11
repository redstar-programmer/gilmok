package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Exposure: where a service is reachable from.
const (
	ExposurePublic    = "public"    // :443 via router port-forward (internet)
	ExposureTailscale = "tailscale" // :8443 via `tailscale serve` (tailnet only)
)

type AutheliaOpts struct {
	Enabled bool     `json:"enabled"`
	Policy  string   `json:"policy"` // one_factor | two_factor
	Groups  []string `json:"groups"` // empty = any logged-in user
}

type Service struct {
	ID        string       `json:"id"`
	Subdomain string       `json:"subdomain"` // "immich"  ->  immich.<domain>
	Upstream  string       `json:"upstream"`  // "immich_server:2283"
	Exposure  string       `json:"exposure"`  // public | tailscale
	Proxied   bool         `json:"proxied"`   // Cloudflare orange cloud (public only)
	MTLS      bool         `json:"mtls"`      // import cf_only (public + proxied)
	Authelia  AutheliaOpts `json:"authelia"`  //
	Extra     string       `json:"extra"`     // raw Caddy directives inserted before reverse_proxy
	Notes     string       `json:"notes"`     //
	Enabled   bool         `json:"enabled"`   // false = not generated, DNS untouched
	ManageDNS bool         `json:"manageDns"` // reconcile Cloudflare record
	DNSOnly   bool         `json:"dnsOnly"`   // DNS record only (no Caddy site), e.g. sftpgo
	WAF       string       `json:"waf"`       // "" (off) | detect | block — Coraza + OWASP CRS in Caddy
	// per-service WAF tuning (0 / empty = global settings)
	WAFParanoia int            `json:"wafParanoia,omitempty"` // blocking paranoia level override 1..4
	WAFExclude  []WafExclusion `json:"wafExclude,omitempty"`  // CRS rules switched off for this site only
	Guard       bool           `json:"guard"`                 // Caddy basic blocking (bots / attack paths), see guard.go
	Updated     time.Time      `json:"updated"`               //
}

type Settings struct {
	Lang             string `json:"lang"`              // UI language of this install: ko | en ("" = not chosen yet — the first visit asks)
	Domain           string `json:"domain"`            // e.g. example.com ("" until set — 설정 탭 › 도메인)
	TailscaleIP      string `json:"tailscaleIp"`       // e.g. 100.64.0.10
	TailscalePort    int    `json:"tailscalePort"`     // 8443 (Caddy listener for tailnet-only sites)
	CaddyContainer   string `json:"caddyContainer"`    // e.g. caddy
	CaddyfilePath    string `json:"caddyfilePath"`     // /stacks/caddy/Caddyfile (inside this container)
	CaddyfileInCtr   string `json:"caddyfileInCtr"`    // /etc/caddy/Caddyfile (inside caddy container)
	AutheliaCtr      string `json:"autheliaContainer"` // e.g. authelia
	AutheliaConfig   string `json:"autheliaConfig"`    // /stacks/authelia-config/configuration.yml
	AutheliaUsers    string `json:"autheliaUsers"`     // /stacks/authelia-config/users_database.yml
	AutheliaCtrDir   string `json:"autheliaCtrDir"`    // /config  (same dir inside authelia container)
	DefaultPolicy    string `json:"defaultPolicy"`     // deny
	DDNSEnabled      bool   `json:"ddnsEnabled"`       // update public A/AAAA records when WAN IP changes
	DDNSIPv6         bool   `json:"ddnsIpv6"`          // also manage AAAA records of public services
	DDNSIntervalMin  int    `json:"ddnsIntervalMin"`   //
	CaddyStackDir    string `json:"caddyStackDir"`     // host-visible path for `docker compose` (updates)
	CaddyService     string `json:"caddyService"`      // compose service name: caddy
	AutheliaStackDir string `json:"autheliaStackDir"`  //
	AutheliaService  string `json:"autheliaService"`   // authelia
	CaddyBase        string `json:"caddyBase"`         // global options + snippets (skeleton)

	// Caddy WAF (Coraza + OWASP CRS) — per-service mode is Service.WAF
	WafParanoia    int            `json:"wafParanoia"`    // CRS paranoia level 1..4
	WafBodyAccess  bool           `json:"wafBodyAccess"`  // inspect request bodies (off: uploads stay fast/unlimited)
	WafDirectives  string         `json:"wafDirectives"`  // extra SecLang lines after the CRS (advanced)
	WafV2          bool           `json:"wafV2"`          // defaults below applied once
	WafDetectPL    int            `json:"wafDetectPl"`    // detection paranoia level (logs only above the blocking level); 0 = same
	WafInbound     int            `json:"wafInbound"`     // inbound anomaly score threshold (CRS default 5)
	WafOutbound    int            `json:"wafOutbound"`    // outbound anomaly score threshold (CRS default 4)
	WafBodyLimitMB int            `json:"wafBodyLimitMb"` // inspected body size; 0 = Coraza default
	WafMethods     string         `json:"wafMethods"`     // allowed HTTP methods (CRS 911100)
	WafGroupsOff   []string       `json:"wafGroupsOff"`   // CRS rule groups switched off ("941", …)
	WafExclude     []WafExclusion `json:"wafExclude"`     // CRS rules switched off everywhere

	// Basic blocking (guard.go) — categories shared by Caddy (per-service Guard) and the Cloudflare threat rule
	GuardBots     bool   `json:"guardBots"`     // scanners / attack tools by User-Agent
	GuardAI       bool   `json:"guardAi"`       // AI crawlers
	GuardEmptyUA  bool   `json:"guardEmptyUa"`  // requests without User-Agent
	GuardPaths    bool   `json:"guardPaths"`    // well-known probe paths (/.env, /.git, /wp-login.php …)
	GuardPHP      bool   `json:"guardPhp"`      // any *.php (sites that are not PHP)
	GuardUA       string `json:"guardUa"`       // extra User-Agent substrings, one per line
	GuardPathList string `json:"guardPathList"` // extra path prefixes, one per line

	// Cloudflare WAF custom rules managed by Gilmok (edge, real client IPs, orange-cloud only)
	CfAsnRule      bool     `json:"cfAsnRule"`      // manage the "KR ISP only" ASN allow-list rule
	CfAsnList      string   `json:"cfAsnList"`      // e.g. "4766 9318" (ISPs to allow)
	CfAsnAction    string   `json:"cfAsnAction"`    // managed_challenge | block | js_challenge
	CfGeoMode      string   `json:"cfGeoMode"`      // allow (only listed pass) | block (listed get the action)
	CfGeoCountries string   `json:"cfGeoCountries"` // ISO codes, e.g. "KR"
	CfGeoBots      bool     `json:"cfGeoBots"`      // let verified bots (search engines) through
	CfGeoHosts     []string `json:"cfGeoHosts"`     // service ids; empty = whole zone

	CfAllowRule bool   `json:"cfAllowRule"` // trusted IPs skip the other custom rules
	CfAllowIPs  string `json:"cfAllowIps"`  // IPs / CIDRs, one per line

	CfThreatRule    bool     `json:"cfThreatRule"`    // one rule: deny IPs + bad bots + AI + empty UA + attack paths
	CfThreatAction  string   `json:"cfThreatAction"`  // block | managed_challenge
	CfThreatBots    bool     `json:"cfThreatBots"`    //
	CfThreatAI      bool     `json:"cfThreatAi"`      //
	CfThreatEmptyUA bool     `json:"cfThreatEmptyUa"` //
	CfThreatPaths   bool     `json:"cfThreatPaths"`   //
	CfThreatPHP     bool     `json:"cfThreatPhp"`     //
	CfDenyIPs       string   `json:"cfDenyIps"`       // IPs / CIDRs to block, one per line
	CfThreatHosts   []string `json:"cfThreatHosts"`   // service ids; empty = whole zone

	CfCustomRule   bool   `json:"cfCustomRule"`
	CfCustomName   string `json:"cfCustomName"`
	CfCustomExpr   string `json:"cfCustomExpr"`
	CfCustomAction string `json:"cfCustomAction"`

	CfRateRule     bool   `json:"cfRateRule"`     // rate limiting rule (phase http_ratelimit)
	CfRatePaths    string `json:"cfRatePaths"`    // path prefixes, one per line (empty = every path)
	CfRateRequests int    `json:"cfRateRequests"` // requests per period per IP
	CfRatePeriod   int    `json:"cfRatePeriod"`   // seconds (Free plan: 10)
	CfRateTimeout  int    `json:"cfRateTimeout"`  // block duration seconds (Free plan: 10)
	CfRateAction   string `json:"cfRateAction"`   // block | managed_challenge

	// CrowdSec (Cloudflare-integrated): reads Caddy access logs of mTLS sites (real IP from
	// Cf-Connecting-Ip), Gilmok syncs its ban decisions into a Cloudflare IP list + block rule.
	CrowdSecEnabled   bool   `json:"crowdsecEnabled"`   // access logs (with real IP) on mTLS sites
	CrowdSecContainer string `json:"crowdsecContainer"` // e.g. crowdsec
	CrowdSecLAPI      string `json:"crowdsecLapi"`      // e.g. http://crowdsec:8080
	CrowdSecSync      bool   `json:"crowdsecSync"`      // push bans to Cloudflare
	CrowdSecInterval  int    `json:"crowdsecInterval"`  // seconds

	// Components in use. Every deployment differs (Caddy only, Caddy + Authelia, DNS only, …):
	// nothing else in the app may assume a component exists unless its flag is on.
	UseInit       bool `json:"useInit"` // false → inferred once at start (components.go)
	UseCaddy      bool `json:"useCaddy"`
	UseAuthelia   bool `json:"useAuthelia"`
	UseCloudflare bool `json:"useCloudflare"`
	UseCrowdSec   bool `json:"useCrowdSec"`
	UseTailscale  bool `json:"useTailscale"` // private sites (:8443) reached over Tailscale / VPN
	UseTSInit     bool `json:"useTsInit"`

	// Logging (SQLite /data/gilmok-logs.db) — see logdb.go
	LogInit             bool `json:"logInit"` // defaults applied once
	LogRequests         bool `json:"logRequests"`
	LogMetrics          bool `json:"logMetrics"`
	LogKeepEventsOnStop bool `json:"logKeepEventsOnStop"`
	LogRetReqDays       int  `json:"logRetReqDays"`
	LogRetMetricDays    int  `json:"logRetMetricDays"`
	LogRetAuditDays     int  `json:"logRetAuditDays"`
	LogRetSecurityDays  int  `json:"logRetSecurityDays"`
	LogRetSystemDays    int  `json:"logRetSystemDays"`
	LogMaxDBMB          int  `json:"logMaxDbMb"`
	DiskWarnPct         int  `json:"diskWarnPct"`
	DiskCritPct         int  `json:"diskCritPct"`
	DiskStopPct         int  `json:"diskStopPct"`

	// How Gilmok talks to Caddy: docker (exec in the container) | native (caddy CLI on the same
	// host as Gilmok) | api (Caddy admin API, e.g. a native Windows Caddy)
	CaddyMode  string `json:"caddyMode"`
	CaddyBin   string `json:"caddyBin"`   // native: path of caddy(.exe)
	CaddyAdmin string `json:"caddyAdmin"` // api: http://host.docker.internal:2019

	// Access security (see security.go)
	SecInit        bool   `json:"secInit"`
	SecIdleMin     int    `json:"secIdleMin"`     // idle session timeout
	SecAbsHours    int    `json:"secAbsHours"`    // absolute session lifetime
	SecReauthMin   int    `json:"secReauthMin"`   // sensitive actions need a password within this window
	SecAllowDirect bool   `json:"secAllowDirect"` // allow the host-published port (127.0.0.1:8088)
	SecAllowProxy  bool   `json:"secAllowProxy"`  // allow access through Caddy (with the proxy secret)
	SecRequireSSO  bool   `json:"secRequireSso"`  // via Caddy: an Authelia user (Remote-User) is required
	SecSSOGroups   string `json:"secSsoGroups"`   // comma list; empty = any Authelia user
	SecSelfService string `json:"secSelfService"` // service id of Gilmok's own site (gets the proxy header)
	SecV2          bool   `json:"secV2"`          // account defaults applied once
	SecRequire2FA  bool   `json:"secRequire2fa"`  // policy (off by default): every account must set up TOTP before using the app
	UpdateCheck    bool   `json:"updateCheck"`    // check registries for newer images

	// Dashboard: access logs (`log # gilmok`) on every generated site, streamed by Gilmok.
	DashLogs bool `json:"dashLogs"`

	// Topology map: the part in front of this host that Gilmok cannot detect (asked in the UI).
	// Display only — never affects generated files.
	TopoEdgeKind    string `json:"topoEdgeKind"`    // "" (unknown) | router | direct | tunnel | proxy
	TopoEdgeName    string `json:"topoEdgeName"`    // e.g. router model
	TopoEdgeExtPort int    `json:"topoEdgeExtPort"` // port the internet connects to
	TopoEdgeFwdPort int    `json:"topoEdgeFwdPort"` // port forwarded to this host
	TopoEdgeNote    string `json:"topoEdgeNote"`    // e.g. "TCP 443만 · 국가 허용 KR"
	// TopoHops: the devices between the internet and this host, internet side first (router,
	// firewall, load balancer, reverse proxy, tunnel …). Replaces the single TopoEdge* device.
	TopoHops     []TopoHop `json:"topoHops"`
	TopoPrivKind string    `json:"topoPrivKind"` // "" | ts_serve | ts_direct | vpn
	TopoPrivName string    `json:"topoPrivName"`
	TopoPrivNote string    `json:"topoPrivNote"`
	TopoHostName string    `json:"topoHostName"` // e.g. "home-nas"
	TopoHostNote string    `json:"topoHostNote"` // e.g. "192.168.1.10 · Windows 11"
}

// CFWAFState: ids of the Cloudflare objects Gilmok owns (server-side only, not part of Settings
// so a settings form can never clobber them).
type CFWAFState struct {
	AsnRuleID    string `json:"asnRuleId"`
	AsnAdopted   bool   `json:"asnAdopted"` // the geo rule was made by hand and adopted: turning it off disables, never deletes
	CsRuleID     string `json:"csRuleId"`
	ListID       string `json:"listId"`
	AllowRuleID  string `json:"allowRuleId"`
	ThreatRuleID string `json:"threatRuleId"`
	CustomRuleID string `json:"customRuleId"`
	RateRuleID   string `json:"rateRuleId"`
}

// WafExclusion switches off one CRS rule (or a range "942100-942199").
type WafExclusion struct {
	ID   string `json:"id"`
	Note string `json:"note,omitempty"`
}

// TopoHop is one device in front of this host (display only — never changes Caddy or DNS).
type TopoHop struct {
	Kind    string `json:"kind"`    // router | firewall | lb | proxy | tunnel | other
	Name    string `json:"name"`    // e.g. model / product
	Note    string `json:"note"`    // shown small on the map
	ExtPort int    `json:"extPort"` // port it receives on (0 = not given)
	FwdPort int    `json:"fwdPort"` // port it passes on to the next hop / this host
	Tailnet bool   `json:"tailnet"` // Tailscale / VPN traffic also passes this device
}

type Data struct {
	Settings      Settings                 `json:"settings"`
	Services      []*Service               `json:"services"`
	AdminHash     string                   `json:"adminHash,omitempty"` // before accounts (migrated to Accounts)
	Accounts      []*Account               `json:"accounts"`
	Roles         []*Role                  `json:"roles"`
	LastApplied   time.Time                `json:"lastApplied"`
	LastPublicIP  string                   `json:"lastPublicIp"`
	Dirty         bool                     `json:"dirty"`         // there are saved changes not applied yet
	ManagedDNS    []string                 `json:"managedDns"`    // FQDNs whose A records this app owns
	ManagedDNS6   []string                 `json:"managedDns6"`   // FQDNs whose AAAA records this app owns
	LastPublicIP6 string                   `json:"lastPublicIp6"` //
	DDNS          DDNSStatus               `json:"ddns"`          // last DDNS run (shown in the Cloudflare tab)
	Pending       []string                 `json:"pending"`       // human-readable list of saved-but-unapplied changes
	CFWAF         CFWAFState               `json:"cfWaf"`
	Dashboard     []Widget                 `json:"dashboard"`             // nil = default layout
	ProxySecret   string                   `json:"proxySecret"`           // header Caddy adds for Gilmok's own site (never sent to the UI)
	TOTPSecret    string                   `json:"totpSecret,omitempty"`  // before accounts (migrated)
	TOTPPending   string                   `json:"totpPending,omitempty"` //
	Updates       UpdateInfo               `json:"updates"`
	SelfName      string                   `json:"selfName"`           // this container's name (detected at start)
	UpdBaseline   map[string]string        `json:"updBaseline"`        // base image → registry digest it was last built from
	AGroups       []AGroup                 `json:"autheliaGroups"`     // predefined Authelia groups (groups.go)
	AGroupsInit   bool                     `json:"autheliaGroupsInit"` // seeded once from groups already in use
	SetupDone     bool                     `json:"setupDone"`          // first-run setup finished or dismissed for good (setup.go)
	Stacks        map[string]*ManagedStack `json:"stacks,omitempty"`   // stacks Gilmok installed itself (stacks.go)
}

type Store struct {
	mu   sync.Mutex
	path string
	d    Data
}

// defaultSettings: a brand-new install — code defaults with the install-time hints from the
// environment (GM_DOMAIN, GM_CADDY_CONTAINER …) on top.
func defaultSettings() Settings {
	s := baseSettings()
	if l := env("GM_LANG", ""); uiLangs[l] {
		s.Lang = l // preset by the deployment (otherwise the first visit asks)
	}
	s.Domain = env("GM_DOMAIN", s.Domain)
	s.TailscaleIP = env("GM_TAILSCALE_IP", s.TailscaleIP)
	s.CaddyContainer = env("GM_CADDY_CONTAINER", s.CaddyContainer)
	s.CaddyfilePath = env("GM_CADDYFILE", s.CaddyfilePath)
	s.AutheliaCtr = env("GM_AUTHELIA_CONTAINER", s.AutheliaCtr)
	s.AutheliaConfig = env("GM_AUTHELIA_CONFIG", s.AutheliaConfig)
	s.AutheliaUsers = env("GM_AUTHELIA_USERS", s.AutheliaUsers)
	s.CaddyStackDir = env("GM_CADDY_STACK", s.CaddyStackDir)
	s.AutheliaStackDir = env("GM_AUTHELIA_STACK", s.AutheliaStackDir)
	s.CrowdSecContainer = env("GM_CROWDSEC_CONTAINER", s.CrowdSecContainer)
	s.CrowdSecLAPI = env("GM_CROWDSEC_LAPI", s.CrowdSecLAPI)
	return s
}

// baseSettings: the code defaults only — what a factory reset returns to (no environment hints).
func baseSettings() Settings {
	return Settings{
		Domain:           "",
		TailscaleIP:      "",
		TailscalePort:    8443,
		CaddyContainer:   "caddy",
		CaddyfilePath:    "/stacks/caddy/Caddyfile",
		CaddyfileInCtr:   "/etc/caddy/Caddyfile",
		AutheliaCtr:      "authelia",
		AutheliaConfig:   "/stacks/authelia-config/configuration.yml",
		AutheliaUsers:    "/stacks/authelia-config/users_database.yml",
		AutheliaCtrDir:   "/config",
		DefaultPolicy:    "deny",
		DDNSIntervalMin:  5,
		CaddyStackDir:    "",
		CaddyService:     "caddy",
		AutheliaStackDir: "",
		AutheliaService:  "authelia",

		WafParanoia: 1,
		WafV2:       true, WafInbound: 5, WafOutbound: 4, WafMethods: "GET HEAD POST OPTIONS PUT PATCH DELETE",
		GuardBots: true, GuardPaths: true,
		CfGeoMode: "allow", CfThreatAction: "block", CfThreatBots: true, CfThreatPaths: true,
		CfCustomAction: "managed_challenge", CfRateRequests: 30, CfRatePeriod: 10, CfRateTimeout: 10, CfRateAction: "block",
		CfRatePaths:       "/login\n/api/login",
		CfAsnList:         "",
		CfAsnAction:       "managed_challenge",
		CrowdSecContainer: "crowdsec",
		CrowdSecLAPI:      "http://crowdsec:8080",
		CrowdSecInterval:  60,
		DashLogs:          true, // new installs; older data files keep false until turned on
		CaddyMode:         "docker",
		CaddyBin:          "caddy",
		CaddyAdmin:        "http://host.docker.internal:2019",

		LogInit: true, LogRequests: true, LogMetrics: true, LogKeepEventsOnStop: true,
		LogRetReqDays: 7, LogRetMetricDays: 90, LogRetAuditDays: 365, LogRetSecurityDays: 180, LogRetSystemDays: 30,
		LogMaxDBMB: 2048, DiskWarnPct: 20, DiskCritPct: 10, DiskStopPct: 5,
		SecInit: true, SecIdleMin: 30, SecAbsHours: 12, SecReauthMin: 10,
		SecAllowDirect: true, SecAllowProxy: true, SecRequireSSO: true, UpdateCheck: true,
		SecV2: true, SecRequire2FA: false,
	}
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.d.Settings = defaultSettings()
		migrateAccounts(&s.d)
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		return nil, err
	}
	// fill new defaults for older data files
	def := defaultSettings()
	st := &s.d.Settings
	if st.TailscalePort == 0 {
		st.TailscalePort = def.TailscalePort
	}
	if st.DefaultPolicy == "" {
		st.DefaultPolicy = def.DefaultPolicy
	}
	if len(st.TopoHops) == 0 && st.TopoEdgeKind != "" {
		kind := st.TopoEdgeKind
		if kind == "direct" {
			kind = "firewall"
		}
		st.TopoHops = []TopoHop{{Kind: kind, Name: st.TopoEdgeName, Note: st.TopoEdgeNote, ExtPort: st.TopoEdgeExtPort, FwdPort: st.TopoEdgeFwdPort, Tailnet: kind == "router" || kind == "firewall"}}
		st.TopoEdgeKind, st.TopoEdgeName, st.TopoEdgeNote, st.TopoEdgeExtPort, st.TopoEdgeFwdPort = "", "", "", 0, 0
	}
	if st.DDNSIntervalMin == 0 {
		st.DDNSIntervalMin = def.DDNSIntervalMin
	}
	if st.CaddyfileInCtr == "" {
		st.CaddyfileInCtr = def.CaddyfileInCtr
	}
	if st.AutheliaCtrDir == "" {
		st.AutheliaCtrDir = def.AutheliaCtrDir
	}
	if st.WafParanoia == 0 {
		st.WafParanoia = def.WafParanoia
	}
	if st.CfAsnAction == "" {
		st.CfAsnList, st.CfAsnAction = def.CfAsnList, def.CfAsnAction
	}
	if st.CrowdSecContainer == "" {
		st.CrowdSecContainer = def.CrowdSecContainer
	}
	if st.CrowdSecLAPI == "" {
		st.CrowdSecLAPI = def.CrowdSecLAPI
	}
	if !st.LogInit {
		st.LogInit, st.LogRequests, st.LogMetrics, st.LogKeepEventsOnStop = true, true, true, true
		st.LogRetReqDays, st.LogRetMetricDays, st.LogRetAuditDays, st.LogRetSecurityDays, st.LogRetSystemDays = 7, 90, 365, 180, 30
		st.LogMaxDBMB, st.DiskWarnPct, st.DiskCritPct, st.DiskStopPct = 2048, 20, 10, 5
	}
	if !st.SecInit {
		st.SecInit, st.SecIdleMin, st.SecAbsHours, st.SecReauthMin = true, 30, 12, 10
		st.SecAllowDirect, st.SecAllowProxy, st.SecRequireSSO, st.UpdateCheck = true, true, true, true
	}
	if st.CaddyMode == "" {
		st.CaddyMode = "docker"
	}
	if st.CrowdSecInterval == 0 {
		st.CrowdSecInterval = def.CrowdSecInterval
	}
	if !st.SecV2 {
		st.SecV2, st.SecRequire2FA = true, false
	}
	migrateAccounts(&s.d)
	if len(s.d.Services) > 0 {
		s.d.SetupDone = true // installs that already have sites never get the first-run prompt
	}
	if st.Lang == "" && (s.d.SetupDone || len(s.d.Services) > 0) {
		st.Lang = "ko" // installs from before the language choice keep the Korean UI
	}
	if !st.WafV2 {
		st.WafV2, st.WafInbound, st.WafOutbound, st.WafMethods = true, def.WafInbound, def.WafOutbound, def.WafMethods
		st.GuardBots, st.GuardPaths = def.GuardBots, def.GuardPaths
		st.WafExclude, st.WafDirectives = migrateRemoveByID(st.WafExclude, st.WafDirectives)
		st.CfGeoMode, st.CfThreatAction, st.CfThreatBots, st.CfThreatPaths = def.CfGeoMode, def.CfThreatAction, def.CfThreatBots, def.CfThreatPaths
		st.CfCustomAction, st.CfRateRequests, st.CfRatePeriod, st.CfRateTimeout, st.CfRateAction, st.CfRatePaths = def.CfCustomAction, def.CfRateRequests, def.CfRatePeriod, def.CfRateTimeout, def.CfRateAction, def.CfRatePaths
		if s.d.CFWAF.AsnRuleID != "" {
			s.d.CFWAF.AsnAdopted = true // earlier versions only adopted (never created) the ASN rule
		}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Snapshot returns a deep copy safe to use without the lock.
func (s *Store) Snapshot() Data {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.d)
	var c Data
	_ = json.Unmarshal(b, &c)
	return c
}

// Read runs fn under the lock without copying (fn must not keep references or modify d).
func (s *Store) Read(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.d)
}

func (s *Store) Update(fn func(d *Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// work on a deep copy: an error from fn (or from saving) must leave the live data as it was
	b, err := json.Marshal(s.d)
	if err != nil {
		return err
	}
	var c Data
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if err := fn(&c); err != nil {
		return err
	}
	old := s.d
	s.d = c
	if err := s.saveLocked(); err != nil {
		s.d = old
		return err
	}
	return nil
}

// markDirty records a pending (saved, not yet applied) change. Repeated edits of the
// same item collapse into one entry so the "N pending" counter stays meaningful.
func (d *Data) markDirty(msg string) {
	d.Dirty = true
	for _, p := range d.Pending {
		if p == msg {
			return
		}
	}
	if len(d.Pending) >= 100 {
		d.Pending = d.Pending[1:]
	}
	d.Pending = append(d.Pending, msg)
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sortServices(list []*Service) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Exposure != list[j].Exposure {
			return list[i].Exposure == ExposurePublic
		}
		return list[i].Subdomain < list[j].Subdomain
	})
}

func (st Settings) FQDN(sub string) string {
	sub = strings.TrimSpace(sub)
	if sub == "" || sub == "@" {
		return st.Domain
	}
	return sub + "." + st.Domain
}

// migrateRemoveByID moves plain "SecRuleRemoveById <id>" lines of the old free-text box into
// the exclusion list (shown and editable in the UI); other lines stay as advanced directives.
func migrateRemoveByID(ex []WafExclusion, directives string) ([]WafExclusion, string) {
	var keep []string
	for _, l := range strings.Split(directives, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "SecRuleRemoveById" && reWafRuleID.MatchString(f[1]) {
			ex = append(ex, WafExclusion{ID: f[1], Note: "예전 추가 규칙에서 옮김"})
			continue
		}
		if strings.TrimSpace(l) != "" {
			keep = append(keep, l)
		}
	}
	return ex, strings.Join(keep, "\n")
}
