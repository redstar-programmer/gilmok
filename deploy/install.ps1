# Gilmok installer / updater (Windows + Docker Desktop).
# ASCII only on purpose: Windows PowerShell 5 garbles non-ASCII in BOM-less .ps1 files.
#
#   powershell -ExecutionPolicy Bypass -File .\deploy\install.ps1 -Target D:\Docker\gilmok `
#       -CaddyDir D:\Docker\caddy -AutheliaDir D:\Docker\authelia -AutheliaConfigDir D:\Docker\authelia\config `
#       -CaddyContainer caddy -AutheliaContainer authelia -Network reverseproxy
#
# Options you pass are saved in <Target>\.env; a later run without them reuses the saved values
# (so updating Gilmok is just running the script again). Everything is an example, nothing assumes
# a particular server.
#
# What it does (safe to re-run):
#   1. creates <Target>\{data,secrets}
#   2. copies the compose file to <Target>; with -Build also the source (this repository) to <Target>\src
#   3. writes <Target>\secrets\cf_token from the running Caddy container (only if missing;
#      the token is never printed). Not found = enter it later in the web UI.
#   4. -CrowdSec: adds a CrowdSec container with a generated bouncer key;
#      remembered in <Target>\.env (COMPOSE_PROFILES=crowdsec), so later runs keep it
#   5. docker compose pull + up -d  (the published image vitive/gilmok; -Build builds from source,
#      remembered in .env as GM_BUILD=1 - -Build:$false goes back to the image)
# It never touches the Caddy / Authelia containers themselves.

param(
    [string]$Target = "",            # default: a "gilmok" folder next to this repository
    [string]$Container = "",         # Gilmok's container name (default gilmok)
    [string]$Port = "",              # host port on 127.0.0.1 (default 8088)
    [string]$Network = "",           # Docker network your Caddy is on (default reverseproxy)
    [string]$CaddyDir = "",          # folder with the Caddyfile (and Caddy's compose file)
    [string]$AutheliaDir = "",       # Authelia's compose folder
    [string]$AutheliaConfigDir = "", # folder with configuration.yml / users_database.yml
    [string]$CaddyContainer = "",
    [string]$AutheliaContainer = "",
    [string]$CrowdSecContainer = "",
    [string]$Domain = "",            # e.g. example.com (empty: set it in the web UI, or import the Caddyfile)
    [string]$TailscaleIP = "",       # e.g. 100.64.0.10
    [string]$TimeZone = "",          # e.g. Asia/Seoul (default UTC)
    [string]$Image = "",             # default vitive/gilmok:latest (e.g. vitive/gilmok:0.2.0 to pin)
    [string]$Lang = "",              # ko | en (empty: the first visit asks)
    [switch]$Build,                  # build from this repository instead of pulling the image
    [switch]$RenewToken,
    [switch]$CrowdSec
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$utf8 = New-Object System.Text.UTF8Encoding($false)
if ($Target -eq "") { $Target = Join-Path (Split-Path -Parent $repo) "gilmok" }
$Target = [System.IO.Path]::GetFullPath($Target)

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# --- .env: keys are updated in place (never the whole file)
$envFile = "$Target\.env"
function Get-EnvKey([string]$k) {
    if (-not (Test-Path $envFile)) { return "" }
    $l = [System.IO.File]::ReadAllLines($envFile, $utf8) | Where-Object { $_ -like "$k=*" } | Select-Object -Last 1
    if ($l) { return $l.Substring($k.Length + 1) }
    return ""
}
function Set-EnvKey([string]$k, [string]$v) {
    $lines = @()
    if (Test-Path $envFile) { $lines = @([System.IO.File]::ReadAllLines($envFile, $utf8) | Where-Object { $_ -notmatch ("^" + [regex]::Escape($k) + "=") }) }
    $lines += "$k=$v"
    [System.IO.File]::WriteAllText($envFile, (($lines -join "`n") + "`n"), $utf8)
}
# option given > value saved in .env > default; the result is saved again
function Resolve-Opt([string]$key, [string]$given, [string]$default) {
    $v = $given
    if ($v -eq "") { $v = Get-EnvKey $key }
    if ($v -eq "") { $v = $default }
    if ($v -ne "") { Set-EnvKey $key $v }
    return $v
}
if (-not (Test-Path $Target)) { New-Item -ItemType Directory -Path $Target | Out-Null }
$parent = Split-Path -Parent $Target
$Container         = Resolve-Opt "GM_CONTAINER" $Container "gilmok"
$Port              = Resolve-Opt "GM_PORT" $Port "8088"
$Network           = Resolve-Opt "GM_NETWORK" $Network "reverseproxy"
$CaddyDir          = Resolve-Opt "GM_CADDY_DIR" $CaddyDir "$parent\caddy"
$AutheliaDir       = Resolve-Opt "GM_AUTHELIA_DIR" $AutheliaDir "$parent\authelia"
$AutheliaConfigDir = Resolve-Opt "GM_AUTHELIA_CONFIG_DIR" $AutheliaConfigDir "$AutheliaDir\config"
$CaddyContainer    = Resolve-Opt "GM_CADDY_CONTAINER" $CaddyContainer "caddy"
$AutheliaContainer = Resolve-Opt "GM_AUTHELIA_CONTAINER" $AutheliaContainer "authelia"
$CrowdSecContainer = Resolve-Opt "GM_CROWDSEC_CONTAINER" $CrowdSecContainer "crowdsec"
$null              = Resolve-Opt "TZ" $TimeZone "UTC"
$null              = Resolve-Opt "GM_IMAGE" $Image "vitive/gilmok:latest"
if ($Lang -ne "") { Set-EnvKey "GM_LANG" $Lang }
if ($PSBoundParameters.ContainsKey("Build")) { Set-EnvKey "GM_BUILD" ($(if ($Build) { "1" } else { "0" })) }
$useBuild = (Get-EnvKey "GM_BUILD") -eq "1"
if ($Domain -ne "") { Set-EnvKey "GM_DOMAIN" $Domain }
if ($TailscaleIP -eq "" -and (Get-EnvKey "GM_TAILSCALE_IP") -eq "") {
    # Tailscale installed on this Windows host: the container cannot ask it, so read it here
    $tsExe = (Get-Command tailscale -ErrorAction SilentlyContinue).Source
    if (-not $tsExe -and (Test-Path "$env:ProgramFiles\Tailscale\tailscale.exe")) { $tsExe = "$env:ProgramFiles\Tailscale\tailscale.exe" }
    if ($tsExe) {
        $found = (& $tsExe ip -4 2>$null | Select-Object -First 1)
        if ($found -match '^100\.\d+\.\d+\.\d+$') { $TailscaleIP = $found; Write-Host "Tailscale IP of this host: $found" }
    }
}
if ($TailscaleIP -ne "") { Set-EnvKey "GM_TAILSCALE_IP" $TailscaleIP }

# --- preflight
docker version --format "{{.Server.Version}}" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker is not running" }
docker network inspect $Network --format "{{.Name}}" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker network '$Network' not found (-Network <name of the network your Caddy is on>)" }
foreach ($p in @("$CaddyDir\Caddyfile", "$AutheliaConfigDir\configuration.yml")) {
    if (-not (Test-Path $p)) { throw "Missing $p (check -CaddyDir / -AutheliaConfigDir)" }
}

# --- folders
Step "Folders in $Target"
foreach ($d in @($Target, "$Target\data", "$Target\secrets")) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}

# --- compose (+ source when building)
Copy-Item "$repo\deploy\docker-compose.yml" "$Target\docker-compose.yml" -Force
if ($useBuild) {
    Step "Copy source to $Target\src"
    if (-not (Test-Path "$Target\src")) { New-Item -ItemType Directory -Path "$Target\src" | Out-Null }
    Get-ChildItem "$Target\src" -Force | Remove-Item -Recurse -Force
    $items = @("go.mod", "go.sum", "Dockerfile", ".dockerignore", "web", "testdata")
    $items += (Get-ChildItem "$repo\*.go" | ForEach-Object { $_.Name })
    foreach ($i in $items) {
        if (Test-Path "$repo\$i") { Copy-Item "$repo\$i" "$Target\src\" -Recurse -Force }
    }
    Copy-Item "$repo\deploy\docker-compose.build.yml" "$Target\docker-compose.build.yml" -Force
}

# --- Cloudflare token (from the running Caddy container's environment)
$tokenFile = "$Target\secrets\cf_token"
if ($RenewToken -or -not (Test-Path $tokenFile) -or (Get-Item $tokenFile).Length -lt 20) {
    Step "Cloudflare token from $CaddyContainer (not printed)"
    $envs = @()
    try {
        $ErrorActionPreference = "Continue"
        $envs = docker inspect $CaddyContainer --format "{{range .Config.Env}}{{println .}}{{end}}" 2>$null
    } catch { $envs = @() } finally { $ErrorActionPreference = "Stop" }
    $line = $envs | Where-Object { $_ -like "CLOUDFLARE_API_TOKEN=*" } | Select-Object -First 1
    $token = ""
    if ($line) { $token = $line.Substring("CLOUDFLARE_API_TOKEN=".Length).Trim() }
    if ($token.Length -ge 20) {
        # no BOM, no newline
        [System.IO.File]::WriteAllText($tokenFile, $token, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "    saved $tokenFile"
    } else {
        # leave an empty file (a missing bind-mount source would become a directory);
        # the token can then be entered in the web UI: Cloudflare tab > API token
        if (-not (Test-Path $tokenFile)) { [System.IO.File]::WriteAllText($tokenFile, "", (New-Object System.Text.UTF8Encoding($false))) }
        Write-Host "    WARN: no usable CLOUDFLARE_API_TOKEN in $CaddyContainer - enter the token later in the web UI (Cloudflare tab)" -ForegroundColor Yellow
    }
    Remove-Variable token, line, envs -ErrorAction SilentlyContinue
} else {
    Write-Host "    keep existing $tokenFile (use -RenewToken to re-read)"
}

# --- files that are bind-mounted must exist (a missing file would be created as a directory)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$csKeyFile = "$Target\secrets\crowdsec_key"
if (-not (Test-Path $csKeyFile)) { [System.IO.File]::WriteAllText($csKeyFile, "", $utf8) }


# --- CrowdSec (optional; the choice is remembered in .env)
$csOn = $CrowdSec -or ((Test-Path $envFile) -and (Select-String -Path $envFile -Pattern '^COMPOSE_PROFILES=.*crowdsec' -Quiet))
if ($csOn) {
    Step "CrowdSec ($CrowdSecContainer)"
    foreach ($d in @("$Target\crowdsec", "$Target\crowdsec\config", "$Target\crowdsec\data")) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
    }
    $acq = [System.IO.File]::ReadAllText("$repo\deploy\crowdsec\acquis.yaml").Replace("  - caddy`n", "  - $CaddyContainer`n")
    [System.IO.File]::WriteAllText("$Target\crowdsec\acquis.yaml", $acq, $utf8)
    Copy-Item "$repo\deploy\crowdsec\gilmok-caddy-logs.yaml" "$Target\crowdsec\gilmok-caddy-logs.yaml" -Force
    if ((Get-Item $csKeyFile).Length -lt 32) {
        $b = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
        [System.IO.File]::WriteAllText($csKeyFile, (-join ($b | ForEach-Object { $_.ToString("x2") })), $utf8)
        Write-Host "    generated bouncer key (not printed)"
    }
    $key = [System.IO.File]::ReadAllText($csKeyFile).Trim()
    Set-EnvKey "COMPOSE_PROFILES" "crowdsec"
    Set-EnvKey "CROWDSEC_BOUNCER_KEY" $key
    Remove-Variable key
    Write-Host "    $envFile : COMPOSE_PROFILES=crowdsec"
}

# --- start (pull the image, or build from source)
Push-Location $Target
try {
    if ($useBuild) {
        Step "docker compose up -d --build (from source)"
        docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
    } else {
        Step "docker compose pull + up -d ($(Get-EnvKey 'GM_IMAGE'))"
        docker compose pull gilmok
        if ($LASTEXITCODE -ne 0) { throw "docker compose pull failed" }
        docker compose up -d
    }
    if ($LASTEXITCODE -ne 0) { throw "docker compose failed" }
} finally { Pop-Location }

Step "Waiting for health"
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    $h = docker inspect $Container --format "{{.State.Health.Status}}"
    if ($h -eq "healthy") { break }
}
Write-Host "    ${Container}: $h"
Write-Host ""
Write-Host "Open http://127.0.0.1:$Port on this computer (first login: admin / admin, then create your own account)." -ForegroundColor Green
Write-Host "See deploy\README.md."
