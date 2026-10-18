#!/usr/bin/bash
# Kali Linux installation and configuration script

#set -x # Uncomment this line to see debug statements, must also uncomment the "set +x" line at the bottom of the file in that case

### Color Codes ###
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color (reset)

### Initial Setup ###
# Exit on errors, enable for debugging
# set -euo pipefail

# Require root
echo "Checking for sudo access..."
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: must run with sudo." >&2
  exit 1
fi

# Find user's home directory
echo "Checking current user..."
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  TARGET_USER="$SUDO_USER"
else
  TARGET_USER="$USER"
fi

# Resolve target HOME
if command -v getent >/dev/null 2>&1; then
  TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
else
  # fallback for systems without getent
  TARGET_HOME="$(eval "echo ~${TARGET_USER}")"
fi

TARGET_GROUP="$(id -gn "$TARGET_USER")"
ZSHRC="$TARGET_HOME/.zshrc"
ALIASFILE="$TARGET_HOME/.aliases"
echo "User is $TARGET_USER, group is $TARGET_GROUP"
echo "Identified home directory as $TARGET_HOME"
echo "Setting aliases file location to $ALIASFILE"
echo "Setting zshrc file location to $ZSHRC"

# run_as script
run_as_target() {
  if [ "$(id -u)" -eq 0 ]; then
    sudo -u "$TARGET_USER" env \
      HOME="$TARGET_HOME" \
      XDG_CONFIG_HOME="$TARGET_HOME/.config" \
      XDG_DATA_HOME="$TARGET_HOME/.local/share" \
      /bin/sh -c "$*"
  else
    # Already the target user
    /bin/sh -c "$*"
  fi
}

### System Configuration ###

# Avoid interactive prompts during upgrade
export DEBIAN_FRONTEND=noninteractive

# Never let git block the whole script on a credential prompt. GitHub answers
# 404 for a repo that is missing OR private, and git then falls back to asking
# for a username and password - which hangs forever on an unattended run.
# With these set, a dead repo fails immediately and "|| true" moves us on.
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/bin/true
export GIT_CONFIG_PARAMETERS="'credential.helper='"

# Enable running all commands as root without sudo password
echo "Enabling passwordless sudo..."
echo "Enabling NOPASSWD sudo for user: $TARGET_USER"
echo -e "$TARGET_USER ALL=(ALL:ALL) NOPASSWD: ALL\nDefaults:$TARGET_USER verifypw=any\n" | sudo tee "/etc/sudoers.d/dont-prompt-$TARGET_USER-for-sudo-password"
# tee leaves the file 0644; sudo wants 0440 for files in sudoers.d and
# "visudo -c" exits non-zero until it is. Passwordless sudo works either way,
# but a sudoers tree that fails its own syntax check is not worth shipping.
chmod 0440 "/etc/sudoers.d/dont-prompt-$TARGET_USER-for-sudo-password"
if ! visudo -c; then
  echo "Error: sudoers validation failed; stopping setup." >&2
  exit 1
fi

### rockyou.txt ###
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "Unzipping rockyou.txt..."
    gunzip /usr/share/wordlists/rockyou.txt.gz
else
    echo "rockyou.txt already exists, skipping..."
fi

### Software ####

# Update the system
echo "Updating the system..."
apt-get update
apt-get -y upgrade

# Install Docker
echo "Installing Docker..."
apt-get -y install ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  trixie stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker $TARGET_USER

# Install Atuin
echo "Installing Atuin..."

ATUIN_VERSION="${ATUIN_VERSION:-}"
if [ -n "$ATUIN_VERSION" ]; then
  ATUIN_INSTALL_URL="https://github.com/atuinsh/atuin/releases/download/v${ATUIN_VERSION}/atuin-installer.sh"
else
  ATUIN_INSTALL_URL="https://github.com/atuinsh/atuin/releases/latest/download/atuin-installer.sh"
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }
need curl
need sed

echo "Installing Atuin for user: $TARGET_USER (HOME=$TARGET_HOME)"

# --- Install the binary as the target user ---
run_as_target "curl --proto '=https' --tlsv1.2 -LsSf '$ATUIN_INSTALL_URL' | sh"


echo "Installed Atuin, must open a new shell to see changes..."

# Install Rust
echo "Installing Rust..."
run_as_target "curl https://sh.rustup.rs -sSf | sh -s -- -y"

# Install ripgrep
echo "Installing ripgrep..."
apt-get -y install ripgrep

# Install dconf-cli, don't remove this or things will break
echo "Installing dconf-cli..."
apt-get -y install dconf-cli

# Install python3-argcomplete
echo "Installing python3-argcomplete..."
apt-get -y install python3-argcomplete

# Install python3-prompt-toolkit (hard import in evil_winrmexec.py)
echo "Installing python3-prompt-toolkit..."
apt-get -y install python3-prompt-toolkit

# Install the SMTP test client used by the phishing rehearsal tooling.
# Python 3 is already required elsewhere in this setup, but listing it here
# makes this block self-contained on a minimal Kali image.
echo "Installing phishing rehearsal prerequisites..."
apt-get -y install python3 swaks openssl ca-certificates

# Install micro
echo "Installing micro..."
apt-get -y install micro

# Install ntpdate
echo "Installing ntpdate..."
apt-get -y install ntpsec-ntpdate

# Install rdate
echo "Installing rdate..."
apt-get -y install rdate

# Install mitm6
echo "Installing mitm6..."
apt-get -y install mitm6

# Install bloodyad
echo "Installing bloodyad..."
apt-get -y install bloodyad

# Install certipy
echo "Installing certipy..."
apt-get -y install certipy-ad

# Install bloodhound-ce-python (Linux-side BloodHound CE collector)
echo "Installing bloodhound-ce-python..."
apt-get -y install bloodhound-ce-python

# Install ligolo-ng (provides ligolo-proxy, plus a local-arch ligolo-agent)
echo "Installing ligolo-ng..."
apt-get -y install ligolo-ng

# Install chisel
echo "Installing chisel..."
apt-get -y install chisel

# ligolo-proxy has no flag to create its tun interface, so create one owned by the
# operator now and persist it across reboots with a oneshot systemd unit.
echo "Creating ligolo tun interface..."
ip link show ligolo >/dev/null 2>&1 || ip tuntap add user "$TARGET_USER" mode tun ligolo
ip link set ligolo up

cat > /etc/systemd/system/ligolo-tun.service <<EOF
[Unit]
Description=Create the ligolo-ng tun interface
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip link show ligolo >/dev/null 2>&1 || ip tuntap add user $TARGET_USER mode tun ligolo'
ExecStart=/bin/sh -c 'ip link set ligolo up'
ExecStop=/bin/sh -c 'ip link del ligolo || true'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable ligolo-tun.service

# Install Sickle
echo "Installing Sickle..."
git clone https://github.com/wetw0rk/Sickle.git /opt/sickle || true

# Install penelope
echo "Installing penelope..."
apt-get -y install penelope

# Install Nuclei
echo "Installing Nuclei..."
apt-get -y install nuclei

# Install feroxbuster
echo "Installing feroxbuster..."
apt-get -y install feroxbuster

# Install ffuf
echo "Installing ffuf..."
apt-get -y install ffuf

# Install WPScan
echo "Installing WPScan..."
apt-get -y install wpscan

# Install jq (needed for the Firefox policy merge further down)
echo "Installing jq..."
apt-get -y install jq

# WPScan API token.
# The token itself CANNOT be generated automatically - it requires registering
# an account at https://wpscan.com/register with email verification, and the
# free tier is 25 API requests/day. Without a token wpscan still works, it just
# returns no vulnerability data.
# What is automated: the config file is created in the right place with the
# right ownership and permissions, so the token is only ever pasted once.
#   at build time:  sudo WPSCAN_API_TOKEN=xxxxx bash setupscript_v0.4.sh
#   afterwards:     wpscan-token <TOKEN>
echo "Configuring WPScan API token..."
mkdir -p "$TARGET_HOME/.wpscan"
if [ -n "${WPSCAN_API_TOKEN:-}" ]; then
  printf 'cli_options:\n  api_token: %s\n' "$WPSCAN_API_TOKEN" > "$TARGET_HOME/.wpscan/scan.yml"
  echo "WPScan API token written to $TARGET_HOME/.wpscan/scan.yml"
elif grep -q '^cli_options:' "$TARGET_HOME/.wpscan/scan.yml" 2>/dev/null; then
  echo "WPScan token already configured, leaving $TARGET_HOME/.wpscan/scan.yml alone"
else
  cat > "$TARGET_HOME/.wpscan/scan.yml" <<'WPSCANEOF'
# No WPScan API token configured yet.
# Register (free, 25 requests/day) at https://wpscan.com/register, then run:
#   wpscan-token <YOUR_TOKEN>
# or uncomment the two lines below and paste it in.
#cli_options:
#  api_token: YOUR_TOKEN_HERE
WPSCANEOF
  echo "No WPSCAN_API_TOKEN in the environment - wrote a placeholder."
  echo "Run 'wpscan-token <TOKEN>' once you have one."
fi
chmod 700 "$TARGET_HOME/.wpscan"
chmod 600 "$TARGET_HOME/.wpscan/scan.yml"
chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.wpscan"

# Helper so the token can be set later without hand-editing YAML
cat > /usr/local/bin/wpscan-token <<'WPSCANTOKENEOF'
#!/bin/sh
# Store a WPScan API token for the current user (~/.wpscan/scan.yml).
set -eu
if [ $# -ne 1 ] || [ -z "$1" ]; then
  echo "usage: wpscan-token <API_TOKEN>" >&2
  echo "register free (25 requests/day) at https://wpscan.com/register" >&2
  exit 1
fi
mkdir -p "$HOME/.wpscan"
printf 'cli_options:\n  api_token: %s\n' "$1" > "$HOME/.wpscan/scan.yml"
chmod 700 "$HOME/.wpscan"
chmod 600 "$HOME/.wpscan/scan.yml"
echo "Token saved to $HOME/.wpscan/scan.yml"
echo "Verify with: wpscan --url <target> (no --api-token needed)"
WPSCANTOKENEOF
chmod +x /usr/local/bin/wpscan-token

# Install LibreOffice
echo "Installing LibreOffice..."
apt-get -y install libreoffice

# Install Remmina
echo "Installing Remmina..."
apt-get -y install remmina

# Install enum4linux-ng
echo "Installing enum4linux-ng..."
apt-get -y install enum4linux-ng

# Install keepass2
echo "Installing keepass2..."
apt-get -y install keepass2

# Terminal emulator
echo "Installing Tilix..."
apt-get -y install tilix

# Tilix settings
echo "Updating Tilix settings..."

ln -sf /etc/profile.d/vte-2.91.sh /etc/profile.d/vte.sh

dconf update

TILIX_PROFILE=$(run_as_target 'gsettings get com.gexperts.Tilix.ProfilesList default' 2>/dev/null | tr -d "'")
TILIX_PROFILE_PATH="com.gexperts.Tilix.Profile:/com/gexperts/Tilix/profiles/$TILIX_PROFILE/"

run_as_target "gsettings set $TILIX_PROFILE_PATH login-shell true"
run_as_target "gsettings set $TILIX_PROFILE_PATH scrollback-unlimited true"
run_as_target "gsettings set $TILIX_PROFILE_PATH background-transparency-percent 0"

run_as_target "gsettings set com.gexperts.Tilix.Settings use-tabs true"
run_as_target "gsettings set com.gexperts.Tilix.Settings window-save-state true"
run_as_target "gsettings set com.gexperts.Tilix.Settings unsafe-paste-alert false"

# Install Sliver
echo "Installing Sliver..."
curl https://sliver.sh/install | bash
systemctl enable sliver

# Install VSCode
echo "Installing VSCode..."
rm -f -- /tmp/vscode.deb && wget https://update.code.visualstudio.com/latest/linux-deb-x64/stable -O /tmp/vscode.deb && apt-get install -y /tmp/vscode.deb && rm -f -- /tmp/vscode.deb

# Configure Bloodhound
echo "Putting bloodhound-ce docker-compose.yml file in /opt/bloodhound/..."

mkdir -p -- /opt/bloodhound-ce
cd /opt/bloodhound-ce
cat > docker-compose.yml <<'EOF'
# BloodHound-CE Compose - Postgres

services:
  app-db:
    image: docker.io/library/postgres:16
    environment:
      - PGUSER=${POSTGRES_USER:-bloodhound}
      - POSTGRES_USER=${POSTGRES_USER:-bloodhound}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-bloodhoundcommunityedition}
      - POSTGRES_DB=${POSTGRES_DB:-bloodhound}
    # ports:
    #   - 127.0.0.1:${POSTGRES_PORT:-5432}:5432
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-bloodhound} -d ${POSTGRES_DB:-bloodhound} -h 127.0.0.1 -p 5432"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    restart: always

  bloodhound:
    image: docker.io/specterops/bloodhound:${BLOODHOUND_TAG:-latest}
    environment:
      # Use PostgreSQL as the graph backend
      - bhe_graph_driver=${GRAPH_DRIVER:-pg}
      # App DB connection (PostgreSQL)
      - bhe_database_connection=user=${POSTGRES_USER:-bloodhound} password=${POSTGRES_PASSWORD:-bloodhoundcommunityedition} dbname=${POSTGRES_DB:-bloodhound} host=app-db
      - bhe_disable_cypher_complexity_limit=${bhe_disable_cypher_complexity_limit:-false}
      - bhe_enable_cypher_mutations=${bhe_enable_cypher_mutations:-false}
      - bhe_graph_query_memory_limit=${bhe_graph_query_memory_limit:-2}
      - bhe_recreate_default_admin=${bhe_recreate_default_admin:-false}
      - bhe_default_admin_password=${BHE_DEFAULT_ADMIN_PASSWORD:-Bloodhound123!}
      - bhe_default_admin_email_address=${BHE_DEFAULT_ADMIN_EMAIL:-admin}
      - bhe_default_admin_first_name=${BHE_DEFAULT_ADMIN_FIRST:-BloodHound}
      - bhe_default_admin_last_name=${BHE_DEFAULT_ADMIN_LAST:-Admin}
      - bhe_default_admin_expire_now=${BHE_DEFAULT_ADMIN_EXPIRE_NOW:-false}

    ports:
      # Expose bloodhound on port 7070
      - 7070:8080
    depends_on:
      app-db:
        condition: service_healthy
    restart: always

volumes:
  postgres-data:
EOF

# Install SNMP MIBS
echo "Installing SNMP MIBS..."
apt-get install -y snmp-mibs-downloader
download-mibs
sed -i 's/^mibs :/# mibs :/' /etc/snmp/snmp.conf

### Firefox extensions ###
# Wappalyzer is installed through Firefox's enterprise policy (ExtensionSettings).
# Dropping an XPI into the profile's extensions/ directory has not worked since
# Firefox 74 (sideloading was removed), so a policy is the only supported
# unattended route.
#
# NOTE: there is NO WhatWeb browser extension - WhatWeb is a CLI tool and already
# ships with Kali at /usr/bin/whatweb. Nothing to install in Firefox for it.
#
# This build has MOZ_SYSTEM_POLICIES=true, which means Firefox checks
# /etc/firefox-esr/policies/policies.json FIRST and returns immediately if it
# exists - completely ignoring /usr/lib/firefox-esr/distribution/policies.json.
# Kali ships its own policy file in that distribution directory (homepage,
# telemetry, bookmarks), so we MERGE it into ours instead of writing a bare
# file, otherwise those defaults would be silently dropped.
printf "\n ${PURPLE}-_-_-_-_- Installing Firefox extensions -_-_-_-_- ${NC}\n\n"

# Cache the XPI locally so first launch does not need to reach AMO.
# /usr/local/share keeps it out of the /opt chown at the end of this script.
FF_EXT_DIR=/usr/local/share/firefox-extensions
FF_XPI="$FF_EXT_DIR/wappalyzer.xpi"
mkdir -p "$FF_EXT_DIR"
# Stage to a temp file. "wget -O <final>" truncates the destination before it
# can fail, so a transient network error on a re-run would silently destroy a
# working ~35 MB extension while the policy kept pointing at the empty file.
# Validate size and that it is a real zip before replacing the cached copy.
FF_XPI_TMP="$(mktemp)"
if wget -q "https://addons.mozilla.org/firefox/downloads/latest/wappalyzer/latest.xpi" \
        -O "$FF_XPI_TMP" \
   && [ -s "$FF_XPI_TMP" ] \
   && [ "$(stat -c %s "$FF_XPI_TMP")" -gt 1000000 ] \
   && unzip -p "$FF_XPI_TMP" manifest.json >/dev/null 2>&1; then
  mv -f "$FF_XPI_TMP" "$FF_XPI"
  chmod 644 "$FF_XPI"
  echo "Wappalyzer XPI cached ($(stat -c %s "$FF_XPI") bytes)"
else
  rm -f "$FF_XPI_TMP"
  if [ -s "$FF_XPI" ]; then
    echo "WARNING: XPI download failed - KEEPING the existing cached copy"
  else
    echo "WARNING: XPI download failed and there is no cached copy;"
    echo "WARNING: Wappalyzer will not install. Re-run this block when online."
  fi
fi

# WHERE the policy has to go, learned the hard way on the first VM build.
# Firefox checks SysConfD/policies/policies.json first and only falls through
# to <installdir>/distribution/policies.json if that file does not EXIST. On
# this image /etc/firefox does not exist at all and /etc/firefox-esr is not the
# SysConfD Firefox looks in, so a policy written only under /etc was silently
# ignored - about:policies showed Kali's defaults and no ExtensionSettings.
# The distribution file is the one Firefox demonstrably reads here, so write
# all three with IDENTICAL merged content. Whichever path a given image
# prefers, it gets the same result and precedence stops mattering.
FF_DIST_POLICY=/usr/lib/firefox-esr/distribution/policies.json
FF_POLICY_PATHS="$FF_DIST_POLICY /etc/firefox/policies/policies.json /etc/firefox-esr/policies/policies.json"

# Start from a policy that already carries our entry if one exists (keeps
# re-runs idempotent), else from Kali's shipped defaults.
FF_BASE="$FF_DIST_POLICY"
for c in $FF_POLICY_PATHS; do
  if [ -s "$c" ] && jq -e '.policies.ExtensionSettings' "$c" >/dev/null 2>&1; then
    FF_BASE="$c"; break
  fi
done

if [ -s "$FF_XPI" ]; then
  chmod 644 "$FF_XPI"
  # installation_mode normal_installed = installed automatically, but the user
  # can still disable it (useful: it hooks webRequest on every host, which is
  # noise you may not want while proxying through Burp).
  FF_MERGED=$(mktemp)
  if { [ -s "$FF_BASE" ] && cat "$FF_BASE" || echo '{}'; } | jq -S \
        --arg xpi "file://$FF_XPI" '
          .policies //= {}
          | .policies.ExtensionSettings //= {}
          | .policies.ExtensionSettings["wappalyzer@crunchlabz.com"] = {
              installation_mode: "normal_installed",
              install_url: $xpi,
              default_area: "navbar"
            }' > "$FF_MERGED" 2>/dev/null && [ -s "$FF_MERGED" ]; then
    for dest in $FF_POLICY_PATHS; do
      mkdir -p "$(dirname "$dest")"
      cp -f "$FF_MERGED" "$dest"
      chmod 644 "$dest"
      echo "Firefox policy written to $dest"
    done
    echo "Wappalyzer installs itself on the next Firefox launch."
    echo "Confirm with about:policies - ExtensionSettings must appear under Active."
  else
    echo "WARNING: failed to build the Firefox policy, left the existing ones alone"
  fi
  rm -f "$FF_MERGED"
else
  echo "WARNING: no Wappalyzer XPI on disk, skipping the Firefox policy"
fi
printf "\n ${GREEN}-_-_-_-_- Finished installing Firefox extensions -_-_-_-_- ${NC}\n\n"

### Configure ~/.aliases ###
echo 'Configuring aliases...'
echo "Writing to $ALIASFILE"
if ! grep -q "# MODIFIED BY AUTOMATIC INSTALLATION SCRIPT" "$ALIASFILE" 2>/dev/null; then
cat >> "$ALIASFILE" <<'EOF'
# MODIFIED BY AUTOMATIC INSTALLATION SCRIPT
alias c='code'
alias s='source ~/.zshrc'
alias hosts='sudo micro /etc/hosts'
alias aliases='micro ~/.aliases'
alias resolv='sudo micro /etc/resolv.conf'
alias zshrc='micro ~/.zshrc'
alias venv='python3 -m venv ./venv && source ./venv/bin/activate'
alias bloodyad='bloodyAD'
alias certipy='certipy-ad'
list_ips() {
  ip a show scope global | awk '/^[0-9]+:/ { sub(/:/,"",$2); iface=$2 } /^[[:space:]]*inet / { split($2, a, "/"); print "[\033[96m" iface"\033[0m] "a[1] }'
}

ls_pwd() {
  echo -e "[\e[96m`pwd`\e[0m]\e[34m" && ls && echo -en "\e[0m"
}

alias www="list_ips && ls_pwd && sudo python3 -m http.server 80"
EOF
fi
echo "Wrote aliases to $ALIASFILE"

if [[ $EUID -eq 0 ]]; then
  chown "$TARGET_USER":"$TARGET_GROUP" "$ALIASFILE"
fi

### Configure ~/.zshrc ###
echo 'Configuring ~/.zshrc'
if ! grep -q "# MODIFIED BY AUTOMATIC INSTALLATION SCRIPT" "$ZSHRC" 2>/dev/null; then
  cat >> "$ZSHRC" <<'EOF'
# MODIFIED BY AUTOMATIC INSTALLATION SCRIPT
# START Logging
# Only start when interactive and not already under "script"
if [[ -o interactive ]]; then
  parent_cmd=$(ps -o comm= -p "$PPID")
  if [[ "$parent_cmd" != "script" ]]; then
    mkdir -p "$HOME/.history_logs"
    script "$HOME/.history_logs/$(date +'%d-%b-%y_%H-%M-%S')_history.log"
  fi
fi
# END Logging
# Add the .aliases file, if it exists
if [[ -f "$HOME/.aliases" ]]; then
  source "$HOME/.aliases"
fi
[ -f "$HOME/.atuin/bin/env" ] && . "$HOME/.atuin/bin/env"
command -v atuin >/dev/null 2>&1 && eval "$(atuin init zsh)"
if [ $TILIX_ID ] || [ $VTE_VERSION ]; then
        source /etc/profile.d/vte.sh
fi
EOF
  echo "Wrote changes to $ZSHRC"
else
  echo "Skipping: $ZSHRC already contains the modifications"
fi

# Same treatment as $ALIASFILE: if ~/.zshrc did not exist, the heredoc above
# just created it as root, and every later append that runs as the target user
# would fail silently.
if [[ $EUID -eq 0 ]]; then
  chown "$TARGET_USER":"$TARGET_GROUP" "$ZSHRC"
fi

# Enable NXC autocompletion
echo "Enabling autocompletion for nxc..."
if ! grep -q "# NXC ARGCOMPLETE" "$ZSHRC" 2>/dev/null; then
  if run_as_target 'command -v register-python-argcomplete >/dev/null 2>&1'; then
    # marker and content together, so a failure leaves the block retryable
    echo "# NXC ARGCOMPLETE" >> "$ZSHRC"
    run_as_target 'register-python-argcomplete nxc >> "$HOME/.zshrc"' \
      || echo "WARNING: nxc completion generation failed - block left unmarked"
  else
    echo "WARNING: register-python-argcomplete not found; skipping nxc completion"
  fi
fi

### Put cargo on the PATH for zsh ###
# rustup writes its PATH line to ~/.profile and ~/.bashrc only, so "cargo" does
# not resolve in a zsh login shell. Guarded by its own marker rather than the
# main block's, so it still applies to a machine built before this was added.
echo "Adding cargo to the zsh PATH..."
if ! grep -q "# CARGO PATH" "$ZSHRC" 2>/dev/null; then
  cat >> "$ZSHRC" <<'EOF'
# CARGO PATH
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
EOF
fi

########### --- SCRIPTS FROM BRADY --- ############

echo "Cloning tools to /opt/"

# Clone krbrelayx
printf "\n ${PURPLE}-_-_-_-_- Cloning krbrelayx -_-_-_-_- ${NC}\n\n"
git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning krbrelayx -_-_-_-_- ${NC}\n\n"

# Clone PKINITtools
printf "\n ${PURPLE}-_-_-_-_- Cloning PKINITtools -_-_-_-_- ${NC}\n\n"
git clone https://github.com/dirkjanm/PKINITtools.git /opt/PKINITtools || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning PKINITtools -_-_-_-_- ${NC}\n\n"

# Clone PetitPotam
printf "\n ${PURPLE}-_-_-_-_- Cloning PetitPotam -_-_-_-_- ${NC}\n\n"
git clone https://github.com/topotam/PetitPotam.git /opt/petitpotam || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning PetitPotam -_-_-_-_- ${NC}\n\n"

# Clone pywhisker
printf "\n ${PURPLE}-_-_-_-_- Cloning pywhisker -_-_-_-_- ${NC}\n\n"
git clone https://github.com/ShutdownRepo/pywhisker.git /opt/pywhisker || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning pywhisker -_-_-_-_- ${NC}\n\n"

# Clone sccmhunter
printf "\n ${PURPLE}-_-_-_-_- Cloning sccmhunter -_-_-_-_- ${NC}\n\n"
git clone https://github.com/garrettfoster13/sccmhunter.git /opt/sccmhunter || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning sccmhunter -_-_-_-_- ${NC}\n\n"

# Impacket (SCCM Relay) - REMOVED in 1.1.
# github.com/garrettfoster13/impacket is deleted (404 as of 2026-10-16), and
# because GitHub 404s private and missing repos alike, git used to stop here and
# prompt for a username, hanging the entire unattended run.
# Upstream fortra/impacket has no SCCM adminservice relay attack, so there is no
# drop-in replacement. /opt/sccmhunter still covers SCCM recon and the
# adminservice paths; Mayyhem/SharpSCCM (official compiled release) is the
# Windows-side option if you want relay/takeover tooling staged.

# Clone winrmexec
printf "\n ${PURPLE}-_-_-_-_- Cloning winrmexec -_-_-_-_- ${NC}\n\n"
git clone https://github.com/ozelis/winrmexec.git /opt/winrmexec || true
# Neither script ships a shebang, so a bare symlink would not be executable.
# Add one (idempotently), mark executable, then symlink both into PATH.
for wrm in winrmexec evil_winrmexec; do
  if [ -f "/opt/winrmexec/$wrm.py" ]; then
    head -1 "/opt/winrmexec/$wrm.py" | grep -q '^#!' || \
      sed -i '1i #!/usr/bin/env python3' "/opt/winrmexec/$wrm.py"
    chmod +x "/opt/winrmexec/$wrm.py"
    ln -sf "/opt/winrmexec/$wrm.py" "/usr/local/bin/$wrm"
  fi
done
printf "\n ${GREEN}-_-_-_-_- Finished cloning winrmexec -_-_-_-_- ${NC}\n\n"

# Set up linPEAS and winPEAS directories
printf "\n ${YELLOW}-_-_-_-_- Setting up linPEAS & winPEAS directories... -_-_-_-_- ${NC}\n\n"
mkdir -p /opt/staging
cd /opt/staging
mkdir -p /opt/staging/windows /opt/staging/linux
mkdir -p /opt/staging/windows/winpeas /opt/staging/linux/linpeas
peas_version=$(curl -fsSL https://api.github.com/repos/peass-ng/PEASS-ng/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')

peas_link="https://github.com/peass-ng/PEASS-ng/releases/download/"$peas_version

printf "\n ${CYAN}-_-_-_-_- Pulling down linPEAS files... -_-_-_-_- ${NC}\n\n"

linpeas_scripts=("linpeas.sh" "linpeas_darwin_amd64" "linpeas_darwin_arm64" "linpeas_fat.sh" "linpeas_linux_386" "linpeas_linux_amd64" "linpeas_linux_arm")
for linpeas_file in ${linpeas_scripts[@]}; do
	wget $peas_link/$linpeas_file -O /opt/staging/linux/linpeas/$linpeas_file
	chmod +x /opt/staging/linux/linpeas/$linpeas_file 
done

printf "\n ${CYAN}-_-_-_-_- Pulling down winPEAS files... -_-_-_-_- ${NC}\n\n"

winpeas_scripts=('winPEAS.bat' 'winPEASany.exe' 'winPEASany_ofs.exe' 'winPEASx64_ofs.exe' 'winPEASx86.exe' 'winPEASx86_ofs.exe')
for winpeas_file in ${winpeas_scripts[@]}; do
	wget $peas_link/$winpeas_file -O /opt/staging/windows/winpeas/$winpeas_file
	chmod +x /opt/staging/windows/winpeas/$winpeas_file 
done

printf "\n ${GREEN}-_-_-_-_- Finished harvesting the PEAS! -_-_-_-_- ${NC}\n\n"

# Set up Linux tools directory
printf "\n ${PURPLE}-_-_-_-_- Setting up Linux tools directory... -_-_-_-_- ${NC}\n\n"

# pspy
pspy_version=$(curl -fsSL https://api.github.com/repos/DominicBreuker/pspy/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
pspy_link="https://github.com/DominicBreuker/pspy/releases/download/"$pspy_version
pspy_scripts=("pspy32" "pspy32s" "pspy64" "pspy64s")
for pspy_file in ${pspy_scripts[@]}; do
	wget $pspy_link/$pspy_file -O /opt/staging/linux/$pspy_file
	chmod +x /opt/staging/linux/$pspy_file 
done

# CDK
mkdir -p /opt/staging/linux/cdk/
cdk_version=$(curl -fsSL https://api.github.com/repos/cdk-team/CDK/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
cdk_link="https://github.com/cdk-team/CDK/releases/download/"$cdk_version
cdk_scripts=("cdk_darwin_amd64" "cdk_linux_386" "cdk_linux_amd64" "cdk_linux_amd64_upx" "cdk_linux_arm" "cdk_linux_arm64")
for cdk_file in ${cdk_scripts[@]}; do
	wget $cdk_link/$cdk_file -O /opt/staging/linux/cdk/$cdk_file
	chmod +x /opt/staging/linux/cdk/$cdk_file 
done

# Polkit
wget https://raw.githubusercontent.com/carlosevieira/polkit/main/pwn -O /opt/staging/linux/polkit_binary

wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh -O /opt/staging/linux/PolKit_PwnKit.sh

printf "\n ${GREEN}-_-_-_-_- Finished setting up the Linux tools directory -_-_-_-_- ${NC}\n\n"

# Stage ligolo-ng agents for targets (the apt ligolo-agent is local-arch only)
printf "\n ${CYAN}-_-_-_-_- Pulling down ligolo-ng agents... -_-_-_-_- ${NC}\n\n"
mkdir -p /opt/staging/windows/ligolo /opt/staging/linux/ligolo
ligolo_version=$(curl -fsSL https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
ligolo_bare=${ligolo_version#v}
ligolo_base="https://github.com/nicocha30/ligolo-ng/releases/download/"$ligolo_version

# Both archives contain a bare "agent"/"agent.exe", so rename per-arch to avoid collisions
wget "$ligolo_base/ligolo-ng_agent_"$ligolo_bare"_windows_amd64.zip" -O /tmp/ligolo_win_amd64.zip
unzip -o -j /tmp/ligolo_win_amd64.zip agent.exe -d /opt/staging/windows/ligolo
mv -f /opt/staging/windows/ligolo/agent.exe /opt/staging/windows/ligolo/ligolo-agent_windows_amd64.exe
rm -f /tmp/ligolo_win_amd64.zip

for ligolo_arch in amd64 arm64; do
	wget "$ligolo_base/ligolo-ng_agent_"$ligolo_bare"_linux_"$ligolo_arch".tar.gz" -O /tmp/ligolo_linux_$ligolo_arch.tar.gz
	tar -xzf /tmp/ligolo_linux_$ligolo_arch.tar.gz -C /opt/staging/linux/ligolo agent
	mv -f /opt/staging/linux/ligolo/agent /opt/staging/linux/ligolo/ligolo-agent_linux_$ligolo_arch
	chmod +x /opt/staging/linux/ligolo/ligolo-agent_linux_$ligolo_arch
	rm -f /tmp/ligolo_linux_$ligolo_arch.tar.gz
done

# Stage chisel binaries for targets (the apt chisel is local-arch only)
printf "\n ${CYAN}-_-_-_-_- Pulling down chisel binaries... -_-_-_-_- ${NC}\n\n"
mkdir -p /opt/staging/windows/chisel /opt/staging/linux/chisel
chisel_version=$(curl -fsSL https://api.github.com/repos/jpillora/chisel/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
chisel_bare=${chisel_version#v}
chisel_base="https://github.com/jpillora/chisel/releases/download/"$chisel_version

# Linux assets are gzipped bare binaries; the Windows asset is a zip holding "chisel.exe"
for chisel_arch in amd64 arm64; do
	wget "$chisel_base/chisel_"$chisel_bare"_linux_"$chisel_arch".gz" -O /tmp/chisel_linux_$chisel_arch.gz
	gunzip -c /tmp/chisel_linux_$chisel_arch.gz > /opt/staging/linux/chisel/chisel_linux_$chisel_arch
	chmod +x /opt/staging/linux/chisel/chisel_linux_$chisel_arch
	rm -f /tmp/chisel_linux_$chisel_arch.gz
done

wget "$chisel_base/chisel_"$chisel_bare"_windows_amd64.zip" -O /tmp/chisel_win_amd64.zip
unzip -o -j /tmp/chisel_win_amd64.zip chisel.exe -d /opt/staging/windows/chisel
mv -f /opt/staging/windows/chisel/chisel.exe /opt/staging/windows/chisel/chisel_windows_amd64.exe
rm -f /tmp/chisel_win_amd64.zip

# Install kerbrute (operator-side). Upstream's last release is v1.0.3 from Dec 2019.
printf "\n ${CYAN}-_-_-_-_- Pulling down kerbrute... -_-_-_-_- ${NC}\n\n"
kerbrute_version=$(curl -fsSL https://api.github.com/repos/ropnop/kerbrute/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
wget "https://github.com/ropnop/kerbrute/releases/download/"$kerbrute_version"/kerbrute_linux_amd64" -O /usr/local/bin/kerbrute
chmod +x /usr/local/bin/kerbrute

# Set up Windows tools directory
printf "\n ${PURPLE}-_-_-_-_- Setting up Windows tools directory... -_-_-_-_- ${NC}\n\n"

printf "\n ${CYAN}-_-_-_-_- Pulling down Ghostpack compiled binaries... -_-_-_-_- ${NC}\n\n"

# Get Ghostpack Binaries
ghostpack_files=("SharpUp.exe" "Certify.exe" "Rubeus.exe" "Seatbelt.exe")
for ghostpack_binary in ${ghostpack_files[@]}; do
	wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/$ghostpack_binary -O /opt/staging/windows/$ghostpack_binary
	chmod +x /opt/staging/windows/$ghostpack_binary 
done

# Get RunasCs
printf "\n ${CYAN}-_-_-_-_- Pulling down RunasCs... -_-_-_-_- ${NC}\n\n"

runascs_version=$(curl -fsSL https://api.github.com/repos/antonioCoco/RunasCs/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
wget "https://github.com/antonioCoco/RunasCs/releases/download/"$runascs_version"/RunasCs.zip" -O /opt/staging/windows/RunasCs.zip
cd /opt/staging/windows
unzip -o /opt/staging/windows/RunasCs.zip
chmod +x /opt/staging/windows/RunasCs.exe  
chmod +x /opt/staging/windows/RunasCs_net2.exe
rm /opt/staging/windows/RunasCs.zip
wget https://raw.githubusercontent.com/antonioCoco/RunasCs/master/Invoke-RunasCs.ps1 -O /opt/staging/windows/Invoke-RunasCs.ps1

# Get SharpHound CE
printf "\n ${CYAN}-_-_-_-_- Pulling down SharpHound CE... -_-_-_-_- ${NC}\n\n"

sharphound_version=$(curl -fsSL https://api.github.com/repos/SpecterOps/SharpHound/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
mkdir -p /opt/staging/windows/sharphound
wget "https://github.com/SpecterOps/SharpHound/releases/download/"$sharphound_version"/SharpHound_"$sharphound_version"_windows_x86.zip" -O /opt/staging/windows/sharphound/SharpHound.zip

unzip -o /opt/staging/windows/sharphound/SharpHound.zip -d /opt/staging/windows/sharphound 
# Leaving this so that dependencies can be transferred as needed

# Copy PowerView.ps1 for ease of access
printf "\n ${CYAN}-_-_-_-_- Pulling down PowerView.ps1... -_-_-_-_- ${NC}\n\n"
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -O /opt/staging/windows/powerview.ps1
printf "\n ${CYAN}-_-_-_-_- Pulling down PowerUp.ps1... -_-_-_-_- ${NC}\n\n"

# PowerUp is no longer being updated and can be downloaded in its latest form:
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 -O /opt/staging/windows/powerup.ps1

# Get nc64 for 64- and 32-bit systems
printf "\n ${CYAN}-_-_-_-_- Pulling down nc64 executables... -_-_-_-_- ${NC}\n\n"
nc64_version=$(curl -fsSL https://api.github.com/repos/vinsworldcom/NetCat64/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
wget "https://github.com/vinsworldcom/NetCat64/releases/download/"$nc64_version"/nc64.exe" -O /opt/staging/windows/nc64.exe
chmod +x /opt/staging/windows/nc64.exe
wget "https://github.com/vinsworldcom/NetCat64/releases/download/"$nc64_version"/nc64-32.exe" -O /opt/staging/windows/nc64_32bit.exe
chmod +x /opt/staging/windows/nc64_32bit.exe

# Get GodPotato and CoercedPotato
printf "\n ${CYAN}-_-_-_-_- Pulling down GodPotato Binaries... -_-_-_-_- ${NC}\n\n"
mkdir -p /opt/staging/windows/potato
godpotato_version=$(curl -fsSL https://api.github.com/repos/BeichenDream/GodPotato/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
godpotato_files=("GodPotato-NET2.exe" "GodPotato-NET35.exe" "GodPotato-NET4.exe")
for godpotato_binary in ${godpotato_files[@]}; do
	wget https://github.com/BeichenDream/GodPotato/releases/download/$godpotato_version/$godpotato_binary -O /opt/staging/windows/potato/$godpotato_binary
	chmod +x /opt/staging/windows/potato/$godpotato_binary 
done

printf "\n ${CYAN}-_-_-_-_- Cloning CoercedPotato... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/windows/potato
git clone https://github.com/overgrowncarrot1/CoercedPotatoCompiled.git || true
cd CoercedPotatoCompiled 
unzip -o CoercedPotato.zip
cp CoercedPotato.exe /opt/staging/windows/potato/CoercedPotato.exe
chmod +x /opt/staging/windows/potato/CoercedPotato.exe
rm -rf /opt/staging/windows/potato/CoercedPotatoCompiled

# Download RemotePotato0
printf "\n ${CYAN}-_-_-_-_- Pulling down RemotePotato0 Binary... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/windows/potato
wget "https://github.com/antonioCoco/RemotePotato0/releases/download/1.2/RemotePotato0.zip" -O /opt/staging/windows/potato/RemotePotato0.zip
unzip -o RemotePotato0.zip
rm -rf /opt/staging/windows/potato/RemotePotato0.zip

# Download Mimikatz
printf "\n ${CYAN}-_-_-_-_- Pulling down Mimikatz... -_-_-_-_- ${NC}\n\n"

mkdir -p /opt/staging/windows/mimikatz
cd /opt/staging/windows/mimikatz
mimikatz_version=$(curl -fsSL https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
wget https://github.com/gentilkiwi/mimikatz/releases/download/$mimikatz_version/mimikatz_trunk.zip -O /opt/staging/windows/mimikatz/mimikatz.zip
unzip -o mimikatz.zip

# Download GhostPack binaries, Seatbelt, etc.
cd /opt/staging/windows
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git ghostpack|| true
cd ghostpack
cp Seatbelt.exe /opt/staging/windows/

########### --- END SCRIPTS FROM BRADY --- ############

# Set user as owner of all tools added to /opt/
# Do not modify existing /opt/microsoft
find /opt -mindepth 1 -maxdepth 1 -path /opt/microsoft -prune -o \
  -exec chown -R --no-dereference "$TARGET_USER:$TARGET_GROUP" {} +

# Autoremove unused packages
echo "Running apt-get autoremove..."
apt-get autoremove -y

# Load file entries into 'locate' database
echo "Updating Locate database, this may take a moment..."
updatedb || true

# Start Bloodhound
echo "Starting Bloodhound server in background, default port is 7070..."
echo 'Default Bloodhound credentials are admin:Bloodhound123!'
cd /opt/bloodhound-ce
docker compose up -d

# Install seclists in the background (545MB download, ~1.8GB installed).
# MUST come after the last apt-get call above - dpkg's lock is global and
# a concurrent apt-get would fail with "Could not get lock".
echo "Starting seclists install in the background..."
setsid sh -c 'apt-get -y install seclists && updatedb' \
  > /var/log/seclists-install.log 2>&1 &
echo "seclists is installing in the background: tail -f /var/log/seclists-install.log"

# Fetch nuclei templates in the background, as the target user so they land in
# their home (~/.local/nuclei-templates) rather than root's.
echo "Fetching nuclei templates in the background..."
# Do NOT add -duc here. -duc (disable-update-check) suppresses -ut
# (update-templates): nuclei prints its banner, exits 0 and downloads nothing,
# so the failure is completely silent. Verified both ways on a throwaway HOME:
# "-ut -duc" => 28K of config and no templates; "-ut" => 14,039 templates.
setsid sudo -u "$TARGET_USER" env HOME="$TARGET_HOME" XDG_CONFIG_HOME="$TARGET_HOME/.config" \
  nuclei -ut > /var/log/nuclei-templates.log 2>&1 &
echo "nuclei templates updating in the background: tail -f /var/log/nuclei-templates.log"

# set +x

cat << 'EOF'
 ███████████   ██████████   █████████   ██████████  
░░███░░░░░███ ░░███░░░░░█  ███░░░░░███ ░░███░░░░███ 
 ░███    ░███  ░███  █ ░  ░███    ░███  ░███   ░░███
 ░██████████   ░██████    ░███████████  ░███    ░███
 ░███░░░░░███  ░███░░█    ░███░░░░░███  ░███    ░███
 ░███    ░███  ░███ ░   █ ░███    ░███  ░███    ███ 
 █████   █████ ██████████ █████   █████ ██████████  
░░░░░   ░░░░░ ░░░░░░░░░░ ░░░░░   ░░░░░ ░░░░░░░░░░   
                                                    
                                                    
                                                    
 ██████   ██████ ██████████ ███ ███ ███             
░░██████ ██████ ░░███░░░░░█░███░███░███             
 ░███░█████░███  ░███  █ ░ ░███░███░███             
 ░███░░███ ░███  ░██████   ░███░███░███             
 ░███ ░░░  ░███  ░███░░█   ░███░███░███             
 ░███      ░███  ░███ ░   █░░░ ░░░ ░░░              
 █████     █████ ██████████ ███ ███ ███             
░░░░░     ░░░░░ ░░░░░░░░░░ ░░░ ░░░ ░░░              


########################################################
########################################################
####                                                ####
####  You MUST 'source ~/.zshrc' to apply changes!  ####
####  Bloodhound: http://127.0.0.1:7070             ####
####  Credentials: admin:Bloodhound123!             ####
####                                                ####
####  seclists (1.8GB) installing in background     ####
####    tail -f /var/log/seclists-install.log       ####
####  nuclei templates fetching in background       ####
####    tail -f /var/log/nuclei-templates.log       ####
####                                                ####
####  wpscan API token: wpscan-token <TOKEN>        ####
####  Wappalyzer loads on first Firefox launch      ####
####                                                ####
########################################################
####H#A#P#P#Y##H#A#C#K#I#N#G############################
EOF

# TODO 
# TODO git clone https://github.com/maurosoria/dirsearch.git --depth 1
# TODO add dirsearch to the PATH after cloning
# TODO add Brady's Ligolo-NG install scripts
# TODO consider adding a reverse engineering tool like Binary Ninja or Ghidra
# TODO consider Pylingual, Pyextractor, pyenv

# Changelog
# 0.1: Created script
# 0.2: Fixed group assignments, removed TODO statements, fixed nxc argcomplete, fixed Tilix zshrc requirements, fixed apt-get statements
# 0.3: Minor fixes
# 0.4: Fixed line endings, added seclists, added rockyou.txt unzip
# 1.0: Consolidated release. Everything below is relative to 0.4.
#
#      Tools added
#      - penelope (reverse shell handler), feroxbuster, ffuf, jq.
#      - certipy-ad, which is the real Certipy; the plain "certipy" package is an
#        unrelated CA utility. The pre-existing certipy alias now resolves.
#      - Sickle from wetw0rk/Sickle. The apt package of that name is a
#        bioinformatics tool.
#      - ozelis/winrmexec at /opt/winrmexec. Both winrmexec.py and
#        evil_winrmexec.py are shebang-patched, chmod +x and symlinked into
#        /usr/local/bin as "winrmexec" and "evil_winrmexec", plus
#        python3-prompt-toolkit, which evil_winrmexec.py imports unconditionally.
#      - ligolo-ng (apt) with a persistent "ligolo" tun interface owned by the
#        target user, recreated at boot by the ligolo-tun.service unit, and
#        per-arch agents staged for Windows and Linux targets.
#      - chisel (apt) with per-arch binaries staged for targets.
#      - bloodhound-ce-python, the Linux-side BloodHound collector, and kerbrute
#        in /usr/local/bin.
#      - wpscan (apt, non-free) with ~/.wpscan/scan.yml at 0600 and a
#        /usr/local/bin/wpscan-token helper. The API token is read from
#        $WPSCAN_API_TOKEN at build time if set, else a placeholder is written;
#        wpscan.com registration needs email verification and cannot be
#        scripted.
#      - Wappalyzer for Firefox, installed by enterprise ExtensionSettings
#        policy rather than apt. The signed XPI is cached under
#        /usr/local/share/firefox-extensions and staged to a temp file, then
#        checked for size and a readable zip manifest before it replaces the
#        cached copy, so a failed download keeps the working one. The policy is
#        merged into Kali's shipped policies.json rather than replacing it, and
#        written to three paths with identical content: the firefox-esr
#        distribution directory, /etc/firefox/policies and
#        /etc/firefox-esr/policies. On Kali the distribution file is the one
#        Firefox reads, so writing all three makes precedence irrelevant.
#        NOTE: that file is not dpkg-tracked, so a firefox-esr or kali-defaults
#        upgrade can replace it and drop the extension. Re-run this script after
#        a major upgrade and confirm with about:policies, not by reading the
#        file. There is no WhatWeb extension; WhatWeb is CLI-only and already
#        in Kali.
#      - nuclei templates fetched in the background as the target user, so they
#        are ready without a manual first-run download.
#
#      Behaviour and configuration
#      - Removed a stray "set -eu" that aborted the script early.
#      - GIT_TERMINAL_PROMPT=0 and GIT_ASKPASS are set, so a missing or private
#        repo cannot hang the run on a credential prompt.
#      - Tilix gsettings are applied to the target user, not root.
#      - ~/.aliases and the nxc argcomplete block are idempotent, and both
#        ~/.aliases and ~/.zshrc are chowned to the target user. The
#        "# NXC ARGCOMPLETE" marker is written only after the completion has
#        been generated, so a failure leaves the block retryable.
#      - ~/.zshrc sources ~/.cargo/env behind its own marker; rustup writes only
#        to ~/.profile and ~/.bashrc.
#      - atuin init is guarded on PATH.
#      - The sudoers.d file is chmod 0440, which "visudo -c" requires.
#      - seclists installs in the background after all other apt work.
#      - Fixed the CDK download URL, which was fetching HTML from /releases/tag/.
