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

# Enable running all commands as root without sudo password
echo "Enabling passwordless sudo..."
echo "Enabling NOPASSWD sudo for user: $TARGET_USER"
echo -e "$TARGET_USER ALL=(ALL:ALL) NOPASSWD: ALL\nDefaults:$TARGET_USER verifypw=any\n" | sudo tee "/etc/sudoers.d/dont-prompt-$TARGET_USER-for-sudo-password"

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
set -eu

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

# Install micro
echo "Installing micro..."
apt-get -y install micro

# Install ntpdate
echo "Installing ntpdate..."
apt-get -y install ntpsec-ntpdate

# Install seclists
echo "Install seclists..."
apt-get -y install seclists

# Install rdate
echo "Installing rdate..."
apt-get -y install rdate

# Install mitm6
echo "Installing mitm6..."
apt-get -y install mitm6

# Install bloodyad
echo "Installing bloodyad..."
apt-get -y install bloodyad

# Install Sickle
echo "Installing Sickle..."
apt-get -y install sickle

# Install Nuclei
echo "Installing Nuclei..."
apt-get -y install nuclei

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

ln -s /etc/profile.d/vte-2.91.sh /etc/profile.d/vte.sh

dconf update

gsettings set com.gexperts.Tilix.Profile:/com/gexperts/Tilix/profiles/$(gsettings get com.gexperts.Tilix.ProfilesList default 2>/dev/null | tr -d "'")/ login-shell true 2>&1
gsettings set com.gexperts.Tilix.Profile:/com/gexperts/Tilix/profiles/$(gsettings get com.gexperts.Tilix.ProfilesList default 2>/dev/null | tr -d "'")/ scrollback-unlimited true 2>&1
gsettings set com.gexperts.Tilix.Profile:/com/gexperts/Tilix/profiles/$(gsettings get com.gexperts.Tilix.ProfilesList default 2>/dev/null | tr -d "'")/ background-transparency-percent 0 2>&1

gsettings set com.gexperts.Tilix.Settings use-tabs true
gsettings set com.gexperts.Tilix.Settings window-save-state true
gsettings set com.gexperts.Tilix.Settings unsafe-paste-alert false

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

### Configure ~/.aliases ###
echo 'Configuring aliases...'
echo "Writing to $ALIASFILE"
cat >> "$ALIASFILE" <<'EOF'
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
eval "$(atuin init zsh)"
if [ $TILIX_ID ] || [ $VTE_VERSION ]; then
        source /etc/profile.d/vte.sh
fi
EOF
  echo "Wrote changes to $ZSHRC"
else
  echo "Skipping: $ZSHRC already contains the modifications"
fi

# Enable NXC autocompletion
echo "Enabling autocompletion for nxc..."
run_as_target 'command -v register-python-argcomplete >/dev/null 2>&1 && \
               register-python-argcomplete nxc >> "$HOME/.zshrc" || true'

########### --- SCRIPTS FROM BRADY --- ############

echo "Cloning tools to /opt/"

# Clone krbrelayx
printf "\n ${PURPLE}-_-_-_-_- Cloning krbrelayx -_-_-_-_- ${NC}\n\n"
git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning krbrelayx -_-_-_-_- ${NC}\n\n"

# Clone PKINITtools
printf "\n ${PURPLE}-_-_-_-_- Cloning PetitPotam -_-_-_-_- ${NC}\n\n"
git clone https://github.com/dirkjanm/PKINITtools.git /opt/PKINITtools || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning PetitPotam -_-_-_-_- ${NC}\n\n"

# Clone PetitPotam
printf "\n ${PURPLE}-_-_-_-_- Cloning PKINITtools -_-_-_-_- ${NC}\n\n"
git clone https://github.com/topotam/PetitPotam.git /opt/petitpotam || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning PKINITtools -_-_-_-_- ${NC}\n\n"

# Clone pywhisker
printf "\n ${PURPLE}-_-_-_-_- Cloning pywhisker -_-_-_-_- ${NC}\n\n"
git clone https://github.com/ShutdownRepo/pywhisker.git /opt/pywhisker || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning pywhisker -_-_-_-_- ${NC}\n\n"

# Clone sccmhunter
printf "\n ${PURPLE}-_-_-_-_- Cloning sccmhunter -_-_-_-_- ${NC}\n\n"
git clone https://github.com/garrettfoster13/sccmhunter.git /opt/sccmhunter || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning sccmhunter -_-_-_-_- ${NC}\n\n"

# Clone Impacket (SCCM Relay)
printf "\n ${PURPLE}-_-_-_-_- Cloning Impacket (SCCM Relay) -_-_-_-_- ${NC}\n\n"
git clone -b feature/relay-sccm-adminservice --single-branch https://github.com/garrettfoster13/impacket.git /opt/impacket_sccm_relay || true
printf "\n ${GREEN}-_-_-_-_- Finished cloning Impacket (SCCM Relay) -_-_-_-_- ${NC}\n\n"

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
pspy_link="https://github.com/DominicBreuker/pspy/releases/download/"$pspy_version"/"
pspy_scripts=("pspy32" "pspy32s" "pspy64" "pspy64s")
for pspy_file in ${pspy_scripts[@]}; do
	wget $pspy_link/$pspy_file -O /opt/staging/linux/$pspy_file
	chmod +x /opt/staging/linux/$pspy_file 
done

# CDK
mkdir -p /opt/staging/linux/cdk/
cdk_version=$(curl -fsSL https://api.github.com/repos/cdk-team/CDK/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
cdk_link="https://github.com/cdk-team/CDK/releases/tag/"$cdk_version"/"
cdk_scripts=("cdk_darwin_amd64" "cdk_linux_386" "cdk_linux_amd64" "cdk_linux_amd64_upx" "cdk_linux_arm" "cdk_linux_arm64")
for cdk_file in ${cdk_scripts[@]}; do
	wget $cdk_link/$cdk_file -O /opt/staging/linux/cdk/$cdk_file
	chmod +x /opt/staging/linux/cdk/$cdk_file 
done

# Polkit
wget https://raw.githubusercontent.com/carlosevieira/polkit/main/pwn -O /opt/staging/linux/polkit_binary

wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh -O /opt/staging/linux/PolKit_PwnKit.sh

printf "\n ${GREEN}-_-_-_-_- Finished setting up the Linux tools directory -_-_-_-_- ${NC}\n\n"

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