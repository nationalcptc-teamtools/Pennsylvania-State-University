#!/usr/bin/env bash
# Post-run verification for setupscript_v1.0.sh
#
# Run AFTER the setup script finishes:   sudo ./verify.sh
# Safe to run repeatedly; makes no changes.
#
# Exit codes: 0 = no failures, 1 = at least one FAIL.
# WARN means "could not confirm here" (background job still running, needs a
# fresh login shell, etc.) - not necessarily broken.

PASS=0; FAIL=0; WARN=0
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'

# Resolve the same target user the setup script would have used
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  TARGET_USER="$SUDO_USER"
else
  TARGET_USER="$USER"
fi
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"

ok()   { PASS=$((PASS+1)); printf "${GREEN}  PASS${NC}  %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf "${RED}  FAIL${NC}  %s\n" "$1"; }
warn() { WARN=$((WARN+1)); printf "${YELLOW}  WARN${NC}  %s\n" "$1"; }
section() { printf "\n=== %s ===\n" "$1"; }

# on PATH, or in sbin (some packages install there and a user PATH may omit it)
have_cmd() {
  command -v "$1" >/dev/null 2>&1 && return 0
  # sudo's secure_path is /usr/sbin:/usr/bin:/sbin:/bin - it does NOT include
  # /usr/local/bin, so anything installed there is invisible to command -v
  # when this script runs under sudo. Check the real locations directly.
  for d in /usr/local/bin /usr/local/sbin /usr/sbin /sbin /usr/bin /bin; do
    [ -x "$d/$1" ] && return 0
  done
  return 1
}
check_cmd() { have_cmd "$1" && ok "command: $1" || bad "command missing: $1"; }
check_file() { [ -f "$2" ] && ok "$1" || bad "$1  (missing: $2)"; }
check_exec() { [ -x "$2" ] && ok "$1" || bad "$1  (missing or not executable: $2)"; }
check_dir()  { [ -d "$2" ] && ok "$1" || bad "$1  (missing: $2)"; }
# marker must appear exactly once - more than once means a re-run duplicated a block
check_marker() {
  local label="$1" file="$2" marker="$3" n
  if [ ! -f "$file" ]; then bad "$label  (file missing: $file)"; return; fi
  n=$(grep -cF "$marker" "$file")
  case "$n" in
    0) bad  "$label  (marker absent from $file)" ;;
    1) ok   "$label" ;;
    *) bad  "$label  (marker appears $n times in $file - block duplicated, idempotency broken)" ;;
  esac
}

# Run a command as the target user (no-op sudo when we already are them)
as_target() {
  if [ "$(id -u)" -eq 0 ]; then
    sudo -u "$TARGET_USER" env HOME="$TARGET_HOME" \
      XDG_CONFIG_HOME="$TARGET_HOME/.config" "$@"
  elif [ "$(id -un)" = "$TARGET_USER" ]; then
    env HOME="$TARGET_HOME" XDG_CONFIG_HOME="$TARGET_HOME/.config" "$@"
  else
    return 127
  fi
}

printf "Verifying build for target user: %s (home: %s)\n" "$TARGET_USER" "$TARGET_HOME"

section "1. apt-installed commands on PATH"
for c in rg micro ntpdate rdate mitm6 bloodyad certipy-ad bloodhound-ce-python \
         ligolo-proxy chisel penelope nuclei feroxbuster ffuf wpscan whatweb \
         remmina enum4linux-ng keepass2 tilix libreoffice docker code jq swaks \
         register-python-argcomplete dconf; do
  check_cmd "$c"
done

section "2. Manually placed binaries and symlinks"
check_exec "kerbrute binary"            /usr/local/bin/kerbrute
check_exec "winrmexec on PATH"          /usr/local/bin/winrmexec
check_exec "evil_winrmexec on PATH"     /usr/local/bin/evil_winrmexec
for w in winrmexec evil_winrmexec; do
  f="/opt/winrmexec/$w.py"
  if [ -f "$f" ]; then
    head -1 "$f" | grep -q '^#!' \
      && ok "$w.py has a shebang" \
      || bad "$w.py has NO shebang - the symlink will not execute"
  else
    bad "$f missing"
  fi
done
# Sliver's installer location is not pinned by the script - find it wherever it landed
if have_cmd sliver-server || have_cmd sliver; then
  ok "sliver present on PATH"
else
  warn "sliver-server not on PATH - check: ls /root/sliver /usr/local/bin/sliver*"
fi

section "3. Cloned repos in /opt (run locally, NOT on PATH by design)"
check_file "krbrelayx"        /opt/krbrelayx/krbrelayx.py
check_file "PKINITtools"      /opt/PKINITtools/gettgtpkinit.py
check_file "PetitPotam"       /opt/petitpotam/PetitPotam.py
check_file "pywhisker"        /opt/pywhisker/pywhisker/pywhisker.py
check_file "sccmhunter"       /opt/sccmhunter/sccmhunter.py
check_dir  "Sickle"           /opt/sickle/src
check_dir  "winrmexec"        /opt/winrmexec
# /opt/impacket_sccm_relay is gone as of script 1.1 - the upstream fork was
# deleted. A leftover from an older build is harmless but will be stale.
[ -d /opt/impacket_sccm_relay ] \
  && warn "/opt/impacket_sccm_relay exists from an earlier build; upstream is deleted, it will never update" \
  || ok "no stale impacket SCCM fork (expected - removed in 1.1)"

section "4. Staged Windows payloads (/opt/staging/windows)"
for f in SharpUp.exe Certify.exe Rubeus.exe Seatbelt.exe \
         RunasCs.exe RunasCs_net2.exe Invoke-RunasCs.ps1 \
         nc64.exe nc64_32bit.exe powerview.ps1 powerup.ps1; do
  check_file "windows/$f" "/opt/staging/windows/$f"
done
for f in winPEAS.bat winPEASany.exe winPEASany_ofs.exe winPEASx64_ofs.exe \
         winPEASx86.exe winPEASx86_ofs.exe; do
  check_file "windows/winpeas/$f" "/opt/staging/windows/winpeas/$f"
done
check_file "windows/ligolo agent" /opt/staging/windows/ligolo/ligolo-agent_windows_amd64.exe
check_file "windows/chisel"       /opt/staging/windows/chisel/chisel_windows_amd64.exe
check_dir  "windows/ghostpack clone" /opt/staging/windows/ghostpack
[ -n "$(ls -A /opt/staging/windows/sharphound/*.exe 2>/dev/null)" ] \
  && ok "SharpHound extracted" || bad "no SharpHound .exe in /opt/staging/windows/sharphound"
[ -n "$(ls -A /opt/staging/windows/mimikatz/x64/mimikatz.exe 2>/dev/null)" ] \
  && ok "mimikatz extracted" || bad "mimikatz.exe not found under /opt/staging/windows/mimikatz/x64"
[ -n "$(ls -A /opt/staging/windows/potato 2>/dev/null)" ] \
  && ok "potato payloads present" || bad "/opt/staging/windows/potato empty or missing"
# A truncated/404 download often lands as a tiny HTML error page
printf "  -- staged files under 1 KB (likely failed downloads):\n"
sml=$(find /opt/staging -type f -size -1k 2>/dev/null)
if [ -z "$sml" ]; then ok "no suspiciously small staged files"; else
  printf "%s\n" "$sml" | sed 's/^/       /'
  bad "some staged files are under 1 KB - inspect them, a 404 page is not a payload"
fi

section "5. Staged Linux payloads (/opt/staging/linux)"
for f in pspy32 pspy32s pspy64 pspy64s polkit_binary PolKit_PwnKit.sh; do
  check_file "linux/$f" "/opt/staging/linux/$f"
done
for f in linpeas.sh linpeas_fat.sh linpeas_linux_386 linpeas_linux_amd64 \
         linpeas_linux_arm linpeas_darwin_amd64 linpeas_darwin_arm64; do
  check_file "linux/linpeas/$f" "/opt/staging/linux/linpeas/$f"
done
for f in cdk_linux_386 cdk_linux_amd64 cdk_linux_amd64_upx cdk_linux_arm \
         cdk_linux_arm64 cdk_darwin_amd64; do
  check_file "linux/cdk/$f" "/opt/staging/linux/cdk/$f"
done
check_file "linux/ligolo amd64" /opt/staging/linux/ligolo/ligolo-agent_linux_amd64
check_file "linux/ligolo arm64" /opt/staging/linux/ligolo/ligolo-agent_linux_arm64
check_file "linux/chisel amd64" /opt/staging/linux/chisel/chisel_linux_amd64
check_file "linux/chisel arm64" /opt/staging/linux/chisel/chisel_linux_arm64

section "6. Wordlists"
check_file "rockyou.txt unzipped" /usr/share/wordlists/rockyou.txt
[ -f /usr/share/wordlists/rockyou.txt.gz ] \
  && warn "rockyou.txt.gz still present alongside the unzipped copy" \
  || ok "rockyou.txt.gz consumed"

section "7. System configuration"
check_file "passwordless sudo"  "/etc/sudoers.d/dont-prompt-$TARGET_USER-for-sudo-password"
if [ "$(id -u)" -eq 0 ]; then
  visudo -c >/dev/null 2>&1 && ok "sudoers syntax valid" || bad "visudo -c reports a sudoers problem"
else
  warn "sudoers syntax not checked (re-run with sudo)"
fi
[ -L /etc/profile.d/vte.sh ] && ok "vte.sh symlink" || bad "/etc/profile.d/vte.sh is not a symlink"
[ -e /etc/profile.d/vte.sh ] && ok "vte.sh target resolves" || bad "vte.sh symlink is dangling (vte-2.91.sh absent?)"
if [ -f /etc/snmp/snmp.conf ]; then
  grep -q '^# mibs :' /etc/snmp/snmp.conf && ok "snmp mibs line commented out" \
    || { grep -q '^mibs :' /etc/snmp/snmp.conf && bad "snmp 'mibs :' still active - MIBs will not load" \
         || warn "no 'mibs :' line in /etc/snmp/snmp.conf to comment"; }
else
  bad "/etc/snmp/snmp.conf missing (snmp-mibs-downloader not installed?)"
fi
id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx docker \
  && ok "$TARGET_USER is in the docker group" || bad "$TARGET_USER is NOT in the docker group"

section "8. Shell config - idempotency markers (must each appear exactly once)"
check_marker "~/.aliases written once" "$TARGET_HOME/.aliases" "# MODIFIED BY AUTOMATIC INSTALLATION SCRIPT"
check_marker "~/.zshrc block written once" "$TARGET_HOME/.zshrc" "# MODIFIED BY AUTOMATIC INSTALLATION SCRIPT"
check_marker "nxc argcomplete block once" "$TARGET_HOME/.zshrc" "# NXC ARGCOMPLETE"
n=$(grep -c 'source.*\.aliases' "$TARGET_HOME/.zshrc" 2>/dev/null)
[ "${n:-0}" -le 1 ] && ok ".aliases sourced at most once" || bad ".aliases sourced $n times in .zshrc"
for f in "$TARGET_HOME/.aliases" "$TARGET_HOME/.zshrc"; do
  [ -f "$f" ] && { [ "$(stat -c %U "$f")" = "$TARGET_USER" ] \
    && ok "$(basename "$f") owned by $TARGET_USER" \
    || bad "$(basename "$f") owned by $(stat -c %U "$f"), not $TARGET_USER"; }
done

section "9. Per-user installs (owned by $TARGET_USER)"
check_file "atuin env script" "$TARGET_HOME/.atuin/bin/env"
check_exec "atuin binary"     "$TARGET_HOME/.atuin/bin/atuin"
check_exec "cargo (rustup)"   "$TARGET_HOME/.cargo/bin/cargo"
# rustup writes its PATH line to .profile/.bashrc, never .zshrc, so the binary
# existing proves nothing about whether "cargo" resolves in a zsh login shell.
if grep -q 'cargo/env' "$TARGET_HOME/.zshrc" 2>/dev/null; then
  ok "cargo env sourced from .zshrc"
else
  bad "cargo is NOT on the zsh PATH - .zshrc does not source ~/.cargo/env"
fi
grep -q 'atuin' "$TARGET_HOME/.zshrc" 2>/dev/null && ok "atuin init in .zshrc" || bad "no atuin init in .zshrc"
# Tilix settings live in the user's dconf, not root's
tp=$(as_target gsettings get com.gexperts.Tilix.ProfilesList default 2>/dev/null | tr -d "'")
if [ -n "$tp" ]; then
  ls=$(as_target gsettings get \
      "com.gexperts.Tilix.Profile:/com/gexperts/Tilix/profiles/$tp/" login-shell 2>/dev/null)
  [ "$ls" = "true" ] && ok "Tilix login-shell=true for $TARGET_USER" \
    || bad "Tilix login-shell is '$ls' for $TARGET_USER - gsettings did not apply to the right user"
else
  warn "could not read Tilix profile for $TARGET_USER (no session bus? run this check from the desktop)"
fi

section "10. systemd units and the ligolo interface"
systemctl is-enabled ligolo-tun.service >/dev/null 2>&1 \
  && ok "ligolo-tun.service enabled" || bad "ligolo-tun.service not enabled"
systemd-analyze verify /etc/systemd/system/ligolo-tun.service >/dev/null 2>&1 \
  && ok "ligolo-tun.service verifies" || warn "systemd-analyze verify complained about ligolo-tun.service"
ip link show ligolo >/dev/null 2>&1 && ok "ligolo tun interface exists" || bad "no 'ligolo' interface - ip link show ligolo failed"
systemctl is-enabled sliver >/dev/null 2>&1 && ok "sliver service enabled" || warn "sliver service not enabled"

section "11. Docker and BloodHound CE"
systemctl is-active docker >/dev/null 2>&1 && ok "docker daemon running" || bad "docker daemon not running"
check_file "compose file" /opt/bloodhound-ce/docker-compose.yml
if [ -d /opt/bloodhound-ce ]; then
  up=$(docker compose -f /opt/bloodhound-ce/docker-compose.yml ps --status running -q 2>/dev/null | wc -l)
  [ "$up" -ge 2 ] && ok "$up BloodHound containers running" || bad "only $up BloodHound containers running (expect >=2)"
fi
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:7070 2>/dev/null)
case "$code" in
  200|301|302|307) ok "BloodHound UI answering on 7070 (HTTP $code)" ;;
  ""|000) bad "nothing answering on 127.0.0.1:7070" ;;
  *)   warn "7070 returned HTTP $code - may still be starting, retry in a minute" ;;
esac

section "12. Background jobs (started as the script exits)"
if pgrep -x apt-get >/dev/null 2>&1 && pgrep -f '[s]eclists' >/dev/null 2>&1; then
  warn "seclists still installing - tail -f /var/log/seclists-install.log"
elif [ -d /usr/share/seclists ]; then
  ok "seclists installed ($(du -sh /usr/share/seclists 2>/dev/null | cut -f1))"
else
  bad "seclists not installed and not running - check /var/log/seclists-install.log"
fi
if pgrep -x nuclei >/dev/null 2>&1; then
  warn "nuclei templates still downloading - tail -f /var/log/nuclei-templates.log"
else
  td=$(find "$TARGET_HOME" -maxdepth 3 -type d -name 'nuclei-templates' 2>/dev/null | head -1)
  if [ -n "$td" ]; then
    ny=$(find "$td" -name '*.yaml' | wc -l)
    # A real template set is ~14k files. Anything far below that means the
    # update ran but fetched nothing - which is what "-ut -duc" used to do.
    [ "$ny" -gt 1000 ] \
      && ok "nuclei templates at $td ($ny yaml files)" \
      || bad "only $ny templates at $td - the update ran but fetched (almost) nothing"
  else
    bad "no nuclei-templates dir under $TARGET_HOME - check /var/log/nuclei-templates.log"
  fi
fi

section "13. /opt ownership"
wrong=$(find /opt -mindepth 1 -maxdepth 1 -path /opt/microsoft -prune -o \
         ! -user "$TARGET_USER" -print 2>/dev/null)
if [ -z "$wrong" ]; then
  ok "all /opt entries owned by $TARGET_USER (except /opt/microsoft)"
else
  printf "%s\n" "$wrong" | sed 's/^/       /'
  warn "the above /opt entries are not owned by $TARGET_USER"
fi

section "14. WPScan API token"
check_exec "wpscan-token helper" /usr/local/bin/wpscan-token
WPCFG="$TARGET_HOME/.wpscan/scan.yml"
if [ -f "$WPCFG" ]; then
  ok "$WPCFG exists"
  m=$(stat -c %a "$WPCFG")
  [ "$m" = "600" ] && ok "scan.yml mode 600" || bad "scan.yml mode is $m, expected 600 (it holds a secret)"
  o=$(stat -c %U "$WPCFG")
  [ "$o" = "$TARGET_USER" ] && ok "scan.yml owned by $TARGET_USER" \
    || bad "scan.yml owned by $o - wpscan runs as $TARGET_USER and will not read it"
  if grep -q '^cli_options:' "$WPCFG"; then
    grep -q 'YOUR_TOKEN_HERE' "$WPCFG" \
      && bad "scan.yml still holds the literal placeholder token" \
      || ok "an API token is configured"
  else
    warn "no token configured yet (expected if you have not registered) - run: wpscan-token <TOKEN>"
  fi
else
  bad "$WPCFG missing"
fi

section "15. Firefox extensions (Wappalyzer)"
FF_XPI=/usr/local/share/firefox-extensions/wappalyzer.xpi
if [ -s "$FF_XPI" ]; then
  sz=$(stat -c %s "$FF_XPI")
  [ "$sz" -gt 1000000 ] && ok "Wappalyzer XPI cached ($((sz/1024/1024)) MB)" \
    || bad "XPI is only $sz bytes - download truncated, not a real extension"
  unzip -p "$FF_XPI" manifest.json >/dev/null 2>&1 \
    && ok "XPI is a readable zip" || bad "XPI is not a valid zip"
else
  bad "no XPI at $FF_XPI"
fi
# The policy must exist where Firefox actually READS it. On this image that is
# the distribution directory: SysConfD/policies/policies.json is only consulted
# if it exists, and a policy written solely under /etc was silently ignored
# (about:policies showed no ExtensionSettings). Script 1.3 writes all three.
FF_DIST=/usr/lib/firefox-esr/distribution/policies.json
if [ -s "$FF_DIST" ] && jq -e '.policies.ExtensionSettings' "$FF_DIST" >/dev/null 2>&1; then
  ok "policy present in the distribution dir (the path Firefox reads here)"
else
  bad "no ExtensionSettings in $FF_DIST - Firefox will not see it, whatever is under /etc"
fi
for extra in /etc/firefox/policies/policies.json /etc/firefox-esr/policies/policies.json; do
  [ -s "$extra" ] && ok "policy also at $extra" || warn "no policy at $extra (harmless if the distribution one is correct)"
done
# Verify the content of whichever copy we can read
FF_POLICY="$FF_DIST"
[ -s "$FF_POLICY" ] || FF_POLICY=/etc/firefox-esr/policies/policies.json
if [ -s "$FF_POLICY" ]; then
  if jq -e . "$FF_POLICY" >/dev/null 2>&1; then
    ok "$FF_POLICY is valid JSON"
    u=$(jq -r '.policies.ExtensionSettings["wappalyzer@crunchlabz.com"].install_url // empty' "$FF_POLICY")
    if [ -n "$u" ]; then
      ok "Wappalyzer policy entry present"
      f=${u#file://}
      [ -s "$f" ] && ok "policy install_url points at an existing XPI" \
        || bad "policy install_url points at $f which does not exist"
      im=$(jq -r '.policies.ExtensionSettings["wappalyzer@crunchlabz.com"].installation_mode' "$FF_POLICY")
      case "$im" in
        normal_installed|force_installed) ok "installation_mode=$im" ;;
        *) bad "installation_mode=$im will not install anything" ;;
      esac
    else
      bad "no wappalyzer entry in ExtensionSettings"
    fi
    # the merge must not have dropped Kali's own defaults
    # NB: use has(), not "jq -e .policies.X" - jq -e exits 1 for a value that is
  # literally false, so CaptivePortal/NetworkPrediction (both false) would be
  # reported as missing when they are present and correct.
  missing=""
  for k in CaptivePortal DisableTelemetry NoDefaultBookmarks Homepage FirefoxHome; do
    jq -e --arg k "$k" '.policies | has($k)' "$FF_POLICY" >/dev/null 2>&1 || missing="$missing $k"
  done
  [ -z "$missing" ] \
    && ok "Kali's own policy keys survived the merge" \
    || bad "Kali's policy keys lost in the merge:$missing"
  else
    bad "$FF_POLICY is not valid JSON - Firefox will ignore ALL policies"
  fi
else
  bad "$FF_POLICY missing"
fi
# Did it actually land? Only true after Firefox has been launched once.
# Scan EVERY profile, not just *.default* - a clean-test profile is the whole
# point of this check and will not match that glob - and parse the JSON rather
# than grepping, so a disabled or stale entry is not counted as a success.
WAP_ID="wappalyzer@crunchlabz.com"
ff_launched=0; ff_found=0; ff_without=""
for ej in "$TARGET_HOME"/.mozilla/firefox/*/extensions.json; do
  [ -f "$ej" ] || continue
  ff_launched=$((ff_launched+1))
  pname=$(basename "$(dirname "$ej")")
  if jq -e --arg id "$WAP_ID" \
       '.addons[]? | select(.id==$id and .active==true and .appDisabled==false)' \
       "$ej" >/dev/null 2>&1; then
    ff_found=$((ff_found+1))
    ver=$(jq -r --arg id "$WAP_ID" '.addons[]?|select(.id==$id)|.version' "$ej" | head -1)
    src=$(jq -r --arg id "$WAP_ID" \
            '.addons[]?|select(.id==$id)|.installTelemetryInfo.source // "unknown"' "$ej" | head -1)
    ok "Wappalyzer $ver active in profile '$pname' (installed by: $src)"
    # the policy, not a human, must have installed it
    [ "$src" = "enterprise-policy" ] \
      && ok "'$pname' install came from the enterprise policy" \
      || warn "'$pname' install source is '$src', not enterprise-policy"
  else
    ff_without="$ff_without $pname"
  fi
done
if [ "$ff_launched" -eq 0 ]; then
  warn "no Firefox profile has been launched yet - launch Firefox once to trigger the install"
elif [ "$ff_found" -eq 0 ]; then
  bad "Firefox has run ($ff_launched profile(s):$ff_without) but Wappalyzer is in none of them"
elif [ -n "$ff_without" ]; then
  warn "not present in:$ff_without - profiles first launched before the policy was fixed need one more launch"
fi

printf "\n======================================\n"
printf "${GREEN}PASS: %d${NC}   ${RED}FAIL: %d${NC}   ${YELLOW}WARN: %d${NC}\n" "$PASS" "$FAIL" "$WARN"
printf "======================================\n"
[ "$FAIL" -eq 0 ] || exit 1
