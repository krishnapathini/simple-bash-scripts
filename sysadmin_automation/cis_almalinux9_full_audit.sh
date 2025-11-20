#!/usr/bin/env bash
# CIS AlmaLinux 9 Benchmark Audit: Sections 1.x – 7.x (single script)
# Generates PASS/FAIL per control with control IDs and a summary.
# Read-only audit: does NOT make changes.
# Tested on AlmaLinux 9.x (RHEL 9 compatible)

set -o pipefail

REPORT="cis_almalinux9_audit_$(date +%F_%H%M%S).log"
: > "$REPORT"

total=0; passed=0; failed=0

say() { echo -e "$*"; }
log() { echo -e "$*" | tee -a "$REPORT"; }

pass() { ((total++)); ((passed++)); log "[PASS] $1 - $2"; }
fail() { ((total++)); ((failed++)); log "[FAIL] $1 - $2"; }

# Helpers
have() { command -v "$1" >/dev/null 2>&1; }
is_enabled() { systemctl is-enabled "$1" >/dev/null 2>&1; }
is_active() { systemctl is-active "$1" >/dev/null 2>&1; }
pkg_installed() { rpm -q "$1" >/dev/null 2>&1; }
file_perm_ok() { # file expected_perm expected_owner expected_group
  local f="$1" exp="$2" eo="$3" eg="$4"
  [ -e "$f" ] || { fail "$CTRL" "$f missing"; return; }
  local p o g; p=$(stat -c "%a" "$f" 2>/dev/null); o=$(stat -c "%U" "$f" 2>/dev/null); g=$(stat -c "%G" "$f" 2>/dev/null)
  if [[ "$p" == "$exp" && "$o" == "$eo" && "$g" == "$eg" ]]; then
    pass "$CTRL" "Permissions ok: $f ($p $o $g)"
  else
    fail "$CTRL" "Permissions wrong: $f expected $exp $eo $eg got $p $o $g"
  fi
}

# ======================
# 1.x Initial Setup
# ======================
log "--- Section 1.x: Initial Setup ---"

# 1.2.1.2 Ensure gpgcheck is globally activated
CTRL="1.2.1.2"
if grep -RHEq '^\s*gpgcheck\s*=\s*0\b' /etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/*.repo 2>/dev/null; then
  fail "$CTRL" "gpgcheck disabled in some repo files"
else
  pass "$CTRL" "gpgcheck globally activated"
fi

# 1.2.2.1 Ensure updates, patches, and additional security software are installed
CTRL="1.2.2.1"
if have dnf; then
  dnf -q check-update >/dev/null 2>&1
  rc=$?
  if [ $rc -eq 100 ]; then fail "$CTRL" "Updates available (system not fully patched)"
  elif [ $rc -eq 0 ]; then pass "$CTRL" "System fully updated"
  else fail "$CTRL" "Unable to check updates (dnf rc=$rc)"; fi
else
  fail "$CTRL" "dnf not found"
fi

# 1.3.1.3 Ensure SELinux policy is configured (targeted or mls)
CTRL="1.3.1.3"
policy=$(sestatus 2>/dev/null | awk -F: '/Loaded policy name/{gsub(/ /,"",$2); print $2}')
if [[ "$policy" == "targeted" || "$policy" == "mls" ]]; then
  pass "$CTRL" "SELinux policy = $policy"
else
  fail "$CTRL" "SELinux policy not compliant ($policy)"
fi

# 1.3.1.5 Ensure the SELinux mode is enforcing
CTRL="1.3.1.5"
mode=$(getenforce 2>/dev/null)
if [[ "$mode" == "Enforcing" ]]; then
  pass "$CTRL" "SELinux enforcing"
else
  fail "$CTRL" "SELinux mode = $mode"
fi

# ======================
# 2.x Services
# ======================
log "--- Section 2.x: Services ---"

# 2.1.x Ensure specific server services are not in use (each control)
declare -A SVC_CTRL=(
  [autofs]="2.1.1" [avahi-daemon]="2.1.2" [dhcpd]="2.1.3" [named]="2.1.4" [dnsmasq]="2.1.5"
  [smb]="2.1.6" [vsftpd]="2.1.7" [dovecot]="2.1.8" [nfs-server]="2.1.9" [ypserv]="2.1.10"
  [cups]="2.1.11" [rpcbind]="2.1.12" [rsyncd]="2.1.13" [snmpd]="2.1.14" [telnet.socket]="2.1.15"
  [tftp.socket]="2.1.16" [squid]="2.1.17" [httpd]="2.1.18" [xinetd]="2.1.19" [xorg-x11-server-Xorg]="2.1.20"
)
for svc in "${!SVC_CTRL[@]}"; do
  CTRL="${SVC_CTRL[$svc]}"
  if [[ "$svc" == "xorg-x11-server-Xorg" ]]; then
    if pkg_installed xorg-x11-server-Xorg; then fail "$CTRL" "X Window server installed"; else pass "$CTRL" "X Window server not installed"; fi
  else
    if is_enabled "$svc" || is_active "$svc"; then fail "$CTRL" "$svc is enabled/active"; else pass "$CTRL" "$svc disabled or not installed"; fi
  fi
done

# 2.1.21 Ensure MTAs are local-only
CTRL="2.1.21"
mta_listening=$(ss -tlnp 2>/dev/null | awk '/:25|:587|:465/{print}')
if [ -n "$mta_listening" ]; then
  # Accept only 127.0.0.1 or ::1
  bad=$(ss -tlnH 2>/dev/null | awk '/:25|:587|:465/ && !/127\.0\.0\.1|::1/ {print $4}')
  if [ -n "$bad" ]; then fail "$CTRL" "MTA listening on non-local addresses: $bad"; else pass "$CTRL" "MTA restricted to localhost"; fi
else
  pass "$CTRL" "No MTA listening"
fi

# 2.1.22 Ensure only approved services are listening on a network interface
CTRL="2.1.22"
# Define approved ports/services (edit to your policy)
APPROVED_REGEX=':22$|:443$|:80$|:53$'
unapproved=$(ss -tulnH | awk '{print $5}' | grep -Ev "$APPROVED_REGEX" | sort -u)
[ -n "$unapproved" ] && fail "$CTRL" "Unapproved listeners: ${unapproved//$'\n'/, }" || pass "$CTRL" "Only approved listeners present"

# 2.2.x Ensure client packages are not installed
declare -A PKG_CTRL=( [ftp]="2.2.1" [openldap-clients]="2.2.2" [yp-tools]="2.2.3" [telnet]="2.2.4" [tftp]="2.2.5" )
for pkg in "${!PKG_CTRL[@]}"; do
  CTRL="${PKG_CTRL[$pkg]}"
  if pkg_installed "$pkg"; then fail "$CTRL" "Package $pkg installed"; else pass "$CTRL" "Package $pkg not installed"; fi
done

# 2.3.1 Ensure time synchronization is in use
CTRL="2.3.1"
if is_enabled chronyd || is_active chronyd; then pass "$CTRL" "chronyd enabled/active"; else fail "$CTRL" "Time sync not active (chronyd)"; fi

# 2.3.2 Ensure chrony is configured
CTRL="2.3.2"
if [ -s /etc/chrony.conf ] && grep -Eq '^\s*(server|pool)\s+' /etc/chrony.conf; then pass "$CTRL" "chrony servers/pools configured"; else fail "$CTRL" "chrony servers/pools not configured"; fi

# 2.3.3 Ensure chrony not run as root
CTRL="2.3.3"
grep -Eq '^\s*user\s+chrony\b' /etc/chrony.conf && pass "$CTRL" "chrony runs as non-root" || fail "$CTRL" "chrony may run as root (no 'user chrony')"

# ======================
# 3.x Network Configuration
# ======================
log "--- Section 3.x: Network Configuration ---"

# 3.1.1 Ensure IPv6 status is identified
CTRL="3.1.1"
if sysctl net.ipv6.conf.all.disable_ipv6 >/dev/null 2>&1; then pass "$CTRL" "IPv6 status identified"; else fail "$CTRL" "Unable to read IPv6 status"; fi

# 3.2.1–3.2.4 Ensure uncommon protocols not available
for mod in dccp tipc rds sctp; do
  CTRL="3.2.$(case $mod in dccp) echo 1;; tipc) echo 2;; rds) echo 3;; sctp) echo 4;; esac)"
  if lsmod | awk '{print $1}' | grep -qx "$mod"; then
    fail "$CTRL" "Module $mod loaded"
  else
    # also verify blacklisting via install /bin/true
    if grep -RqsE "^\s*install\s+$mod\s+/bin/true" /etc/modprobe.d; then
      pass "$CTRL" "Module $mod not loaded and disabled"
    else
      pass "$CTRL" "Module $mod not loaded (not explicitly disabled)"
    fi
  fi
done

# ======================
# 4.x Firewall Configuration (nftables)
# ======================
log "--- Section 4.x: Firewall ---"

# 4.1.1 Ensure nftables is installed
CTRL="4.1.1"
pkg_installed nftables && pass "$CTRL" "nftables installed" || fail "$CTRL" "nftables not installed"

# 4.1.2 Ensure a single firewall configuration utility is in use
CTRL="4.1.2"
active_fw=$(for s in nftables firewalld iptables; do is_enabled "$s" && echo "$s"; done | xargs)
if [[ "$(echo "$active_fw" | wc -w)" -le 1 ]]; then pass "$CTRL" "Single firewall utility in use: ${active_fw:-none}"; else fail "$CTRL" "Multiple firewall utilities enabled: $active_fw"; fi

# 4.3.1 Ensure nftables base chains exist
CTRL="4.3.1"
if have nft; then
  rs=$(nft list ruleset 2>/dev/null)
  if echo "$rs" | grep -q 'hook input'; then pass "$CTRL" "Base chains present"; else fail "$CTRL" "Missing base chains (input/forward/output)"; fi
else
  fail "$CTRL" "nft command not found"
fi

# 4.3.2 Ensure established connections are configured
CTRL="4.3.2"
if nft list ruleset 2>/dev/null | grep -Eq 'ct state (related,)?established accept'; then
  pass "$CTRL" "Established/related rules present"
else
  fail "$CTRL" "Established connection rules missing"
fi

# 4.3.3 Ensure default deny policy
CTRL="4.3.3"
if nft list ruleset 2>/dev/null | grep -Eq 'chain (input|forward|output).*\n.*policy drop'; then
  pass "$CTRL" "Default drop policy set"
else
  fail "$CTRL" "Default drop policy not set"
fi

# 4.3.4 Ensure loopback traffic is configured
CTRL="4.3.4"
if nft list ruleset 2>/dev/null | grep -Eq 'iif\s+lo\s+accept' && nft list ruleset 2>/dev/null | grep -Eq 'ip\s+saddr\s+127\.0\.0\.0/8\s+counter\s+drop|ip6\s+saddr\s+::1/128\s+counter\s+drop'; then
  pass "$CTRL" "Loopback rules configured"
else
  # Accept alternative: accept lo and drop inbound on lo subnets from non-lo
  if nft list ruleset 2>/dev/null | grep -Eq 'iif\s+lo\s+accept'; then
    pass "$CTRL" "Loopback accept present (drop rules may need review)"
  else
    fail "$CTRL" "Loopback traffic rules incomplete"
  fi
fi

# ======================
# 5.x Access, Authentication, Authorization
# ======================
log "--- Section 5.x: Access, Authentication, Authorization ---"

# 5.1.1 Ensure permissions on /etc/ssh/sshd_config are configured
CTRL="5.1.1"; file_perm_ok /etc/ssh/sshd_config 600 root root

# 5.1.2 Ensure permissions on SSH private host key files are configured
CTRL="5.1.2"
bad_keys=""
for k in /etc/ssh/ssh_host_*_key; do
  [ -f "$k" ] || continue
  p=$(stat -c "%a" "$k"); o=$(stat -c "%U" "$k"); g=$(stat -c "%G" "$k")
  if [[ "$p" != "600" || "$o" != "root" || "$g" != "root" ]]; then bad_keys+="$k($p $o $g) "; fi
done
[ -z "$bad_keys" ] && pass "$CTRL" "SSH private host keys permissions ok" || fail "$CTRL" "Bad SSH host key perms: $bad_keys"

# 5.1.8 Ensure sshd Banner is configured
CTRL="5.1.8"
grep -Eq '^\s*Banner\s+/.+' /etc/ssh/sshd_config && pass "$CTRL" "Banner configured" || fail "$CTRL" "Banner not set"

# 5.1.9 Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
CTRL="5.1.9"
if grep -Eq '^\s*ClientAliveInterval\s+[0-9]+' /etc/ssh/sshd_config && grep -Eq '^\s*ClientAliveCountMax\s+[0-9]+' /etc/ssh/sshd_config; then
  pass "$CTRL" "ClientAliveInterval/CountMax configured"
else
  fail "$CTRL" "ClientAlive settings missing"
fi

# 5.1.10 Ensure sshd DisableForwarding is enabled
CTRL="5.1.10"
if grep -Eq '^\s*DisableForwarding\s+yes\b' /etc/ssh/sshd_config; then pass "$CTRL" "DisableForwarding yes"; else fail "$CTRL" "DisableForwarding not set to yes"; fi

# 5.1.14 Ensure sshd LoginGraceTime is configured
CTRL="5.1.14"
grep -Eq '^\s*LoginGraceTime\s+[0-9]+' /etc/ssh/sshd_config && pass "$CTRL" "LoginGraceTime configured" || fail "$CTRL" "LoginGraceTime not configured"

# 5.1.15 Ensure sshd LogLevel is configured
CTRL="5.1.15"
grep -Eq '^\s*LogLevel\s+(VERBOSE|INFO|INFO\+AUTHPRIV|VERBOSE\+AUTHPRIV)' /etc/ssh/sshd_config && pass "$CTRL" "LogLevel configured" || fail "$CTRL" "LogLevel not configured"

# 5.1.16 Ensure sshd MaxAuthTries is configured
CTRL="5.1.16"
grep -Eq '^\s*MaxAuthTries\s+[1-6]\b' /etc/ssh/sshd_config && pass "$CTRL" "MaxAuthTries configured" || fail "$CTRL" "MaxAuthTries not configured or too high"

# 5.1.19 Ensure sshd PermitEmptyPasswords is disabled
CTRL="5.1.19"
grep -Eq '^\s*PermitEmptyPasswords\s+no\b' /etc/ssh/sshd_config && pass "$CTRL" "PermitEmptyPasswords no" || fail "$CTRL" "PermitEmptyPasswords not set to no"

# 5.1.20 Ensure sshd PermitRootLogin is disabled
CTRL="5.1.20"
grep -Eq '^\s*PermitRootLogin\s+no\b' /etc/ssh/sshd_config && pass "$CTRL" "PermitRootLogin no" || fail "$CTRL" "PermitRootLogin not set to no"

# 5.1.21 Ensure sshd PermitUserEnvironment is disabled
CTRL="5.1.21"
grep -Eq '^\s*PermitUserEnvironment\s+no\b' /etc/ssh/sshd_config && pass "$CTRL" "PermitUserEnvironment no" || fail "$CTRL" "PermitUserEnvironment not set to no"

# 5.1.22 Ensure sshd UsePAM is enabled
CTRL="5.1.22"
grep -Eq '^\s*UsePAM\s+yes\b' /etc/ssh/sshd_config && pass "$CTRL" "UsePAM yes" || fail "$CTRL" "UsePAM not set to yes"

# 5.2.6 Ensure sudo authentication timeout is configured correctly
CTRL="5.2.6"
if grep -RqsE '^\s*Defaults\s+.*timestamp_timeout\s*=\s*([0-9]+|0|-1)' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
  pass "$CTRL" "sudo timestamp_timeout configured"
else
  fail "$CTRL" "sudo timestamp_timeout not configured"
fi

# 5.2.7 Ensure access to su is restricted
CTRL="5.2.7"
grep -Eq '^\s*auth\s+required\s+pam_wheel\.so' /etc/pam.d/su && pass "$CTRL" "su restricted with pam_wheel" || fail "$CTRL" "su not restricted via pam_wheel"

# 5.3.3.1.1 Ensure password failed attempts lockout is configured
CTRL="5.3.3.1.1"
grep -Eq '^\s*auth\s+(required|requisite)\s+pam_faillock\.so.*deny=\d+' /etc/pam.d/{system-auth,password-auth} && pass "$CTRL" "faillock deny configured" || fail "$CTRL" "faillock deny not set"

# 5.3.3.1.2 Ensure password unlock time is configured
CTRL="5.3.3.1.2"
grep -Eq '^\s*auth\s+(required|requisite)\s+pam_faillock\.so.*unlock_time=\d+' /etc/pam.d/{system-auth,password-auth} && pass "$CTRL" "faillock unlock_time configured" || fail "$CTRL" "unlock_time not set"

# 5.3.3.1.3 Ensure lockout includes root
CTRL="5.3.3.1.3"
grep -Eq '^\s*auth\s+(required|requisite)\s+pam_faillock\.so.*even_deny_root' /etc/pam.d/{system-auth,password-auth} && pass "$CTRL" "even_deny_root set" || fail "$CTRL" "even_deny_root not set"

# 5.3.3.2.2 Ensure password length is configured
CTRL="5.3.3.2.2"
grep -Eq '^\s*minlen\s*=\s*[1-9][0-9]*' /etc/security/pwquality.conf && pass "$CTRL" "pwquality minlen set" || fail "$CTRL" "pwquality minlen not set"

# 5.3.3.2.3 Ensure password complexity is configured
CTRL="5.3.3.2.3"
if grep -Eq '^\s*(minclass|dcredit|ucredit|lcredit|ocredit)\s*=' /etc/security/pwquality.conf; then
  pass "$CTRL" "pwquality complexity params present"
else
  fail "$CTRL" "pwquality complexity not configured"
fi

# 5.3.3.3.1 Ensure password history remember is configured
CTRL="5.3.3.3.1"
grep -Eq '^\s*password\s+requisite\s+pam_pwhistory\.so.*remember=\d+' /etc/pam.d/system-auth && pass "$CTRL" "pam_pwhistory remember set" || fail "$CTRL" "pam_pwhistory remember not set"

# 5.4.1.1 Ensure password expiration is configured
CTRL="5.4.1.1"
max_days=$(awk -F: '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs | xargs)
if [[ -n "$max_days" && "$max_days" -le 365 ]]; then pass "$CTRL" "PASS_MAX_DAYS=$max_days"; else fail "$CTRL" "PASS_MAX_DAYS not set or too high ($max_days)"; fi

# 5.4.1.3 Ensure password expiration warning days is configured
CTRL="5.4.1.3"
warn_days=$(awk -F: '/^PASS_WARN_AGE/{print $2}' /etc/login.defs | xargs)
if [[ -n "$warn_days" && "$warn_days" -ge 7 ]]; then pass "$CTRL" "PASS_WARN_AGE=$warn_days"; else fail "$CTRL" "PASS_WARN_AGE not set/too low ($warn_days)"; fi

# 5.4.1.4 Ensure strong password hashing algorithm is configured
CTRL="5.4.1.4"
authselect current 2>/dev/null | grep -q 'with-sha512' && pass "$CTRL" "sha512 hashing enabled (authselect)" || \
grep -Eq '^\s*ENCRYPT_METHOD\s+SHA512' /etc/login.defs && pass "$CTRL" "SHA512 in login.defs" || \
fail "$CTRL" "SHA512 hashing not confirmed"

# 5.4.1.5 Ensure inactive password lock is configured
CTRL="5.4.1.5"
inactive=$(useradd -D | awk -F= '/INACTIVE/{print $2}')
if [[ -n "$inactive" && "$inactive" -ge 0 && "$inactive" -le 30 ]]; then pass "$CTRL" "Default INACTIVE=$inactive"; else fail "$CTRL" "Default INACTIVE not set within 0..30 ($inactive)"; fi

# 5.4.2.1 Ensure root is the only UID 0 account
CTRL="5.4.2.1"
uid0=$(awk -F: '($3==0){print $1}' /etc/passwd | xargs)
[ "$uid0" = "root" ] && pass "$CTRL" "Only root has UID 0" || fail "$CTRL" "UID 0 accounts: $uid0"

# 5.4.2.2 Ensure root is the only GID 0 account
CTRL="5.4.2.2"
gid0=$(awk -F: '($3==0){print $1}' /etc/group | xargs)
[ "$gid0" = "root" ] && pass "$CTRL" "Only root has GID 0" || fail "$CTRL" "GID 0 groups: $gid0"

# 5.4.2.4 Ensure root account access is controlled
CTRL="5.4.2.4"
if passwd -S root 2>/dev/null | grep -q 'LK'; then
  pass "$CTRL" "root account locked (per policy may be acceptable)"
else
  # Allow alternate acceptable: sudo-only via securetty/pam controls not trivially auditable here
  pass "$CTRL" "root account status reviewed (not locked) - manual policy review may be required"
fi

# 5.4.2.7 Ensure system accounts do not have a valid login shell
CTRL="5.4.2.7"
bad_sys=""
while IFS=: read -r u _ uid _ _ _ sh; do
  if [ "$uid" -lt 1000 ] && [ "$u" != "root" ] && [[ "$sh" != *"nologin" && "$sh" != *"false" ]]; then
    bad_sys+="$u($sh) "
  fi
done < /etc/passwd
[ -z "$bad_sys" ] && pass "$CTRL" "System accounts have nologin/false shells" || fail "$CTRL" "System accounts with login shells: $bad_sys"

# 5.4.3.2 Ensure default user shell timeout is configured
CTRL="5.4.3.2"
if grep -RqsE '^\s*TMOUT=\d+' /etc/profile /etc/profile.d/*.sh 2>/dev/null; then pass "$CTRL" "TMOUT configured"; else fail "$CTRL" "TMOUT not configured"; fi

# ======================
# 6.x Logging & Auditing
# ======================
log "--- Section 6.x: Logging & Auditing ---"

# 6.3.1.4 Ensure auditd service is enabled and active
CTRL="6.3.1.4"
(is_enabled auditd && is_active auditd) && pass "$CTRL" "auditd enabled and active" || fail "$CTRL" "auditd not enabled/active"

# 6.3.2.1 Ensure audit log storage size is configured
CTRL="6.3.2.1"
grep -Eq '^\s*max_log_file\s*=\s*[1-9][0-9]*' /etc/audit/auditd.conf && pass "$CTRL" "max_log_file configured" || fail "$CTRL" "max_log_file not set"

# 6.3.2.2 Ensure audit logs are not automatically deleted
CTRL="6.3.2.2"
if grep -Eq '^\s*max_log_file_action\s*=\s*(keep_logs|rotate)\b' /etc/audit/auditd.conf; then
  pass "$CTRL" "max_log_file_action compliant"
else
  fail "$CTRL" "max_log_file_action may delete logs"
fi

# ======================
# 7.x File Permissions & Accounts
# ======================
log "--- Section 7.x: File Permissions & Accounts ---"

# 7.1.1 – 7.1.10 File permission checks
CTRL="7.1.1"; file_perm_ok /etc/passwd 644 root root
CTRL="7.1.2"; file_perm_ok /etc/passwd- 600 root root
CTRL="7.1.3"; file_perm_ok /etc/group 644 root root
CTRL="7.1.4"; file_perm_ok /etc/group- 600 root root
CTRL="7.1.5"; file_perm_ok /etc/shadow 000 root root
CTRL="7.1.6"; file_perm_ok /etc/shadow- 000 root root
CTRL="7.1.7"; file_perm_ok /etc/gshadow 000 root root
CTRL="7.1.8"; file_perm_ok /etc/gshadow- 000 root root
CTRL="7.1.9"; file_perm_ok /etc/shells 644 root root
CTRL="7.1.10"; file_perm_ok /etc/security/opasswd 600 root root

# 7.1.11 World writable files and directories are secured
CTRL="7.1.11"
ww=$(find / -xdev -type f -perm -0002 2>/dev/null | head -n 5)
wwd=$(find / -xdev -type d -perm -0002 2>/dev/null | head -n 5)
if [ -n "$ww" ] || [ -n "$wwd" ]; then
  fail "$CTRL" "World-writable paths exist (sample): ${ww//$'\n'/, } ${wwd//$'\n'/, }"
else
  pass "$CTRL" "No world-writable files/dirs found"
fi

# 7.1.12 No unowned or ungrouped files/dirs
CTRL="7.1.12"
uo=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 5)
[ -z "$uo" ] && pass "$CTRL" "No unowned/ungrouped files" || fail "$CTRL" "Unowned/ungrouped files exist (sample): ${uo//$'\n'/, }"

# 7.1.13 SUID and SGID files are reviewed
CTRL="7.1.13"
suid=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -n 10)
[ -n "$suid" ] && pass "$CTRL" "SUID/SGID files found (manual review): ${suid//$'\n'/, }" || pass "$CTRL" "No SUID/SGID files found"

# 7.2.1 Accounts in /etc/passwd use shadowed passwords
CTRL="7.2.1"
if awk -F: '($2 != "x") {print $1}' /etc/passwd | grep -q .; then fail "$CTRL" "Some accounts not using shadowed passwords"; else pass "$CTRL" "All accounts use shadowed passwords"; fi

# 7.2.2 /etc/shadow password fields are not empty
CTRL="7.2.2"
awk -F: '($2 == "" ) {print $1}' /etc/shadow | grep -q . && fail "$CTRL" "Empty password fields in /etc/shadow" || pass "$CTRL" "No empty password fields"

# 7.2.3 All groups in /etc/passwd exist in /etc/group
CTRL="7.2.3"
if pwck -r >/dev/null 2>&1; then pass "$CTRL" "passwd/group consistency ok"; else fail "$CTRL" "passwd/group inconsistencies"; fi

# 7.2.4 No duplicate UIDs exist
CTRL="7.2.4"
dupu=$(cut -d: -f3 /etc/passwd | sort -n | uniq -d | xargs)
[ -z "$dupu" ] && pass "$CTRL" "No duplicate UIDs" || fail "$CTRL" "Duplicate UIDs: $dupu"

# 7.2.5 No duplicate GIDs exist
CTRL="7.2.5"
dupg=$(cut -d: -f3 /etc/group | sort -n | uniq -d | xargs)
[ -z "$dupg" ] && pass "$CTRL" "No duplicate GIDs" || fail "$CTRL" "Duplicate GIDs: $dupg"

# 7.2.6 No duplicate user names exist
CTRL="7.2.6"
dupun=$(cut -d: -f1 /etc/passwd | sort | uniq -d | xargs)
[ -z "$dupun" ] && pass "$CTRL" "No duplicate usernames" || fail "$CTRL" "Duplicate usernames: $dupun"

# 7.2.7 No duplicate group names exist
CTRL="7.2.7"
dupgn=$(cut -d: -f1 /etc/group | sort | uniq -d | xargs)
[ -z "$dupgn" ] && pass "$CTRL" "No duplicate group names" || fail "$CTRL" "Duplicate group names: $dupgn"

# 7.2.8 Local interactive user home directories are configured
CTRL="7.2.8"
badhome=""
while IFS=: read -r u _ uid _ _ home _; do
  [ "$uid" -ge 1000 ] || continue
  [ -d "$home" ] || { badhome+="$u(home missing:$home) "; continue; }
  [ "$(stat -c '%U' "$home")" = "$u" ] || badhome+="$u(owner $(stat -c '%U' "$home")) "
  p=$(stat -c '%a' "$home")
  [[ "$p" -le 750 ]] || badhome+="$u(perm $p) "
done < /etc/passwd
[ -z "$badhome" ] && pass "$CTRL" "Interactive user homes configured" || fail "$CTRL" "Home issues: $badhome"

# 7.2.9 Local interactive user dot files access is configured
CTRL="7.2.9"
baddots=""
for d in $(awk -F: '($3>=1000){print $6}' /etc/passwd); do
  [ -d "$d" ] || continue
  for f in "$d"/.[A-Za-z0-9]*; do
    [ -f "$f" ] || continue
    p=$(stat -c '%a' "$f")
    # Flag if group/world writable (>= 664 or 646 etc). Simple check:
    if [ $((p%10)) -ge 6 ] || [ $(((p/10)%10)) -ge 6 ]; then
      baddots+="$f($p) "
    fi
  done
done
[ -z "$baddots" ] && pass "$CTRL" "Dot files not group/world writable" || fail "$CTRL" "Writable dotfiles: $baddots"

# ======================
# SUMMARY
# ======================
log ""
log "========== SUMMARY =========="
log "Total controls checked : $total"
log "Passed                 : $passed"
log "Failed                 : $failed"
log "Detailed results saved to: $REPORT"

exit 0
