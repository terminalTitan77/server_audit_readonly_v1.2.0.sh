#!/bin/bash
# Read-only Linux server audit, version 1.3.0, 2026-10-04.
# Bash 4+ and existing Linux utilities only. No Python/PHP scripts are executed.
# No installations, upgrades, configuration/service changes or scans.
# Output is stdout; redirect it only if YOU want to create a report file.
# Normal OS read side effects (atime, audit logs, DNS/HTTP logs) may still occur.
# This is an evidence collector, not a penetration test or a compliance guarantee.
# Sources and the limits of each check are documented by --help.
#
# 1.3.0 changes:
#  - No RECOMMENDATION is printed for healthy statuses (ACTIVE/GOOD/Configured/...).
#  - OPERATING SYSTEM ignores kernel package updates when KernelCare has a patch applied.
#  - MALWARE SCAN / ROOTKIT CHECK read each scanner's own report section and accept
#    "Rootkits checked : N" + "Possible rootkits: N" summaries.
#  - SSH ROOT ACCESS uses the effective config for root (sshd -T -C) and only flags
#    files that actually permit root login.
#  - PHP FUNCTIONS SECURITY evaluates the PHP handlers actually in use (cPanel userdata)
#    instead of every INI file on disk.
#  - JetBackup (read-only listBackupJobs) is used as evidence for daily/weekly/monthly.
#  - cPanel LOCAL BACKUP accepts a recent Success log when KEEPLOCAL=0 (staging backup).

if (( BASH_VERSINFO[0] < 4 )); then
    printf 'ERROR: Bash 4 or newer is required.\n' >&2; exit 2
fi
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -o pipefail
shopt -s nullglob

usage() {
cat <<'HELP'
READ-ONLY LINUX SERVER AUDIT 1.3.0

Run: sudo bash server_audit_readonly.sh [options]

  --offline                  No DNS or vendor HTTPS requests
  --no-package-check         Skip DNF/YUM/APT update-availability queries
  --ip IPv4                  Public/mail IPv4 to audit (use for NAT/multiple IPs)
  --http-url URL              Optional HTTP(S) HEAD check; repeat for virtual hosts
  --webroot /absolute/path    CMS discovery root; repeat (replaces default roots)
  --backup-dir /abs/path      Backup artifact root; repeat (replaces defaults)
  --expected-backup-bytes N   Administrator-supplied minimum acceptable backup size
  --report /abs/path          Existing scan report (default /root/scripts/malware-scan-report.txt)
  --max-report-days N         Maximum report age, default 20
  --backup-max-days N         Recent backup threshold, default 2
  --cpu-max N                CPU busy/load threshold percent, default 85
  --ram-max N                RAM used threshold percent, default 85
  --disk-max N               Disk/inode used threshold percent, default 85
  --queue-max N              Mail queue message threshold, default 100
  --baseline /abs/file.tsv    Optional reviewed version/lifecycle baseline (below)
  --help                     This guide

No package installation/upgrade, configuration change, service start/stop/reload,
firewall modification, malware/rootkit scan, backup
execution, CMS execution, eval or sourced configuration is performed.
Existing utilities are used only if available. stdout is the only
report destination. Missing tools are not installed. timeout is required to
bound external commands. Bash 4.2 (CentOS 7) is supported.

Read activity can update filesystem atime and generate normal system/audit logs;
Bash or read-only utilities may use internal transient files/locks.
DNS requests disclose the queried IP to the resolver and DNSBL provider. HTTP
HEAD requests happen only for explicitly supplied --http-url values. --offline
disables both. No external IP-discovery service or geolocation API is used.

OUTPUT: 38 checks, each with exactly ITEM, STATUS, ISSUE, RECOMMENDATION.
Evidence is included in ISSUE. UNVERIFIED is an issue qualifier, not a pass.
RECOMMENDATION is left empty when the STATUS is healthy (ACTIVE, GOOD, Configured,
All updates installed, Support Period Active, Recent Backups Available, Expected size).
Section B/D: NA means absent OR unable to verify; ISSUE distinguishes them.
Section C: NOT GOOD includes inability to confirm health; read ISSUE.
E2 reboot procedure has all three value fields blank, as requested.
E4/E5 use MALWARE SCAN NEEDED when the report is absent, stale or inconclusive.
F2 remains NA/manual. F7 uses NA when size expectations are unknown; it never
labels an unverified size Expected size or Too small.

KernelCare: when kcarectl --info reports "kpatch-state: patch is applied", kernel
package candidates are not counted as pending OS updates (the live patch covers
the running kernel). Other OS package candidates are still reported.

Firewall A1 intentionally follows the requested installed=ACTIVE definition.
Its ISSUE separately says whether enforcement could be confirmed. Running
Fail2Ban/LFD, installed scanners or configuration text alone are not proof of
full protection. WAF and PHP-FPM/vhost overrides generally need manual review.

DNF/YUM use check-update queries only; no install/upgrade transaction is run.
When online, repository metadata/cache may be refreshed by the package manager and
normal package-tool logs/locks/cache files may be written. --offline uses cache-only
RPM queries where possible. --no-package-check skips package availability queries.
Debian candidates use apt-cache with disk caches disabled. Successful results
describe enabled/configured repository coverage, not necessarily latest upstream
software or a newer major operating-system migration.
cPanel tier, WordPress, PHP and supported OS reference metadata are fetched with
HTTPS unless --offline. cPanel also uses local updatenow --check/--dry-run only;
those query/dry-run commands may write normal cPanel logs/locks but no --upcp or
update transaction is invoked. Public metadata requests contain no credentials.
No retrieved code is executed. A reviewed --baseline can override references.

BASELINE: tab-separated plain data, never executed. One row per exact component:
key<TAB>latest-version<TAB>support-end-YYYY-MM-DD<TAB>reviewed-YYYY-MM-DD<TAB>source
Use '-' for an unknown latest version or support end. Examples of keys:
os:centos:7.9.2009       (OS latest-version must be '-', lifecycle only)
php:8.2                (latest patch for that branch; excludes distro backports)
cms:wordpress:6.8       (branch of detected CMS version)
cms:drupal:10.5
panel:cpanel:11.134.0.1 (use the EXACT detected panel version; this is an example)
pkg:nginx              (EXACT package version-release/epoch printed by inventory)
pkg:openssl
For pkg keys on RPM, use the printed epoch:version-release value. Package rows
cover that package only, not the entire OS/stack. Support rows must describe the
installed branch/package, including vendor backport coverage. reviewed dates
must be within 30 days; only a small numeric dotted-version comparator is used
for PHP/CMS. Package versions must match exactly to pass. Verify baseline trust
and release channel yourself. Baseline content is never fetched automatically.

Built-in lifecycle facts: CloudLinux 7/8/9/10 vendor support dates,
CentOS Linux 7/8 EOL, Ubuntu LTS standard-support
months, AlmaLinux/Rocky 8.10 and reviewed 9.8/10.2 releases, PHP upstream branch
security end dates through 8.5. Vendor/paid support needs separate verification.
Unknown distributions/branches are NA, not guessed to be supported.
Sources (reviewed 2026-10-02):
https://www.redhat.com/en/topics/linux/centos-linux-eol
https://www.php.net/supported-versions.php
https://www.php.net/eol.php
https://www.spamhaus.org/faqs/dnsbl-usage/
https://ubuntu.com/about/release-cycle
https://wiki.almalinux.org/release-notes/
https://wiki.rockylinux.org/rocky/version/
https://www.spamcop.net/fom-serve/cache/291.html
https://docs.cloudlinux.com/introduction/
https://docs.cpanel.net/knowledge-base/third-party/third-party-software-end-of-life-policy/
https://docs.cpanel.net/knowledge-base/cpanel-product/product-versions-and-the-release-process/
https://wordpress.org/documentation/article/supported-versions/
https://magazine.joomla.org/issues/2021/august-2021/joomla-3-10-end-of-support-handling
https://dnf.readthedocs.io/en/stable/command_ref.html

CMS discovery: bounded filename search, max depth 12, one filesystem per root,
up to 45 seconds per root. Default roots /var/www /home /srv/www
/usr/share/nginx/html. Add roots for other mounts/containers. Only version
files for WordPress, Drupal, Joomla and Moodle are read; no PHP/WP CLI is run.
Plugins, themes, containers, custom document roots and remote services require
additional review. Plesk is a hosting panel, not a CMS.

SCAN REPORTS: mtime within the last 20 days (not older than 20 days).
The report may contain a "Malware Scan Report" section followed by a
"Rootkit Scan Report" section; each scanner is evaluated from its own section
(if there is no "Rootkit Scan Report" header the whole file is used for both).
Recognized summary lines are listed below. The audit accepts a clean result only
when a completion summary and a clean count both exist for the relevant scanner.
It does not assume a recently touched file is proof that a scan was completed.
ClamAV: SCAN SUMMARY plus 'Scanned files: N' (N>0) and 'Infected files: N'.
rkhunter: 'System checks summary' plus 'Possible rootkits: N' and 'Files checked: N' (N>0).
Also accepted for rootkits: 'Rootkits checked : N' (N>0) with 'Possible rootkits: N'.
Also supports these anchored audit-summary fields in existing reports:
MALWARE_SCAN_COMPLETED: YES
MALWARE_FILES_SCANNED: <positive integer>
MALWARE_INFECTED_FILES: <nonnegative integer>
ROOTKIT_SCAN_COMPLETED: YES
ROOTKIT_CHECKS_PERFORMED: <positive integer>
ROOTKIT_FOUND: <nonnegative integer>
Do not append these markers without reviewing the actual scan outcome/scope.
Error/warning markers inside a scanner's own section make a clean summary
inconclusive. Findings take priority.
Report mtime cannot authenticate report contents, coverage or completion time.
CMS inventory/version lines in a fresh report are informational only.

SSH: PermitRootLogin is read from the effective configuration evaluated for the
root user (sshd -T -C user=root,host=localhost,addr=127.0.0.1). Configured requires
PermitRootLogin=no and no config file line that sets it to a permissive value.

PHP functions: on cPanel the PHP handlers in use are read from
/var/cpanel/userdata/*/* (phpversion:) plus the EasyApache default. Each in-use
INI must disable exec, shell_exec, system, passthru, popen and proc_open.
INI files not matched to an in-use handler are listed for review but do not fail
the check. CloudLinux PHP Selector per-user choices are not read.

Backups: cPanel /var/cpanel/backups/config, standard cron/timer candidates
and archive metadata are inspected. cPanel's configured BACKUPDIR is included.
JetBackup (5) jobs are listed read-only with jetbackup5api listBackupJobs; a
daily/weekly/monthly job is recognised from the job NAME only (schedule/enabled
state is not parsed) and is labelled as such in ISSUE.
Scheduling evidence is not successful backup evidence. Default artifact roots:
/backup /backups /var/backups. Set --backup-dir for the real destination.
Archive mtime/size are indicators only; no archive is unpacked or restored.
Backup files outside search scope, snapshots, encrypted repositories and remote
destinations require manual review. No remote backup repository is opened.

Health thresholds are audit policy defaults, not universal capacity rules.
CPU uses two /proc/stat samples over 2 seconds plus load/core. RAM prefers
MemAvailable. Disk includes inode pressure. HTTP service uptime is current
process uptime, not historical availability. Mail age is not inferred from count.
Exit 0: audit completed (can include failures/unverified checks).
Exit 2: invalid options, missing prerequisites, or not run as root.
HELP
}

OFFLINE=0; NO_PACKAGE_CHECK=0; TARGET_IP=''; SCAN_REPORT=/root/scripts/malware-scan-report.txt
MAX_REPORT_DAYS=20; BACKUP_MAX_DAYS=2; CPU_MAX=85; RAM_MAX=85; DISK_MAX=85
QUEUE_MAX=100; EXPECTED_BACKUP_BYTES=0; BASELINE=''
WEBROOTS=(); BACKUP_DIRS=(); HTTP_URLS=()
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
need_value() { (( $# >= 2 )) && [[ -n $2 ]] || die "Missing value for $1"; }
uint() { [[ $1 =~ ^[0-9]{1,12}$ ]] && [[ $1 == 0 || $1 != 0* ]]; }
while (( $# )); do
    case "$1" in
        --help|-h) usage; exit 0;;
        --offline) OFFLINE=1; shift;;
        --no-package-check) NO_PACKAGE_CHECK=1; shift;;
        --ip) need_value "$@"; TARGET_IP=$2; shift 2;;
        --http-url) need_value "$@"; [[ $2 =~ ^https?://[^[:space:]]+$ ]] || die 'Invalid HTTP URL'; HTTP_URLS+=("$2"); shift 2;;
        --webroot) need_value "$@"; [[ $2 == /* && -d $2 && ! -L $2 ]] || die 'Webroot must be an existing absolute, non-symlink directory'; WEBROOTS+=("$2"); shift 2;;
        --backup-dir) need_value "$@"; [[ $2 == /* && -d $2 && ! -L $2 ]] || die 'Backup root must be an existing absolute, non-symlink directory'; BACKUP_DIRS+=("$2"); shift 2;;
        --report) need_value "$@"; [[ $2 == /* ]] || die 'Report path must be absolute'; SCAN_REPORT=$2; shift 2;;
        --baseline) need_value "$@"; [[ $2 == /* && -f $2 && -r $2 && ! -L $2 ]] || die 'Baseline must be a readable absolute regular file, not a symlink'; BASELINE=$2; shift 2;;
        --max-report-days|--backup-max-days|--cpu-max|--ram-max|--disk-max|--queue-max|--expected-backup-bytes)
            need_value "$@"; uint "$2" || die "Invalid integer for $1"
            case "$1" in
                --max-report-days) MAX_REPORT_DAYS=$2;;
                --backup-max-days) BACKUP_MAX_DAYS=$2;;
                --cpu-max) CPU_MAX=$2;; --ram-max) RAM_MAX=$2;; --disk-max) DISK_MAX=$2;;
                --queue-max) QUEUE_MAX=$2;; --expected-backup-bytes) EXPECTED_BACKUP_BYTES=$2;;
            esac; shift 2;;
        *) die "Unknown option: $1 (use --help)";;
    esac
done
(( EUID == 0 )) || die 'Run as root for protected configuration and password-age reads.'
for dep in awk sed grep find stat date timeout sort head tail tr cut cat sleep; do
    command -v "$dep" >/dev/null 2>&1 || die "Required existing utility missing: $dep (nothing installed)"
done
for pct in "$CPU_MAX" "$RAM_MAX" "$DISK_MAX"; do (( pct > 0 && pct <= 100 )) || die 'Percent thresholds must be 1..100'; done
(( MAX_REPORT_DAYS <= 3650 && BACKUP_MAX_DAYS <= 3650 )) || die 'Day thresholds must be <=3650'
(( ${#WEBROOTS[@]} )) || WEBROOTS=(/var/www /home /srv/www /usr/share/nginx/html)
(( ${#BACKUP_DIRS[@]} )) || BACKUP_DIRS=(/backup /backups /var/backups)
NOW=$(date +%s); TODAY=$(date -u +%F)
have() { command -v "$1" >/dev/null 2>&1; }
run() { timeout -k 2s 15s "$@" 2>/dev/null; }
flat() { tr '\n\r\t' '   ' | tr -cd '\40-\176' | cut -c 1-6000; }
emit() {
    local recommendation=$4
    # No recommendation is written for healthy statuses.
    case "$2" in
        ACTIVE|GOOD|Configured|'All updates installed'|'Support Period Active'|'Recent Backups Available'|'Expected size') recommendation='';;
    esac
    [[ -n $recommendation ]] && recommendation=$(client_recommendation "$1" "$2" "$recommendation")
    printf '[ITEM] : %s\n[STATUS] : %s\n[ISSUE] : %s\n[RECOMMENDATION] : %s\n\n' \
        "$1" "$2" "$(printf '%s' "$3" | flat)" "$(printf '%s' "$recommendation" | flat)"
}
section() { AUDIT_SECTION=${1%% *}; printf '\nSECTION %s\n%s\n\n' "$1" '============================================================'; }
client_recommendation() {
    local item=$1 status=$2
    case "${AUDIT_SECTION:-}:$item" in
        B:'CONTROL PANEL')
            if [[ ${PANEL:-} == cpanel && ${PANEL_VER:-} == 11.110.* && ( ${OS_ID:-} == cloudlinux || ${OS_NAME:-} == CloudLinux* ) && ${OS_VERSION:-} == 7* ]]; then
                printf 'We recommend migrating to a new server with a current supported operating system. cPanel & WHM 110 is the last cPanel branch compatible with CloudLinux 7, so a newer cPanel release requires an OS migration; plan compatibility testing, backups and an approved off-peak migration window.'
            elif [[ $status == 'All updates installed' ]]; then printf 'Please continue scheduled maintenance. We can assist with monitoring vendor updates and validating application compatibility.'
            elif [[ $status == NA ]]; then printf 'Please confirm the applicable vendor subscription/release channel and approve further verification where indicated. We can assist with validating update availability and planning any required work during an agreed off-peak window.'
            else printf 'Please approve an off-peak maintenance window for the identified updates. We can assist with compatibility checks, backups, implementation and post-update validation; application changes will be coordinated with your developer team.'; fi;;
        B:'OPERATING SYSTEM')
            if [[ ${OS_STANDARD_EOL:-0} == 1 ]]; then
                printf 'We recommend migrating to a new server with a current supported operating system. The installed OS branch is past standard support; any ELS/extended-support entitlement should be treated only as temporary coverage while migration is planned.'
            elif [[ $status == 'All updates installed' ]]; then printf 'Please continue scheduled maintenance. We can assist with monitoring vendor updates and validating application compatibility.'
            elif [[ $status == NA ]]; then printf 'Please confirm the applicable vendor subscription/release channel and approve further verification where indicated. We can assist with validating update availability and planning any required work during an agreed off-peak window.'
            else printf 'Please approve an off-peak maintenance window for the identified updates or version migration. We can assist with compatibility checks, backups, implementation and post-update validation; application changes will be coordinated with your developer team.'; fi;;
        B:*)
            if [[ $status == 'All updates installed' ]]; then printf 'Please continue scheduled maintenance. We can assist with monitoring vendor updates and validating application compatibility.'
            elif [[ $status == NA ]]; then printf 'Please confirm the applicable vendor subscription/release channel and approve further verification where indicated. We can assist with validating update availability and planning any required work during an agreed off-peak window.'
            else printf 'Please approve an off-peak maintenance window for the identified updates or version migration. We can assist with compatibility checks, backups, implementation and post-update validation; application changes will be coordinated with your developer team.'; fi;;
        D:'CONTROL PANEL')
            if [[ ${PANEL:-} == cpanel && ${PANEL_VER:-} == 11.110.* && ( ${OS_ID:-} == cloudlinux || ${OS_NAME:-} == CloudLinux* ) && ${OS_VERSION:-} == 7* ]]; then
                printf 'We recommend migrating to a new server with a current supported operating system. cPanel & WHM 110 is the last cPanel branch compatible with CloudLinux 7; validate any temporary ELS coverage separately and plan the server migration.'
            elif [[ $status == 'Support Period Active' ]]; then printf 'Please maintain the applicable vendor support subscription and patching schedule. We can assist with tracking support dates and planning updates.'
            elif [[ $status == 'End Of Life Period' ]]; then printf 'Please approve a supported-version migration plan and an off-peak maintenance window. We can assist with validating extended-support coverage, testing compatibility and coordinating the migration with your developer team.'
            else printf 'Please confirm any extended-support contract or vendor support arrangement. We can assist with validating coverage and preparing an off-peak migration plan if needed.'; fi;;
        D:*)
            if [[ $status == 'Support Period Active' ]]; then printf 'Please maintain the applicable vendor support subscription and patching schedule. We can assist with tracking support dates and planning updates.'
            elif [[ $status == 'End Of Life Period' ]]; then printf 'Please approve a supported-version migration plan and an off-peak maintenance window. We can assist with validating extended-support coverage, testing compatibility and coordinating the migration with your developer team.'
            else printf 'Please confirm any extended-support contract or vendor support arrangement. We can assist with validating coverage and preparing an off-peak migration plan if needed.'; fi;;
        A:'SYSTEM FIREWALL') printf 'Please confirm the required public services and trusted access IPs. We can assist with reviewing effective IPv4/IPv6 protection and correcting any confirmed policy gaps after approval.';;
        A:'MALWARE SCANNER') printf 'Please confirm your preferred protection policy and approve any required scanner setup or scheduled scan. We can assist with verifying service health, licensing, signatures and scan coverage; no scan or cleanup was performed by this audit.';;
        A:'ROOTKIT SCANNER')
            if [[ $status == ACTIVE ]]; then printf 'Please verify that rkhunter/chkrootkit are scheduled as required and that recent reports are reviewed. The audit only confirms installed tools; it does not execute a rootkit scan.'
            else printf 'Please confirm your preferred rootkit-scanning policy and approve any required scanner setup. No rootkit scan or cleanup was performed by this audit.'; fi;;
        A:'FAILED LOGIN DETETCTION') printf 'Please confirm authorized administrative IPs and acceptable login-attempt limits. We can assist with reviewing login protection and adjusting exclusions or thresholds after approval.';;
        A:'WEB APP FIREWALL') printf 'Please review any WAF-disabled websites or exclusions with your developer team. We can assist with validating rules and enabling appropriate protection after compatibility testing and approval.';;
        C:'SERVER UPTIME'|C:'HTTP UPTIME') printf 'Please confirm any planned restart or maintenance activity. We can assist with reviewing service history and external uptime monitoring if the reported result is unexpected.';;
        C:'CPU USAGE'|C:'RAM USAGE') printf 'Please notify us of any performance symptoms or planned workload increases. We can assist with reviewing sustained resource usage and proposing tuning or capacity changes when required.';;
        C:'DISC SPACE USAGE') printf 'Please confirm retention requirements before any cleanup. We can assist with investigating growth and proposing cleanup or capacity changes; application files will not be removed without your developer team approval.';;
        C:'EMAIL QUEUE') printf 'Please confirm any expected bulk-mail activity or reported delivery delays. We can assist with reviewing deferred messages and resolving delivery issues without deleting mail without approval.';;
        C:'IP REPUTATION') printf 'Please confirm the server public IP and actual outbound mail IP. We can assist with validating reputation and investigating any confirmed listings before requesting delisting.';;
        E:'/tmp SECURITY')
            if [[ $status == Configured ]]; then printf 'Please retain the current /tmp protections and include them in change reviews. We can assist with validating continued application compatibility.'
            else printf 'Please approve a review of the missing or unverified /tmp protections with your application owners. We can assist with testing and applying suitable mount options during an agreed maintenance window.'; fi;;
        E:'IP RDNS') printf 'Please confirm the intended mail hostname and outbound IP. We can assist with arranging any required PTR change through your IP provider and validating forward/reverse DNS.';;
        E:'MALWARE SCAN'|E:'ROOTKIT CHECK')
            if [[ $status == Configured ]]; then printf 'Please continue the scheduled scan/report review cycle and retain recent completed reports. No cleanup is indicated by the reviewed zero-finding summary, subject to the report scope and authenticity limits.'
            elif [[ $status == 'Not Configured' ]]; then printf 'Please approve investigation of the reported findings. We can assist with reviewing scope and evidence; suspicious files will not be removed without approval.'
            else printf 'Please approve a scan if a recent complete report is unavailable or inconclusive. We can assist with reviewing scope and results; suspicious files will not be removed without approval.'; fi;;
        E:'SSH ROOT ACCESS SECURITY') printf 'Please approve SSH access hardening where required. We can assist with first validating a named sudo account and recovery access, then safely restricting direct root login.';;
        E:'PHP FUNCTIONS SECURITY') printf 'Please ask your developer team to confirm which PHP functions the applications require. We can assist with applying appropriate restrictions after compatibility testing and approval.';;
        E:'ROOT PASSWORD HEALTH') printf 'Please arrange an approved root-password rotation if the 90-day policy is not met. We can assist through the agreed secure credential process and verify access afterwards.';;
        F:'REMOTE BACKUP') printf 'Please confirm your off-server backup destination and retention requirements. We can assist with verifying successful transfers and restore capability.';;
        F:'SIZE OF LAST BACKUP') printf 'Please confirm the expected backup size or provide a known-good backup baseline. We can assist with comparing backup sets and validating restoration; size alone cannot prove integrity.';;
        F:*) printf 'Please confirm the required backup scope, frequency and retention. We can assist with verifying configuration, investigating missing recent backups and testing recovery; any configuration changes require your approval.';;
        *) printf 'Please review the reported finding. We can assist with verifying it and implementing any agreed corrective action after approval.';;
    esac
}
active() {
    local name
    for name in "$@"; do
        if have systemctl && [[ -d /run/systemd/system ]] && run systemctl is-active --quiet "$name"; then return 0; fi
        if have pgrep && run pgrep -x "$name" >/dev/null; then return 0; fi
    done
    return 1
}
os_value() { awk -F= -v k="$1" '$1==k {v=substr($0,index($0,"=")+1); gsub(/^"|"$/,"",v); print v; exit}' /etc/os-release 2>/dev/null; }
OS_ID=$(os_value ID); OS_VERSION=$(os_value VERSION_ID); OS_NAME=$(os_value PRETTY_NAME)
[[ -n $OS_NAME ]] || OS_NAME=$(head -c 300 /etc/redhat-release 2>/dev/null)
KERNEL=$(run uname -r); HOST=$(run hostname)
PKGS=''; PKG_KIND=unknown; PKG_DIAGNOSTIC=''; PKG_QUERY_OK=0
query_rpm_inventory() {
    local raw rc
    raw=$(timeout -k 2s 60s rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\n' 2>&1); rc=$?
    if (( rc==0 )); then
        PKGS=$(printf '%s\n' "$raw" | awk -F '\t' 'NF==3 && $1 ~ /^[A-Za-z0-9_+.-]+$/ {e=$2;if(e=="(none)")e=0;if(e ~ /^[0-9]+$/)print $1 "\t" e ":" $3}')
        [[ -n $PKGS ]] && { PKG_KIND=rpm; PKG_QUERY_OK=1; return 0; }
    fi
    PKG_DIAGNOSTIC+="RPM inventory failed/empty (exit=$rc); $(printf '%s' "$raw" | head -n 2 | flat); "; return 1
}
query_deb_inventory() {
    local raw rc
    raw=$(timeout -k 2s 60s dpkg-query -W '-f=${db:Status-Status}\t${binary:Package}\t${Version}\n' 2>&1); rc=$?
    if (( rc==0 )); then
        PKGS=$(printf '%s\n' "$raw" | awk -F '\t' '$1=="installed" {print $2 "\t" $3}')
        [[ -n $PKGS ]] && { PKG_KIND=deb; PKG_QUERY_OK=1; return 0; }
    fi
    PKG_DIAGNOSTIC+="Debian inventory failed/empty (exit=$rc); "; return 1
}
# An auxiliary dpkg-query on cPanel must not suppress the real RPM database.
case "$OS_ID" in
    debian|ubuntu|linuxmint) have dpkg-query && query_deb_inventory; [[ $PKG_QUERY_OK == 1 ]] || { have rpm && query_rpm_inventory; };;
    *) have rpm && query_rpm_inventory; [[ $PKG_QUERY_OK == 1 ]] || { have dpkg-query && query_deb_inventory; };;
esac
PKG_DIAGNOSTIC+="Selected=$PKG_KIND; installed package rows=$(printf '%s\n' "$PKGS" | awk 'NF{n++}END{print n+0}')."
pkgmatch() { printf '%s\n' "$PKGS" | awk -F '\t' -v re="$1" '$1 ~ re {print}'; }

# Baselines are data, not executable shell. Expired/invalid rows never authorize a pass.
declare -A BL_LATEST BL_EOL BL_SOURCE
BASELINE_NOTE='No reviewed external baseline supplied.'
if [[ -n $BASELINE ]]; then
    accepted=0; rejected=0
    while IFS=$'\t' read -r key latest eol reviewed source extra; do
        [[ -z $key || $key == \#* ]] && continue
        rd=$(date -u -d "$reviewed" +%s 2>/dev/null)
        if [[ ! $reviewed =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ || ! $rd =~ ^[0-9]+$ ]] ||
           (( rd > NOW || NOW-rd > 30*86400 )) || [[ -z $source || -n $extra ]] ||
           [[ ! $key =~ ^(os|php|cms|panel|pkg):[a-zA-Z0-9_.:+-]+$ ]] ||
           [[ ! $latest =~ ^[-a-zA-Z0-9_.:+~]+$ ]] ||
           [[ $eol != - && ! $eol =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            ((rejected++)); continue
        fi
        if [[ $eol != - ]] && ! date -u -d "$eol" +%s >/dev/null 2>&1; then ((rejected++)); continue; fi
        BL_LATEST["$key"]=$latest; BL_EOL["$key"]=$eol; BL_SOURCE["$key"]=$source; ((accepted++))
    done < "$BASELINE"
    BASELINE_NOTE="Reviewed baseline rows accepted=$accepted rejected=$rejected (maximum review age 30 days)."
fi

public_v4() {
    local a b c d tail
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d tail <<< "$1"
    a=$((10#$a)); b=$((10#$b)); c=$((10#$c)); d=$((10#$d))
    (( a<=255 && b<=255 && c<=255 && d<=255 )) || return 1
    (( a>0 && a<224 && a!=10 && a!=127 )) || return 1
    (( a==169 && b==254 || a==172 && b>=16 && b<=31 || a==192 && b==168 || a==100 && b>=64 && b<=127 )) && return 1
    (( a==192 && b==0 || a==192 && b==2 || a==198 && (b==18 || b==19 || b==51) || a==203 && b==0 && c==113 )) && return 1
    return 0
}
if [[ -n $TARGET_IP ]]; then public_v4 "$TARGET_IP" || die '--ip must be a public IPv4 address'; fi
ips=()
if have ip; then
    while read -r ipval; do public_v4 "$ipval" && ips+=("$ipval"); done < <(run ip -o -4 addr show scope global | awk '{split($4,a,"/");print a[1]}' | sort -u)
fi
IP_NOTE='Explicit IP supplied; confirm this is also the mail egress IP.'; IP_MISMATCH=0
if [[ -n $TARGET_IP ]] && ! printf '%s\n' "${ips[@]}" | grep -Fxq "$TARGET_IP"; then
    IP_NOTE='WARNING: explicit IP is not assigned to a detected public interface. Confirm NAT/mail egress ownership; this may be the wrong server IP.'; IP_MISMATCH=1
fi
if [[ -z $TARGET_IP ]]; then
    mainip=$(awk '$1=="ADDR" && $2 ~ /^[0-9.]+$/ {print $2;exit}' /etc/wwwacct.conf 2>/dev/null)
    if [[ -n $mainip ]] && public_v4 "$mainip" && printf '%s\n' "${ips[@]}" | grep -Fxq "$mainip"; then
        TARGET_IP=$mainip; IP_NOTE='cPanel main IP matched to a local public interface; mail egress still needs confirmation.'
    elif (( ${#ips[@]} == 1 )); then TARGET_IP=${ips[0]}; IP_NOTE='Single local public interface IP selected; NAT/mail egress still needs confirmation.'
    else IP_NOTE="UNVERIFIED: found ${#ips[@]} public interface IPv4 addresses; provide --ip for the actual server/mail IP."; fi
fi

# Report summaries: no full scan or arbitrary report commands are executed.
REPORT_TEXT=''; REPORT_FRESH=0; REPORT_INFO='Report missing, unreadable, not regular, or a symlink.'
MALWARE_TEXT=''; ROOTKIT_TEXT=''
if [[ -f $SCAN_REPORT && -r $SCAN_REPORT && ! -L $SCAN_REPORT ]]; then
    mtime=$(stat -c %Y -- "$SCAN_REPORT" 2>/dev/null); rsize=$(stat -c %s -- "$SCAN_REPORT" 2>/dev/null)
    if [[ $mtime =~ ^[0-9]+$ && $rsize =~ ^[0-9]+$ ]]; then
        age=$((NOW-mtime))
        REPORT_INFO="Report age=$((age/86400)) days; bytes=$rsize."
        if (( age >= 0 && age <= MAX_REPORT_DAYS*86400 && rsize > 0 && rsize <= 20971520 )); then
            REPORT_TEXT=$(run cat -- "$SCAN_REPORT"); REPORT_FRESH=1
        else REPORT_INFO+=' Rejected: stale/future/empty or larger than 20 MiB.'; fi
    fi
fi
summary_num() {
    printf '%s\n' "$2" | awk -v re="$1" 'BEGIN{re=tolower(re);n=-1} tolower($0) ~ re {v=$0;sub(/^[^:]*:[[:space:]]*/,"",v);sub(/[[:space:]]*$/,"",v);if(v ~ /^[0-9]+$/ && v+0>n)n=v+0} END{if(n>=0)print n}'
}
text_has() { printf '%s\n' "$2" | grep -Eiq -- "$1"; }
MALWARE_RESULT=unknown; ROOTKIT_RESULT=unknown
if (( REPORT_FRESH )); then
    # Evaluate each scanner from its own section so one scanner's warnings or
    # summary lines cannot affect the other.
    if text_has '^[[:space:]]*Rootkit Scan Report' "$REPORT_TEXT"; then
        MALWARE_TEXT=$(printf '%s\n' "$REPORT_TEXT" | awk 'tolower($0) ~ /^[[:space:]]*rootkit scan report/ {exit} {print}')
        ROOTKIT_TEXT=$(printf '%s\n' "$REPORT_TEXT" | awk 'f || tolower($0) ~ /^[[:space:]]*rootkit scan report/ {f=1; print}')
    else
        MALWARE_TEXT=$REPORT_TEXT; ROOTKIT_TEXT=$REPORT_TEXT
    fi
    mi=$(summary_num '^[[:space:]]*(Infected files|MALWARE_INFECTED_FILES)[[:space:]]*:' "$MALWARE_TEXT")
    mc=$(summary_num '^[[:space:]]*(Scanned files|MALWARE_FILES_SCANNED)[[:space:]]*:' "$MALWARE_TEXT")
    ri=$(summary_num '^[[:space:]]*(Possible rootkits|ROOTKIT_FOUND)[[:space:]]*:' "$ROOTKIT_TEXT")
    rc=$(summary_num '^[[:space:]]*(Files checked|Rootkits checked|ROOTKIT_CHECKS_PERFORMED)[[:space:]]*:' "$ROOTKIT_TEXT")
    malware_error=0; rootkit_error=0
    text_has '(^|[[:space:]])(ERROR|FAILED|ABORTED|WARNING)(:|[[:space:]]|$)' "$MALWARE_TEXT" && malware_error=1
    text_has '(^|[[:space:]])(ERROR|FAILED|ABORTED|WARNING)(:|[[:space:]]|$)' "$ROOTKIT_TEXT" && rootkit_error=1
    if [[ $mi =~ ^[0-9]+$ ]] && (( mi > 0 )); then MALWARE_RESULT=found
    elif [[ $mi == 0 && $mc =~ ^[0-9]+$ ]] && (( mc > 0 && malware_error == 0 )) &&
         text_has 'SCAN SUMMARY|^MALWARE_SCAN_COMPLETED:[[:space:]]*YES[[:space:]]*$' "$MALWARE_TEXT"; then MALWARE_RESULT=clean; fi
    if [[ $ri =~ ^[0-9]+$ ]] && (( ri > 0 )); then ROOTKIT_RESULT=found
    elif [[ $ri == 0 && $rc =~ ^[0-9]+$ ]] && (( rc > 0 && rootkit_error == 0 )) &&
         text_has 'System checks summary|^ROOTKIT_SCAN_COMPLETED:[[:space:]]*YES[[:space:]]*$|^[[:space:]]*Rootkits checked[[:space:]]*:' "$ROOTKIT_TEXT"; then ROOTKIT_RESULT=clean; fi
    text_has '^[[:space:]]*Checking.*INFECTED' "$ROOTKIT_TEXT" && ROOTKIT_RESULT=found
    text_has '^/[^:]+: .+ FOUND[[:space:]]*$' "$MALWARE_TEXT" && MALWARE_RESULT=found
fi

# Bounded file discovery; partial discovery never establishes full coverage.
CMS_LIST=''; CMS_SCOPE=''; CMS_PARTIAL=0
for root in "${WEBROOTS[@]}"; do
    [[ -d $root ]] || continue
    CMS_SCOPE+="$root "
    files=$(timeout -k 2s 45s find "$root" -xdev -maxdepth 12 \
        \( -type d \( -name node_modules -o -name .git -o -name cache -o -name vendor \) -prune \) -o \
        \( -type f \( -path '*/wp-includes/version.php' -o -path '*/core/lib/Drupal.php' -o \
        -path '*/includes/bootstrap.inc' -o -path '*/administrator/manifests/files/joomla.xml' -o -name version.php \) -print \) 2>/dev/null)
    (( $? == 0 )) || CMS_PARTIAL=1
    while IFS= read -r file; do
        [[ -n $file ]] || continue
        ver=''; product=''
        case "$file" in
            */wp-includes/version.php) product=wordpress; ver=$(sed -nE "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" "$file" | head -n 1);;
            */core/lib/Drupal.php) product=drupal; ver=$(sed -nE "s/.*const VERSION[[:space:]]*=[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" "$file" | head -n 1);;
            */includes/bootstrap.inc) product=drupal; ver=$(sed -nE "s/.*define\(['\"]VERSION['\"],[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" "$file" | head -n 1);;
            */administrator/manifests/files/joomla.xml) product=joomla; ver=$(sed -nE 's/.*<version>([0-9.]+)<\/version>.*/\1/p' "$file" | head -n 1);;
            */version.php)
                if [[ -f ${file%/*}/lib/moodlelib.php ]]; then
                    product=moodle; ver=$(sed -nE "s/^[[:space:]]*\\\$release[[:space:]]*=[[:space:]]*['\"]([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p" "$file" | head -n 1)
                fi;;
        esac
        [[ -n $product && -n $ver ]] && CMS_LIST+="$product"$'\t'"$ver"$'\t'"$file"$'\n'
    done <<< "$files"
done
CMS_LIST=$(printf '%s' "$CMS_LIST" | sort -u)

PANEL=none; PANEL_VER=''
if [[ -f /usr/local/cpanel/version ]]; then PANEL=cpanel; PANEL_VER=$(head -c 100 /usr/local/cpanel/version)
elif [[ -f /usr/local/psa/version ]]; then PANEL=plesk; PANEL_VER=$(head -c 100 /usr/local/psa/version)
elif [[ -d /usr/local/directadmin ]]; then PANEL=directadmin; PANEL_VER='unverified (binary not executed)'
elif [[ -d /usr/share/webmin || -d /etc/webmin ]]; then PANEL=webmin; PANEL_VER=$(head -c 100 /usr/share/webmin/version 2>/dev/null); fi

PHP_LIST=''; declare -A SEEN_PHP
for bin in /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /opt/remi/php*/root/usr/bin/php /opt/alt/php*/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/php; do
    [[ -x $bin && ${bin##*/} =~ ^php([0-9.]*)?$ ]] || continue
    resolved=$(run readlink -f "$bin"); [[ -n $resolved ]] || resolved=$bin
    [[ -n ${SEEN_PHP[$resolved]:-} ]] && continue; SEEN_PHP[$resolved]=1
    # -n avoids extensions/configuration/autoload; no PHP application code is run.
    ver=$(run "$bin" -n -v | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n 1)
    [[ -n $ver ]] && PHP_LIST+="$ver"$'\t'"$bin"$'\n'
done
PHP_LIST=$(printf '%s' "$PHP_LIST" | sort -u)
WEB_PKGS=$(pkgmatch '^(ea-apache24|ea-nginx|nginx|apache2|httpd|litespeed|openlitespeed|lsws)([-:]|$)')
DB_PKGS=$(pkgmatch '^([Mm][Yy][Ss][Qq][Ll]|mysql-community|mariadb|MariaDB|postgresql|percona|Percona|redis|mongodb)([-:]|$)')
OTHER_PKGS=$(pkgmatch '^(cpanel-)?(postfix|exim|sendmail|dovecot|bind|bind9|unbound|powerdns|pdns|openssh|openssl|proftpd|pure-ftpd|vsftpd)([-:]|$)')
WEB_BINARIES=''; DB_BINARIES=''
for cmd in nginx httpd apache2; do
    if have "$cmd"; then
        binary_version=$(timeout -k 2s 10s "$cmd" -v 2>&1 | head -n 2 | flat)
        WEB_BINARIES+="$cmd: $binary_version; "
    fi
done
for cmd in mysqld mariadbd; do
    have "$cmd" && DB_BINARIES+="$cmd: $(run "$cmd" --no-defaults --version | flat); "
done
for cmd in postgres redis-server mongod; do
    have "$cmd" && DB_BINARIES+="$cmd: $(run "$cmd" --version | head -n 2 | flat); "
done

printf 'READ-ONLY SERVER AUDIT 1.3.0 | %s UTC\n' "$(date -u '+%F %T')"
printf 'Host: %s | OS: %s | Kernel: %s | Panel: %s %s\n' "$HOST" "$OS_NAME" "$KERNEL" "$PANEL" "$PANEL_VER"
printf 'Target IPv4: %s | %s\n' "${TARGET_IP:-unverified}" "$IP_NOTE"
printf 'Package inventory: %s\n' "$PKG_DIAGNOSTIC"
printf 'Network checks: %s | %s\n' "$([[ $OFFLINE == 1 ]] && printf disabled || printf 'DNS and public vendor HTTPS enabled; website HEAD only for supplied URLs')" "$BASELINE_NOTE"
printf 'Unknowns are not passes. No installations/upgrades, configuration changes or scans. Package/cPanel query tools may write normal metadata/cache/logs/locks. See --help.\n'

section 'A : Threat Protection'
fw_installed=''; fw_issues=''; fw_rules=''; rules_known=0
for cmd in csf iptables nft firewall-cmd ufw imunify360-agent; do have "$cmd" && fw_installed+="$cmd "; done
[[ -d /etc/csf ]] && fw_installed+='CSF-config '
active lfd && fw_installed+='LFD-running '
active fail2ban && fw_installed+='Fail2Ban-running '
for svc in firewalld nftables iptables imunify360; do
    if have systemctl && [[ -d /run/systemd/system ]]; then
        load=$(run systemctl show "$svc" -p LoadState | sed -n 's/^LoadState=//p')
        if [[ $load == loaded ]] && ! active "$svc"; then fw_issues+="$svc service inactive (rules may persist independently); "; fi
    fi
done
if [[ -f /etc/csf/csf.disable ]]; then fw_issues+='CSF disable marker exists; '; fi
if [[ -r /etc/csf/csf.conf ]] && grep -Eq '^[[:space:]]*TESTING[[:space:]]*=[[:space:]]*"?1' /etc/csf/csf.conf; then fw_issues+='CSF TESTING=1; '; fi
if have iptables; then
    rules=$(run iptables -S); rc=$?
    if (( rc == 0 )); then
        rules_known=1
        drops=$(printf '%s\n' "$rules" | grep -Ec -- '^-P INPUT (DROP|REJECT)|^-A .* -j (DROP|REJECT)( |$)')
        fw_rules+="IPv4 filter has $drops restrictive policy/rule entries (reachability not proven); "
    else fw_issues+='IPv4 rules unreadable; '; fi
fi
if have ip6tables; then
    rules6=$(run ip6tables -S)
    if (( $? == 0 )); then fw_rules+="IPv6 restrictive entries=$(printf '%s\n' "$rules6" | grep -Ec -- '^-P INPUT (DROP|REJECT)|^-A .* -j (DROP|REJECT)( |$)'); "; else fw_issues+='IPv6 rules unreadable; '; fi
fi
if have nft; then
    nrules=$(run nft list ruleset)
    if (( $? == 0 )); then rules_known=1; fw_rules+="nft restrictive statements=$(printf '%s\n' "$nrules" | grep -Ec '(^|[[:space:];])(drop|reject)([[:space:];]|$)'); "; fi
fi
if [[ -n $fw_installed ]]; then fw_status=ACTIVE; else fw_status=INACTIVE; fi
emit 'SYSTEM FIREWALL' "$fw_status" "Installed/detected: ${fw_installed:-none}. $fw_issues $fw_rules Presence is not proof of effective inbound protection. Cloud/Sucuri controls are not locally verifiable." 'Review effective IPv4/IPv6 INPUT policies, rule order, exposed ports, trusted IPs, and disabled/test-mode products. Coordinate one consistent firewall policy; do not enable competing managers blindly.'

scanners=$(pkgmatch '(clamav|clamd|imunify|maldet|rkhunter|chkrootkit)' | head -n 30 | flat)
scanner_status=INACTIVE; scanner_ev="Installed packages: ${scanners:-none detected}. "; malware_tool=0
for cmd in clamscan clamdscan maldet imunify360-agent imunify-antivirus; do
    if have "$cmd"; then scanner_ev+="$cmd present; "; malware_tool=1; fi
done
if active clamd clamd@scan clamav-daemon; then
    scanner_ev+='Clam daemon process/service running; '
    if have clamdscan && run clamdscan --ping=1 >/dev/null; then
        scanner_ev+='clamd PING succeeded; '
        sig_recent=0
        for f in /var/lib/clamav/daily.cvd /var/lib/clamav/daily.cld /var/clamav/daily.cvd /var/clamav/daily.cld /usr/local/cpanel/3rdparty/share/clamav/daily.cvd /usr/local/cpanel/3rdparty/share/clamav/daily.cld; do
            [[ -f $f ]] || continue; t=$(stat -c %Y "$f" 2>/dev/null)
            [[ $t =~ ^[0-9]+$ ]] && (( NOW>=t && NOW-t<=7*86400 )) && sig_recent=1
        done
        if (( sig_recent )); then scanner_status=ACTIVE; scanner_ev+='Signature-file mtime within 7 days (signature version not authenticated). '
        else scanner_ev+='UNVERIFIED: signature freshness. '; fi
    fi
fi
if active imunify360 imunify-antivirus; then
    scanner_ev+='Imunify service running; '
    imunify_cmd=''; have imunify360-agent && imunify_cmd=imunify360-agent
    [[ -n $imunify_cmd ]] || { have imunify-antivirus && imunify_cmd=imunify-antivirus; }
    if [[ -n $imunify_cmd ]]; then
        imunify_config=$(run "$imunify_cmd" config show --json); imunify_rc=$?
        if (( imunify_rc==0 )) && printf '%s\n' "$imunify_config" | grep -Eq '"enable_scan_inotify"[[:space:]]*:[[:space:]]*true([,[:space:]}]|$)'; then
            scanner_status=ACTIVE; scanner_ev+='Agent responds and realtime scanning is configured enabled; licensing/signatures and full coverage still need review. '
        else scanner_ev+='Agent response or realtime-scan enablement unverified; licensing/protection needs console review. '; fi
        # Never output full Imunify configuration (may contain notification details).
        unset imunify_config
    fi
fi
[[ $MALWARE_RESULT != unknown && $malware_tool == 1 ]] && { scanner_status=ACTIVE; scanner_ev+="Recent completed scan summary detected: $MALWARE_RESULT. "; }
emit 'MALWARE SCANNER' "$scanner_status" "$scanner_ev Enabled scheduling/realtime coverage is not proven; $REPORT_INFO" 'If operation or coverage is unverified, review scanner health, signature updates, licensing and completed scan history. Arrange a scan separately if required; none was run.'

login_status=INACTIVE; login_ev=''
if have fail2ban-client; then
    fstatus=$(run fail2ban-client status)
    jails=$(printf '%s\n' "$fstatus" | sed -nE 's/.*Jail list:[[:space:]]*(.*)/\1/p' | tr ',' ' ')
    for jail in $jails; do
        [[ $jail =~ ^[A-Za-z0-9_.-]+$ ]] || continue
        js=$(run fail2ban-client status "$jail"); acts=$(run fail2ban-client get "$jail" actions)
        if [[ -n $js && -n $acts ]] && ! printf '%s' "$acts" | grep -Eiq 'error|invalid|sorry'; then
            # Only known blocking actions count; email-only jails do not.
            if printf '%s' "$acts" | grep -Eiq 'iptables|nftables|firewallcmd|ufw|route|ipset'; then login_status=ACTIVE; login_ev+="Fail2Ban jail $jail responds with blocking-action configuration; "; fi
        fi
    done
fi
if active lfd && [[ -r /etc/csf/csf.conf ]] &&
   grep -Eq '^[[:space:]]*LF_SSHD[[:space:]]*=[[:space:]]*"?[1-9][0-9]*' /etc/csf/csf.conf &&
   ! grep -Eq '^[[:space:]]*TESTING[[:space:]]*=[[:space:]]*"?1' /etc/csf/csf.conf && [[ ! -e /etc/csf/csf.disable ]]; then
    login_status=ACTIVE; login_ev+='LFD running with positive LF_SSHD threshold and CSF not marked disabled/testing; '
fi
active cphulkd && login_ev+='cPHulk running; enablement/policy unverified. '
[[ $login_status == INACTIVE ]] && login_ev+='No operational login-blocking mechanism confirmed. '
emit 'FAILED LOGIN DETETCTION' "$login_status" "$login_ev No controlled ban test was performed." 'Verify SSH and application-specific jails, thresholds, exclusions, persistent rules and recent bans. Configured actions still need an end-to-end review.'

waf_pkgs=$(pkgmatch '(mod_security|modsecurity|imunify|naxsi)' | flat)
waf_paths=''; waf_mode=''
for dir in /etc/httpd /etc/apache2 /etc/nginx /usr/local/lsws/conf; do
    [[ -d $dir ]] || continue
    matches=$(timeout -k 2s 15s grep -rIlE --include='*.conf' '^[[:space:]]*(SecRuleEngine|modsecurity|modsecurity_rules_file|enableSecurity)' "$dir" 2>/dev/null)
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        waf_paths+="$f; "
        waf_mode+=$(grep -E '^[[:space:]]*(SecRuleEngine|modsecurity[[:space:]])' "$f" | head -n 10 | flat)
    done <<< "$matches"
done
waf_status=INACTIVE; waf_runtime='UNVERIFIED runtime enforcement.'; waf_mapped=0
imunify360_present=0
if [[ -n $(pkgmatch '^imunify360([_-]|$)') ]] || have imunify360-agent || [[ -d /usr/share/imunify360 || -d /opt/imunify360 ]]; then
    imunify360_present=1
    waf_status=ACTIVE
    waf_runtime='Imunify360 components detected; audit policy marks WEB APP FIREWALL ACTIVE. Per-vhost blocking mode/ruleset coverage still requires review.'
fi
if have pgrep; then
    for pname in httpd apache2 nginx lshttpd; do
        for pid in $(run pgrep -x "$pname"); do
            [[ $pid =~ ^[0-9]+$ && -r /proc/$pid/maps ]] || continue
            grep -Eiq '(mod_security2|ngx_http_modsecurity|libmodsecurity)\.so' "/proc/$pid/maps" && waf_mapped=1
        done
    done
fi
# Live ModSecurity evidence supplements the installed-Imunify360 classification.
if (( waf_mapped )); then
    (( imunify360_present )) || waf_runtime='ModSecurity library mapped by a live web process; blocking enforcement not yet confirmed.'
    today_error=$(date '+%a %b %d'); today_audit=$(date '+%d/%b/%Y')
    for log in /var/log/httpd/error_log /var/log/apache2/error.log /var/log/nginx/error.log /var/log/httpd/modsec_audit.log /var/log/apache2/modsec_audit.log; do
        [[ -f $log && -r $log ]] || continue
        if run tail -n 2000 "$log" | grep -F -e "$today_error" -e "$today_audit" | grep -Eq 'ModSecurity: Access denied with code (403|406|429)'; then
            waf_status=ACTIVE; waf_runtime="Live mapped ModSecurity plus today's blocking event in $log (some request coverage only)."; break
        fi
    done
fi
emit 'WEB APP FIREWALL' "$waf_status" "$waf_runtime Packages: ${waf_pkgs:-none detected}. Config candidates: ${waf_paths:-none}. Modes: ${waf_mode:-unknown}. Files can be excluded, overridden or DetectionOnly; no test request sent." 'Review loaded modules, effective vhost configuration, enabled rulesets and audit logs with the developer team. Confirm blocking mode and all-site coverage; externally managed WAFs need manual verification.'

rootkit_tools=''; for cmd in rkhunter chkrootkit; do have "$cmd" && rootkit_tools+="$cmd "; done
rootkit_status=INACTIVE; [[ -n $rootkit_tools ]] && rootkit_status=ACTIVE
emit 'ROOTKIT SCANNER' "$rootkit_status" "Installed tools: ${rootkit_tools:-not found}. Recent report result=$ROOTKIT_RESULT. $REPORT_INFO Tool availability is the ACTIVE criterion for this item; no rootkit scan was executed by the audit." 'Verify scheduled execution and a recent completed report. Review rootkit warnings against a known baseline; a warning is not automatically proof of compromise.'

# Read-only version references. TLS is verified; only public vendor URLs are used.
fetch_metadata() {
    (( OFFLINE )) && return 1
    have curl || return 1
    timeout -k 2s 22s curl -q -f -sS --proto '=https' --proto-redir '=https' \
        --connect-timeout 5 --max-time 20 --max-filesize 2097152 -- "$1" 2>/dev/null
}
json_version() {
    # Numeric release strings only; never interpret JSON as shell or PHP code.
    grep -oE '"'"$1"'"[[:space:]]*:[[:space:]]*"[0-9]+(\.[0-9]+){1,3}"' |
        head -n 1 | sed -E 's/.*:[[:space:]]*"([0-9.]+)"/\1/'
}
CPANEL_TIERS=''; CPANEL_TIER=''; CPANEL_REFERENCE=''; CPANEL_REFERENCE_NOTE='Vendor tier metadata unavailable.'
CPANEL_LOCAL_REFERENCE=''; CPANEL_LOCAL_CHECK_NOTE='Local cPanel update check unavailable.'
if [[ $PANEL == cpanel ]]; then
    CPANEL_TIER=$(awk -F= '$1=="CPANEL" {gsub(/[[:space:]"\047]/,"",$2);print tolower($2);exit}' /etc/cpupdate.conf 2>/dev/null)
    tiers_raw=$(fetch_metadata 'https://httpupdate.cpanel.net/cpanelsync/TIERS')
    if (( $?==0 )); then
        CPANEL_TIERS=$(printf '%s\n' "$tiers_raw" | tr ':=' '  ' | awk '$1 ~ /^(stable|release|current|lts|edge)$/ && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1 "\t" $2}')
        CPANEL_REFERENCE=$(printf '%s\n' "$CPANEL_TIERS" | awk -F '\t' -v t="$CPANEL_TIER" '$1==t{print $2;exit}')
        [[ -n $CPANEL_REFERENCE ]] && CPANEL_REFERENCE_NOTE='Live cPanel HTTPS tier metadata.'
    fi
    # The user-requested cPanel comparison is query/dry-run only. No --upcp or update action is used.
    if (( ! OFFLINE )) && [[ -x /usr/local/cpanel/scripts/updatenow ]]; then
        cp_check_out=$(timeout -k 2s 60s /usr/local/cpanel/scripts/updatenow --check 2>&1); cp_check_rc=$?
        cp_dry_out=$(timeout -k 2s 90s /usr/local/cpanel/scripts/updatenow --dry-run 2>&1); cp_dry_rc=$?
        CPANEL_LOCAL_REFERENCE=$(printf '%s\n' "$cp_dry_out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -n 1)
        [[ -n $CPANEL_LOCAL_REFERENCE ]] || CPANEL_LOCAL_REFERENCE=$(printf '%s\n' "$cp_check_out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -n 1)
        CPANEL_LOCAL_CHECK_NOTE="updatenow --check exit=$cp_check_rc; --dry-run exit=$cp_dry_rc; local reference=${CPANEL_LOCAL_REFERENCE:-not parsed}."
        [[ -n $CPANEL_LOCAL_REFERENCE ]] && CPANEL_REFERENCE=$CPANEL_LOCAL_REFERENCE
        unset cp_check_out cp_dry_out
    elif (( OFFLINE )); then
        CPANEL_LOCAL_CHECK_NOTE='Local updatenow check skipped by --offline.'
    fi
    [[ $CPANEL_TIER == never || $CPANEL_TIER =~ ^[0-9] ]] && CPANEL_REFERENCE_NOTE+=' Updates are disabled or pinned; the local dry-run reference is preferred when available.'
fi

# Live vendor OS reference is informational and never executes retrieved content.
OS_VENDOR_LATEST=''; OS_VENDOR_REFERENCE_URL=''; OS_VENDOR_REFERENCE_NOTE='Vendor OS website reference unavailable.'
os_vendor_raw=''
if (( OFFLINE )); then
    OS_VENDOR_REFERENCE_NOTE='Vendor OS website check skipped by --offline.'
else
    case "$OS_ID" in
        cloudlinux)
            OS_VENDOR_REFERENCE_URL='https://docs.cloudlinux.com/introduction/'
            os_vendor_raw=$(fetch_metadata "$OS_VENDOR_REFERENCE_URL")
            OS_VENDOR_LATEST=$(printf '%s\n' "$os_vendor_raw" | grep -oE 'CloudLinux OS [0-9]+' | grep -oE '[0-9]+' | sort -Vu | tail -n 1);;
        almalinux)
            OS_VENDOR_REFERENCE_URL='https://wiki.almalinux.org/release-notes/'
            os_vendor_raw=$(fetch_metadata "$OS_VENDOR_REFERENCE_URL")
            OS_VENDOR_LATEST=$(printf '%s\n' "$os_vendor_raw" | grep -oE 'AlmaLinux( OS)? [0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | sort -Vu | tail -n 1);;
        rocky)
            OS_VENDOR_REFERENCE_URL='https://wiki.rockylinux.org/rocky/version/'
            os_vendor_raw=$(fetch_metadata "$OS_VENDOR_REFERENCE_URL")
            OS_VENDOR_LATEST=$(printf '%s\n' "$os_vendor_raw" | grep -oE 'Rocky( Linux)? [0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | sort -Vu | tail -n 1);;
        ubuntu)
            OS_VENDOR_REFERENCE_URL='https://ubuntu.com/about/release-cycle'
            os_vendor_raw=$(fetch_metadata "$OS_VENDOR_REFERENCE_URL")
            OS_VENDOR_LATEST=$(printf '%s\n' "$os_vendor_raw" | grep -oE 'Ubuntu [0-9]{2}\.04 LTS' | grep -oE '[0-9]{2}\.04' | sort -Vu | tail -n 1);;
    esac
    [[ -n $OS_VENDOR_LATEST ]] && OS_VENDOR_REFERENCE_NOTE="Live vendor website latest release reference=$OS_VENDOR_LATEST." 
fi
unset os_vendor_raw

# Standard-support lifecycle flag used by the Software Updates recommendation.
# ELS/paid extended support is deliberately treated as separate from standard support.
OS_STANDARD_EOL=0
case "$OS_ID:$OS_VERSION" in
    cloudlinux:7|cloudlinux:7.*) [[ $TODAY > 2024-06-30 ]] && OS_STANDARD_EOL=1;;
    centos:7|centos:7.*) [[ $OS_NAME != *Stream* && $TODAY > 2024-06-30 ]] && OS_STANDARD_EOL=1;;
    centos:8|centos:8.*) [[ $OS_NAME != *Stream* && $TODAY > 2021-12-31 ]] && OS_STANDARD_EOL=1;;
    ubuntu:14.04|ubuntu:16.04|ubuntu:18.04|ubuntu:20.04) OS_STANDARD_EOL=1;;
esac
WP_LATEST=''; WP_REFERENCE_NOTE='WordPress HTTPS release metadata unavailable.'
if printf '%s\n' "$CMS_LIST" | grep -q '^wordpress'; then
    wp_json=$(fetch_metadata 'https://api.wordpress.org/core/version-check/1.7/')
    if (( $?==0 )); then
        WP_LATEST=$(printf '%s' "$wp_json" | json_version current)
        [[ -n $WP_LATEST ]] && WP_REFERENCE_NOTE="Latest official WordPress release=$WP_LATEST (live HTTPS)."
    fi
fi
declare -A PHP_LIVE_LATEST
while IFS=$'\t' read -r ver bin; do
    [[ -n $ver ]] || continue; branch=${ver%.*}
    case "$branch" in 8.2|8.3|8.4|8.5) ;; *) continue;; esac
    [[ -n ${PHP_LIVE_LATEST[$branch]+set} ]] && continue
    php_json=$(fetch_metadata "https://www.php.net/releases/index.php?json&version=$branch"); php_fetch_rc=$?
    latest=''; (( php_fetch_rc==0 )) && latest=$(printf '%s' "$php_json" | json_version version)
    [[ $latest == "$branch".* ]] || latest=''
    PHP_LIVE_LATEST[$branch]=$latest
done <<< "$PHP_LIST"

# DNF/YUM availability query. Online mode may refresh repository metadata/cache,
# but no install/upgrade transaction is invoked. Offline mode is cache-only.
RPM_UPDATES=''; RPM_CHECK_OK=0; RPM_CACHE_DAYS=unknown; RPM_CHECK_NOTE='RPM package check unavailable.'
RPM_MANAGER=''
if [[ $PKG_KIND == rpm && $NO_PACKAGE_CHECK == 0 ]]; then
    have dnf && RPM_MANAGER=dnf; [[ -n $RPM_MANAGER ]] || { have yum && RPM_MANAGER=yum; }
    if [[ -n $RPM_MANAGER ]]; then
        if (( OFFLINE )); then
            rpm_opts=(-C --noplugins --setopt=history_record=false --setopt=skip_if_unavailable=false)
            [[ $RPM_MANAGER == yum ]] && rpm_opts+=(--setopt=logfile=/dev/null)
            update_raw=$(timeout -k 2s 90s "$RPM_MANAGER" "${rpm_opts[@]}" -q check-update 2>&1); update_rc=$?
            mode_note='cache-only, plugins disabled'
        else
            rpm_opts=(--setopt=history_record=false --setopt=skip_if_unavailable=false)
            [[ $RPM_MANAGER == yum ]] && rpm_opts+=(--setopt=logfile=/dev/null)
            update_raw=$(timeout -k 2s 90s "$RPM_MANAGER" "${rpm_opts[@]}" -q check-update 2>&1); update_rc=$?
            mode_note='online repository check; metadata/cache refresh may occur'
        fi
        if (( update_rc==0 || update_rc==100 )); then
            RPM_UPDATES=$(printf '%s\n' "$update_raw" | awk '$1 ~ /\.(x86_64|i[3-6]86|noarch|aarch64|ppc64le|s390x)$/ && NF>=3 && $2 ~ /^[0-9]/ {n=$1;sub(/\.[^.]+$/,"",n);print n "\t" $2 "\t" $3}')
            RPM_CHECK_OK=1
            RPM_CHECK_NOTE="$RPM_MANAGER check-update succeeded ($mode_note), exit=$update_rc, candidate rows=$(printf '%s\n' "$RPM_UPDATES" | awk 'NF{n++}END{print n+0}')."
        else
            RPM_CHECK_NOTE="UNVERIFIED: $RPM_MANAGER check-update failed, exit=$update_rc (124 means timeout). $(printf '%s\n' "$update_raw" | tail -n 4 | flat)"
        fi
        cache_root=/var/cache/dnf; [[ $RPM_MANAGER == yum ]] && cache_root=/var/cache/yum
        ct=$(timeout -k 2s 10s find "$cache_root" -maxdepth 6 -type f -name repomd.xml -printf '%T@\n' 2>/dev/null | sort -n | head -n 1); ct=${ct%%.*}
        [[ $ct =~ ^[0-9]+$ ]] && (( NOW>=ct )) && RPM_CACHE_DAYS=$(((NOW-ct)/86400))
        RPM_CHECK_NOTE+=" Oldest cached repomd.xml age=$RPM_CACHE_DAYS days."
        unset update_raw rpm_opts
    fi
fi

APT_CANDIDATES=''; APT_AGE='unknown'; APT_OK=0
if [[ $PKG_KIND == deb ]] && have apt-cache; then
    list_time=$(find /var/lib/apt/lists -maxdepth 1 -type f \( -name '*InRelease' -o -name '*Release' \) -printf '%T@\n' 2>/dev/null | sort -n | head -n 1)
    list_time=${list_time%%.*}
    if [[ $list_time =~ ^[0-9]+$ ]] && (( NOW >= list_time )); then APT_AGE=$(((NOW-list_time)/86400)); fi
    # Candidate reads are limited to the relevant installed packages plus kernel.
    wanted=$(printf '%s\n' "$PKGS" | awk -F '\t' '$1 ~ /^(linux-image|linux-headers|php|nginx|apache2|mariadb|mysql|postgresql|redis|mongodb|postfix|exim|sendmail|dovecot|bind|unbound|pdns|openssh|openssl|proftpd|pure-ftpd|vsftpd)/{print $1}')
    if [[ -n $wanted ]]; then
        mapfile -t pkgargs <<< "$wanted"
        pol=$(timeout -k 2s 45s apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "${pkgargs[@]}" 2>/dev/null)
        if (( $? == 0 )); then
            APT_CANDIDATES=$(printf '%s\n' "$pol" | awk '/^[^[:space:]].*:$/ {p=$0;sub(/:$/,"",p)} /^[[:space:]]*Candidate:/ {print p "\t" $2}')
            [[ $APT_AGE =~ ^[0-9]+$ ]] && (( APT_AGE <= 1 )) && APT_OK=1
        fi
    fi
fi
OFFPEAK='Ask the client for an approved off-peak maintenance time before any upgrade/update; test application compatibility and arrange rollback first.'
package_updates() {
    local item=$1 inventory=$2 binaries=${3:-} n v candidate key count=0 pending=0 unknown=0 ev=''
    if [[ -z $inventory ]]; then emit "$item" NA "No matching packages detected; source/container installs may exist. Binary version evidence: ${binaries:-none found}." "Review actual service inventory and vendor release channel. $OFFPEAK"; return; fi
    while IFS=$'\t' read -r n v; do
        [[ -n $n ]] || continue; ((count++)); key="pkg:$n"; candidate=${BL_LATEST[$key]:-}
        if [[ -n $candidate && $candidate != - ]]; then
            if [[ $v != "$candidate" ]]; then ((unknown++)); ev+="$n=$v reviewed-reference=$candidate (difference; upgrade direction needs vendor verification); "
            else ev+="$n=$v matches reviewed reference; "; fi
        elif [[ $PKG_KIND == rpm ]]; then
            candidate=$(printf '%s\n' "$RPM_UPDATES" | awk -F '\t' -v p="$n" '$1==p{print $2;exit}')
            if [[ -n $candidate ]]; then
                ((pending++)); ev+="$n installed=$v repository-candidate=$candidate; "
            elif (( RPM_CHECK_OK )); then
                ev+="$n=$v (no update candidate reported by successful $RPM_MANAGER check-update); "
            else
                ((unknown++)); ev+="$n=$v (package availability check failed/skipped); "
            fi
        elif [[ $PKG_KIND == deb ]]; then
            candidate=$(printf '%s\n' "$APT_CANDIDATES" | awk -F '\t' -v p="$n" '$1==p{print $2;exit}')
            if [[ -n $candidate && $candidate != '(none)' ]] && run dpkg --compare-versions "$v" lt "$candidate"; then
                ((pending++)); ev+="$n=$v candidate=$candidate; "
            elif [[ -n $candidate && $candidate != '(none)' && $APT_OK == 1 ]] && run dpkg --compare-versions "$v" ge "$candidate"; then
                ev+="$n=$v (no newer candidate in Debian cache); "
            else ((unknown++)); ev+="$n=$v (candidate availability unverified); "; fi
        else ((unknown++)); ev+="$n=$v; "; fi
    done <<< "$inventory"
    local status=NA
    (( pending > 0 )) && status='Updates pending to install'
    (( count > 0 && pending == 0 && unknown == 0 )) && status='All updates installed'
    ev=$(printf '%s' "$ev" | cut -c1-2600)
    emit "$item" "$status" "Packages=$count; pending=$pending; unverified=$unknown. $ev Binary evidence: ${binaries:-not collected}. $RPM_CHECK_NOTE Debian cache age=$APT_AGE days. A successful check-update with no matching candidate is treated as All updates installed for the enabled repositories; source/container builds remain separate." "$OFFPEAK"
}
version_le() {
    [[ $1 =~ ^[0-9]+(\.[0-9]+){1,3}$ && $2 =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || return 2
    [[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1) == "$1" ]]
}
php_eol() {
    local ver=$1 branch=${1%.*} key="php:${1%.*}" end=${BL_EOL["php:${1%.*}"]:-}
    if [[ -z $end || $end == - ]]; then
        case "$branch" in
            5.*|7.*|8.0|8.1) printf 'End Of Life Period'; return;;
            8.2) end=2026-12-31;; 8.3) end=2027-12-31;; 8.4) end=2028-12-31;; 8.5) end=2029-12-31;;
            *) printf NA; return;;
        esac
    fi
    if [[ $TODAY > $end ]]; then printf 'End Of Life Period'; else printf 'Support Period Active'; fi
}
section 'B : Software Updates'
panel_key="panel:$PANEL:${PANEL_VER%% *}"; panel_latest=${BL_LATEST[$panel_key]:-$CPANEL_REFERENCE}; panel_status=NA
if [[ $PANEL != none && -n $panel_latest && $panel_latest != - ]]; then
    if [[ $PANEL_VER == "$panel_latest" ]]; then panel_status='All updates installed'
    elif version_le "$PANEL_VER" "$panel_latest"; then panel_status='Updates pending to install'; fi
fi
panel_os_note=''
if [[ $PANEL == cpanel && $PANEL_VER == 11.110.* && ( $OS_ID == cloudlinux || $OS_NAME == CloudLinux* ) && $OS_VERSION == 7* ]]; then
    panel_os_note='cPanel & WHM 110 is the last branch compatible with CloudLinux 7; newer cPanel releases require migration to a supported OS. Standard CloudLinux 7 support is EOL; ELS entitlement is separate.'
fi
emit 'CONTROL PANEL' "$panel_status" "Detected panel=$PANEL version=${PANEL_VER:-none}; configured tier=${CPANEL_TIER:-not applicable/unknown}; local/tier reference build=${panel_latest:-unknown}. $CPANEL_LOCAL_CHECK_NOTE $CPANEL_REFERENCE_NOTE $panel_os_note" "$OFFPEAK"

# KernelCare: when a live patch is applied, kernel package candidates are not
# reported as pending OS updates (the running kernel is already patched).
kcare=0; kcare_note=''
if have kcarectl; then
    kcare_info=$(run kcarectl --info)
    if printf '%s\n' "$kcare_info" | grep -q 'kpatch-state: patch is applied'; then
        kcare=1; kcare_note='KernelCare is installed and a live patch is applied; kernel package candidates are excluded from the pending list.'
    else
        kcare_note='kcarectl is present but "patch is applied" was not confirmed; kernel updates are still counted.'
    fi
    unset kcare_info
fi
kernel_pkgs=$(pkgmatch '^(kernel|linux-image|linux-headers)([-:]|$)')
os_update_status=NA; kernel_updates=''; os_repo_candidates=''
if [[ $PKG_KIND == rpm ]]; then
    if (( kcare )); then
        os_re='^(cloudlinux-release|almalinux-release|rocky-release|centos-release|redhat-release)(-|$)'
    else
        os_re='^(kernel|cloudlinux-release|almalinux-release|rocky-release|centos-release|redhat-release)(-|$)'
    fi
    os_repo_candidates=$(printf '%s\n' "$RPM_UPDATES" | awk -F '\t' -v re="$os_re" '$1 ~ re {print $1 " -> " $2}' | flat)
    if [[ -n $os_repo_candidates ]]; then
        os_update_status='Updates pending to install'; kernel_updates=$os_repo_candidates
    elif (( RPM_CHECK_OK )); then
        os_update_status='All updates installed'
    fi
fi
while IFS=$'\t' read -r name ver; do
    [[ -n $name ]] || continue
    (( kcare )) && continue
    candidate=$(printf '%s\n' "$APT_CANDIDATES" | awk -F '\t' -v p="$name" '$1==p{print $2;exit}')
    if [[ $PKG_KIND == deb && -n $candidate && $candidate != '(none)' ]] && run dpkg --compare-versions "$ver" lt "$candidate"; then
        os_update_status='Updates pending to install'; kernel_updates+="$name candidate=$candidate; "
    elif [[ $PKG_KIND == deb && $APT_OK == 1 && -n $candidate && $candidate != '(none)' && $os_update_status == NA ]]; then
        os_update_status='All updates installed'
    fi
done <<< "$kernel_pkgs"
(( kcare )) && [[ $PKG_KIND == deb && $os_update_status == NA && $APT_OK == 1 ]] && os_update_status='All updates installed'
# If the installed branch is past standard support and the repository check reports
# no in-branch update candidate, retain the requested update status while clearly
# separating the required OS migration in ISSUE/RECOMMENDATION and Section D.
if (( OS_STANDARD_EOL )) && [[ -z $os_repo_candidates ]] && { [[ $PKG_KIND != rpm ]] || (( RPM_CHECK_OK )); }; then
    os_update_status='All updates installed'
    kernel_updates+='Installed OS branch is past standard support; no in-branch release/kernel update candidate was reported. Migration is a separate action. '
fi
vendor_compare_note="$OS_VENDOR_REFERENCE_NOTE"
if [[ -n $OS_VENDOR_LATEST ]]; then
    installed_major=${OS_VERSION%%.*}; vendor_major=${OS_VENDOR_LATEST%%.*}
    if [[ $installed_major =~ ^[0-9]+$ && $vendor_major =~ ^[0-9]+$ && $vendor_major -gt $installed_major ]]; then
        vendor_compare_note+=" Newer major OS branch=$OS_VENDOR_LATEST is available; this requires migration/major upgrade, not a normal package update."
    elif [[ $OS_VENDOR_LATEST == *.* && $OS_VERSION == "$installed_major".* ]] && version_le "$OS_VERSION" "$OS_VENDOR_LATEST" && [[ $OS_VERSION != "$OS_VENDOR_LATEST" ]]; then
        os_update_status='Updates pending to install'
        vendor_compare_note+=" Installed release=$OS_VERSION is older than vendor release reference=$OS_VENDOR_LATEST."
    fi
fi
emit 'OPERATING SYSTEM' "$os_update_status" "OS=$OS_NAME; running kernel=$KERNEL; installed kernels: $(printf '%s' "$kernel_pkgs" | flat). ${kcare_note} In-branch candidates: ${kernel_updates:-none confirmed}. $RPM_CHECK_NOTE Debian cache age=$APT_AGE days. $vendor_compare_note Vendor URL=${OS_VENDOR_REFERENCE_URL:-not selected}. Standard-EOL=$OS_STANDARD_EOL." "$OFFPEAK"
php_ev=''; php_pending=0; php_unknown=0; php_count=0
while IFS=$'\t' read -r ver bin; do
    [[ -n $ver ]] || continue; ((php_count++)); state=$(php_eol "$ver"); latest=${BL_LATEST["php:${ver%.*}"]:-${PHP_LIVE_LATEST[${ver%.*}]:-}}
    php_ev+="$bin=$ver ($state upstream); "
    if [[ $state == 'End Of Life Period' && $bin == /opt/cpanel/ea-php* ]]; then
        ((php_pending++)); php_ev+='EasyApache upstream-EOL branch: supported-version migration required, not proof of a queued RPM update; '
    elif [[ -n $latest && $latest != - && $latest == "$ver" ]]; then :
    elif [[ -n $latest && $latest != - ]] && version_le "$ver" "$latest"; then ((php_pending++)); php_ev+="reviewed branch latest=$latest; "
    else ((php_unknown++)); fi
done <<< "$PHP_LIST"
php_status=NA; (( php_pending>0 )) && php_status='Updates pending to install'
(( php_count>0 && php_pending==0 && php_unknown==0 )) && php_status='All updates installed'
emit PHP "$php_status" "${php_ev:-No CLI PHP version found.} Package inventory: $(pkgmatch '(^php|php[0-9]|ea-php|alt-php)' | head -n 30 | flat). CLI discovery does not prove active FPM/vhost usage; version currency requires a reviewed baseline." "Map each site to its actual PHP handler, review deprecated branches and vendor backports. $OFFPEAK"
cms_ev=''; cms_pending=0; cms_unknown=$CMS_PARTIAL; cms_count=0
while IFS=$'\t' read -r product ver file; do
    [[ -n $product ]] || continue; ((cms_count++)); branch=$(printf '%s' "$ver" | cut -d. -f1-2); key="cms:$product:$branch"; latest=${BL_LATEST[$key]:-}
    [[ $product == wordpress && -z $latest ]] && latest=$WP_LATEST
    cms_ev+="$product $ver at $file; "
    if [[ $product == joomla && $ver == 3.* ]]; then ((cms_pending++)); cms_ev+='Joomla 3 requires migration from the retired branch; '
    elif [[ $product == wordpress && -z $latest ]] && version_le "$ver" 4.6.99; then ((cms_pending++)); cms_ev+='Retired WordPress branch requires upgrade; '
    elif [[ -n $latest && $latest != - && $ver == "$latest" ]]; then :
    elif [[ -n $latest && $latest != - ]] && version_le "$ver" "$latest"; then ((cms_pending++)); cms_ev+="reviewed latest=$latest; "
    else ((cms_unknown++)); fi
done <<< "$CMS_LIST"
report_cms=''; (( REPORT_FRESH )) && report_cms=$(printf '%s\n' "$REPORT_TEXT" | grep -Ei '(wordpress|drupal|joomla|moodle).*(version|[0-9]+\.[0-9]+)' | head -n 12 | flat)
cms_status=NA; (( cms_pending>0 )) && cms_status='Updates pending to install'
(( cms_count>0 && cms_pending==0 && cms_unknown==0 )) && cms_status='All updates installed'
cms_ev=$(printf '%s' "$cms_ev" | cut -c1-3000)
emit CMS "$cms_status" "Discovered=$cms_count; needing upgrade/migration=$cms_pending; currency unverified=$cms_unknown. $WP_REFERENCE_NOTE Examples (limited): ${cms_ev:-none}. Scope=$CMS_SCOPE partial=$CMS_PARTIAL. Includes staging/backup/old directory candidates; exposure is NOT inferred from directory names. Fresh report hints: ${report_cms:-none}; $REPORT_INFO Plugins/themes unverified." "$OFFPEAK"
package_updates 'WEB SERVER' "$WEB_PKGS" "$WEB_BINARIES"
package_updates 'DATABASE SERVER' "$DB_PKGS" "$DB_BINARIES"
package_updates 'OTHER SOFTWARES' "$OTHER_PKGS"

section 'C : Server Health'
uptime_seconds=$(awk '{printf "%.0f",$1}' /proc/uptime 2>/dev/null)
if [[ $uptime_seconds =~ ^[0-9]+$ ]] && (( uptime_seconds>=3600 )); then up_status=GOOD; else up_status='NOT GOOD'; fi
emit 'SERVER UPTIME' "$up_status" "Current uptime=${uptime_seconds:-unknown} seconds; minimum=3600. This measures time since boot, not historical reliability." 'Review recent reboot reasons if under one hour; correlate with authorized maintenance and monitoring history.'
http_status='NOT GOOD'; http_ev=''; web_running=0; web_bad=0
declare -A HTTP_SEEN
for svc in nginx apache2 httpd lsws litespeed; do
    if active "$svc"; then
        service_age=''; service_key=''; main_pid=''
        if have systemctl && [[ -d /run/systemd/system ]]; then
            properties=$(run systemctl show "$svc" -p Id -p MainPID -p ActiveState -p ActiveEnterTimestampMonotonic)
            start=$(printf '%s\n' "$properties" | sed -n 's/^ActiveEnterTimestampMonotonic=//p')
            main_pid=$(printf '%s\n' "$properties" | sed -n 's/^MainPID=//p')
            unit_id=$(printf '%s\n' "$properties" | sed -n 's/^Id=//p')
            if printf '%s\n' "$properties" | grep -Fxq 'ActiveState=active' && [[ $start =~ ^[0-9]+$ && $uptime_seconds =~ ^[0-9]+$ ]] && (( start>0 )); then
                service_age=$((uptime_seconds-start/1000000)); service_key="unit:$unit_id"
                [[ $main_pid =~ ^[1-9][0-9]*$ ]] && service_key="pid:$main_pid"
            fi
        fi
        if [[ -z $service_age ]] && have ps; then
            read -r process_pid process_age < <(run ps -C "$svc" -o pid=,etimes= | sort -k2,2nr | head -n 1)
            if [[ $process_pid =~ ^[0-9]+$ && $process_age =~ ^[0-9]+$ ]]; then service_key="pid:$process_pid"; service_age=$process_age; fi
        fi
        [[ -n $service_key ]] || service_key="unverified:$svc"
        [[ -n ${HTTP_SEEN[$service_key]:-} ]] && continue; HTTP_SEEN[$service_key]=1
        ((web_running++))
        if [[ $service_age =~ ^[0-9]+$ ]] && (( service_age>=3600 )); then http_ev+="$svc uptime=$service_age seconds ($service_key); "
        else ((web_bad++)); http_ev+="$svc running; age=${service_age:-unverified} seconds ($service_key); "; fi
    fi
done
(( web_running>0 && web_bad==0 )) && http_status=GOOD
for url in "${HTTP_URLS[@]}"; do
    if (( OFFLINE )) || ! have curl; then http_ev+='Requested HTTP check skipped (offline/curl unavailable); '; http_status='NOT GOOD'; continue; fi
    # -q ignores curlrc; no redirects, cookies, credentials or response body stored.
    code=$(run curl -q --noproxy '*' --proto '=http,https' --connect-timeout 4 --max-time 10 -sS -I -o /dev/null -w '%{http_code}' -- "$url"); curl_rc=$?
    if (( curl_rc==0 )) && [[ $code =~ ^[23][0-9][0-9]$ ]]; then http_ev+="Requested endpoint returned HTTP $code; "
    else http_ev+="Requested endpoint failed/unhealthy or HEAD unsupported (curl=$curl_rc HTTP=$code); "; http_status='NOT GOOD'; fi
done
emit 'HTTP UPTIME' "$http_status" "${http_ev:-No supported running local web service confirmed.} Current service age is not historical HTTP availability; ${#HTTP_URLS[@]} explicit URL(s)." 'Review external uptime history and critical virtual hosts. Use --http-url for known safe health endpoints; no default website requests are made.'
cpu_sample() { awk '/^cpu / {total=0;for(i=2;i<=9;i++)total+=$i;print total,$5+$6;exit}' /proc/stat; }
read -r total1 idle1 < <(cpu_sample); sleep 2; read -r total2 idle2 < <(cpu_sample)
cores=$(awk '/^processor[[:space:]]*:/{n++} END{print n+0}' /proc/cpuinfo)
load1=$(awk '{print $1}' /proc/loadavg)
cpu_busy='unknown'; cpu_status='NOT GOOD'; load_pct='unknown'
if [[ $total1 =~ ^[0-9]+$ && $total2 =~ ^[0-9]+$ ]] && (( total2>total1 && cores>0 )); then
    cpu_busy=$((100*(total2-total1-idle2+idle1)/(total2-total1)))
    load_pct=$(awk -v l="$load1" -v n="$cores" 'BEGIN{printf "%.0f",100*l/n}')
    (( cpu_busy<CPU_MAX && load_pct<CPU_MAX )) && cpu_status=GOOD
fi
emit 'CPU USAGE' "$cpu_status" "Two-second busy=$cpu_busy%; 1-minute load=$load1; cores=$cores; load/core=$load_pct%; threshold=$CPU_MAX%. Load includes uninterruptible waits." 'Correlate sustained load, CPU steal and I/O wait with monitoring; a short sample can miss spikes.'
read -r mem_total mem_avail mem_method < <(awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2;has=1}/^MemFree:/{f=$2}/^Buffers:/{b=$2}/^Cached:/{c=$2}/^SReclaimable:/{r=$2}/^Shmem:/{s=$2} END{if(has)print t,a,"MemAvailable";else print t,f+b+c+r-s,"estimated"}' /proc/meminfo)
ram_status='NOT GOOD'; ram_used=unknown
if [[ $mem_total =~ ^[0-9]+$ && $mem_avail =~ ^[0-9]+$ ]] && (( mem_total>0 && mem_avail<=mem_total )); then
    ram_used=$((100*(mem_total-mem_avail)/mem_total)); (( ram_used<RAM_MAX )) && ram_status=GOOD
fi
swap_ev=$(awk '/^SwapTotal:/{t=$2}/^SwapFree:/{f=$2} END{printf "swap-used=%d KiB of %d KiB",t-f,t}' /proc/meminfo)
emit 'RAM USAGE' "$ram_status" "Used excluding available cache=$ram_used%; threshold=$RAM_MAX%; method=$mem_method; $swap_ev." 'Review sustained memory pressure, swap activity and OOM events before changing memory allocations.'
disk_status=GOOD; disk_ev=''; dfout=$(run df -P -l -k); dfrc=$?; inodeout=$(run df -P -l -i); ifrc=$?
if (( dfrc!=0 || ifrc!=0 )); then disk_status='NOT GOOD'; disk_ev+='UNVERIFIED: filesystem statistics failed; '; fi
disk_bad=$(printf '%s\n' "$dfout" | awk -v max="$DISK_MAX" 'NR>1 {v=$5;gsub(/%/,"",v);if(v+0>=max)print $1 " " $5 " " $6}')
inode_bad=$(printf '%s\n' "$inodeout" | awk -v max="$DISK_MAX" 'NR>1 {v=$5;gsub(/%/,"",v);if(v ~ /^[0-9]+$/ && v+0>=max)print $1 " " $5 " " $6}')
[[ -n $disk_bad || -n $inode_bad ]] && disk_status='NOT GOOD'
disk_ev+="Local filesystem threshold=$DISK_MAX%. Space alerts: ${disk_bad:-none}. Inode alerts: ${inode_bad:-none}. Remote filesystems excluded to avoid stalled network mounts."
emit 'DISC SPACE USAGE' "$disk_status" "$disk_ev" 'Review growth and inode use on alerted mounts; obtain developer approval before removing application files. Review remote mount capacity separately.'
queue_status='NOT GOOD'; queue_ev='UNVERIFIED: no supported readable mail queue.'; queue_total=0; queue_seen=0; queue_unknown=0
if have exim; then
    q=$(run exim -bpc)
    if [[ $q =~ ^[0-9]+$ ]]; then ((queue_seen++)); ((queue_total+=q)); queue_ev="Exim messages=$q; "; else ((queue_unknown++)); fi
fi
if have postqueue; then
    qout=$(run postqueue -p); qrc=$?; q=''
    if (( qrc==0 )); then
        if [[ $qout == *'Mail queue is empty'* ]]; then q=0
        else q=$(printf '%s\n' "$qout" | sed -nE 's/^-- .* in ([0-9]+) Request(s)?\..*/\1/p' | tail -n 1); fi
    fi
    if [[ $q =~ ^[0-9]+$ ]]; then ((queue_seen++)); ((queue_total+=q)); queue_ev+="Postfix messages=$q; "; else ((queue_unknown++)); fi
fi
(( queue_seen>0 && queue_unknown==0 && queue_total<=QUEUE_MAX )) && queue_status=GOOD
emit 'EMAIL QUEUE' "$queue_status" "$queue_ev Total confirmed=$queue_total; threshold=$QUEUE_MAX; unreadable queues=$queue_unknown. Sendmail/other MTAs need manual review; no message content printed." 'Inspect queue age, deferrals, delivery rates and legitimate traffic volume. Do not delete or flush messages without approval.'

dns_query() { run dig +time=3 +tries=1 +noall +comments +answer "$@"; }
dns_code() { sed -nE 's/.*status: ([A-Z]+),.*/\1/p' | head -n 1; }
dns_a() { awk '$4=="A" {print $5}'; }
reputation_status='NOT GOOD'; reputation_ev='UNVERIFIED: requires a selected public IPv4, dig and network access.'
if (( ! OFFLINE )) && [[ -n $TARGET_IP ]] && have dig; then
    IFS=. read -r a b c d <<< "$TARGET_IP"; reverse="$d.$c.$b.$a"
    reputation_ev=''; dns_listed=0; dns_clean=0; dns_unknown=0
    # Small maintained set; query positive AND negative controls before trusting NXDOMAIN.
    for zone in zen.spamhaus.org bl.spamcop.net; do
        pos=$(dns_query "2.0.0.127.$zone" A); neg=$(dns_query "1.0.0.127.$zone" A)
        pos_codes=$(printf '%s\n' "$pos" | dns_a); neg_status=$(printf '%s\n' "$neg" | dns_code)
        if ! printf '%s\n' "$pos_codes" | grep -Eq '^127\.0\.0\.(2|3|4|9|10|11)$' ||
           printf '%s\n' "$pos_codes" | grep -Eq '^127\.255\.255\.' || [[ $neg_status != NXDOMAIN ]]; then
            ((dns_unknown++)); reputation_ev+="$zone query controls failed/blocked; "; continue
        fi
        ans=$(dns_query "$reverse.$zone" A); code=$(printf '%s\n' "$ans" | dns_code); codes=$(printf '%s\n' "$ans" | dns_a)
        if [[ $code == NXDOMAIN ]]; then ((dns_clean++)); reputation_ev+="$zone not listed; "
        elif [[ $code == NOERROR ]] && [[ -n $codes ]]; then
            valid=1
            while read -r answer; do
                if [[ $zone == zen.spamhaus.org ]]; then [[ $answer =~ ^127\.0\.0\.(2|3|4|9|10|11)$ ]] || valid=0
                else [[ $answer == 127.0.0.2 ]] || valid=0; fi
            done <<< "$codes"
            if (( valid )); then ((dns_listed++)); reputation_ev+="$zone LISTED ($codes); "
            else ((dns_unknown++)); reputation_ev+="$zone provider error/unrecognized response ($codes); "; fi
        else ((dns_unknown++)); reputation_ev+="$zone DNS response unverified ($code); "; fi
    done
    (( dns_listed==0 && dns_unknown==0 && dns_clean==2 )) && reputation_status=GOOD
    reputation_ev+="IP=$TARGET_IP; listed=$dns_listed not-listed=$dns_clean unverified=$dns_unknown. Results cover only these two lists; PBL policy listings are not proof of malware."
fi
if (( IP_MISMATCH )); then reputation_status='NOT GOOD'; reputation_ev+=" OWNERSHIP UNVERIFIED: $IP_NOTE"; fi
emit 'IP REPUTATION' "$reputation_status" "$reputation_ev" 'Confirm actual outbound SMTP IP, provider terms, and authenticated reputation dashboards. DNS errors/rate limits are unknown, never clean. Investigate listing reasons before requesting delisting.'

section 'D : Software Life Time'
panel_end=${BL_EOL[$panel_key]:-}; panel_life=NA; panel_life_note=''
if [[ $PANEL == cpanel && $PANEL_VER == 11.110.* && ( $OS_ID == cloudlinux || $OS_NAME == CloudLinux* ) && $OS_VERSION == 7* ]]; then
    panel_life='End Of Life Period'
    panel_end='legacy OS-capped branch'
    panel_life_note='cPanel & WHM 110 is the last branch compatible with CloudLinux 7. The audit classifies this OS-capped legacy branch as EOL for migration planning; any cPanel/CloudLinux ELS critical-update entitlement must be validated separately.'
elif [[ -n $panel_end && $panel_end != - ]]; then
    if [[ $TODAY > $panel_end ]]; then panel_life='End Of Life Period'; else panel_life='Support Period Active'; fi
elif [[ $PANEL == cpanel && -n $CPANEL_TIERS ]]; then
    installed_branch=$(printf '%s' "$PANEL_VER" | cut -d. -f2)
    if printf '%s\n' "$CPANEL_TIERS" | awk -F '\t' -v b="$installed_branch" '$1!="edge"{split($2,v,".");if(v[2]==b)found=1}END{exit !found}'; then
        panel_life='Support Period Active'; panel_end='current vendor tier membership (no fixed date inferred)'
    fi
fi
emit 'CONTROL PANEL' "$panel_life" "Panel=$PANEL version=${PANEL_VER:-none}; reviewed/support reference=${panel_end:-unknown}. $panel_life_note $CPANEL_LOCAL_CHECK_NOTE" "Check vendor support policy if a panel is present. $OFFPEAK"
os_life=NA; os_end=${BL_EOL["os:$OS_ID:$OS_VERSION"]:-}; os_note='Vendor support and entitlement unverified.'
if [[ -n $os_end && $os_end != - ]]; then
    if [[ $TODAY > $os_end ]]; then os_life='End Of Life Period'; else os_life='Support Period Active'; fi
    os_note="Reviewed standard/vendor support end=$os_end."
elif [[ $OS_ID == cloudlinux || $OS_NAME == CloudLinux* ]]; then
    case "$OS_VERSION" in
        7|7.*) os_end=2024-06-30;; 8|8.*) os_end=2029-05-31;;
        9|9.*) os_end=2032-05-31;; 10|10.*) os_end=2035-05-31;;
    esac
    if [[ -n $os_end && $os_end != - ]]; then
        if [[ $TODAY > $os_end ]]; then os_life='End Of Life Period'; else os_life='Support Period Active'; fi
        os_note="CloudLinux vendor branch lifecycle end=$os_end. License/subscription, optional ELS and package patch currency are separate checks."
    fi
elif [[ $OS_ID == centos && $OS_NAME != *Stream* ]]; then
    case "$OS_VERSION" in 7|7.*) os_life='End Of Life Period'; os_note='CentOS Linux 7 upstream support ended 2024-06-30.';;
        8|8.*) os_life='End Of Life Period'; os_note='CentOS Linux 8 upstream support ended 2021-12-31.';; esac
elif [[ $OS_ID == ubuntu ]]; then
    end_month=''
    case "$OS_VERSION" in
        14.04) end_month=2019-04;; 16.04) end_month=2021-04;; 18.04) end_month=2023-05;;
        20.04) end_month=2025-05;; 22.04) end_month=2027-05;; 24.04) end_month=2029-05;; 26.04) end_month=2031-05;;
    esac
    if [[ -n $end_month ]]; then
        os_note="Ubuntu standard security maintenance ends in $end_month; Pro/ESM entitlement and package coverage unverified."
        if [[ ${TODAY:0:7} > $end_month ]]; then os_life='End Of Life Period'
        elif [[ ${TODAY:0:7} < $end_month ]]; then os_life='Support Period Active'
        else os_note+=' Exact transition date requires verification this month.'; fi
    fi
elif [[ $OS_ID == almalinux || $OS_ID == rocky ]]; then
    # The major lifecycle is not a promise that an obsolete minor stays supported.
    current_minor=''; os_end=''
    case "$OS_VERSION" in
        8.*) current_minor=8.10; os_end=2029-05-31;;
        9.*) current_minor=9.8; os_end=2032-05-31;;
        10.*) current_minor=10.2; os_end=2035-05-31;;
    esac
    os_note="Major branch security end=${os_end:-unknown}; minor-release support must also be verified. Release snapshot reviewed 2026-10-02."
    if [[ -n $os_end && $TODAY > $os_end ]]; then os_life='End Of Life Period'
    elif [[ $OS_VERSION == 8.10 ]]; then os_life='Support Period Active'
    elif [[ -n $current_minor && $OS_VERSION != "$current_minor" ]] && version_le "$OS_VERSION" "$current_minor"; then
        os_life='End Of Life Period'; os_note+=' Detected minor was superseded in the reviewed release snapshot.'
    elif [[ $OS_VERSION == "$current_minor" && $TODAY < 2026-11-02 && $TODAY > 2026-10-01 ]]; then os_life='Support Period Active'; fi
fi
[[ $KERNEL == *tuxcare* || $KERNEL == *els* ]] && os_note+=' Extended-support kernel marker detected; this does not prove a current subscription, patch level or userspace coverage.'
emit 'OPERATING SYSTEM' "$os_life" "$OS_NAME. $os_note $OS_VENDOR_REFERENCE_NOTE Vendor URL=${OS_VENDOR_REFERENCE_URL:-not selected}." "Verify vendor lifecycle and paid extended-support entitlement. Plan supported-OS migration where appropriate. $OFFPEAK"
cms_life=NA; cms_eol=0; cms_supported=0; cms_life_unknown=$CMS_PARTIAL
while IFS=$'\t' read -r product ver file; do
    [[ -n $product ]] || continue; branch=$(printf '%s' "$ver" | cut -d. -f1-2); end=${BL_EOL["cms:$product:$branch"]:-}
    if [[ -n $end && $end != - ]]; then
        if [[ $TODAY > $end ]]; then ((cms_eol++)); else ((cms_supported++)); fi
    elif [[ $product == joomla && $ver == 3.* ]]; then ((cms_eol++))
    elif [[ $product == wordpress && -n $WP_LATEST ]]; then
        if [[ $branch == "${WP_LATEST%.*}" ]]; then ((cms_supported++))
        elif version_le "$ver" "$WP_LATEST"; then ((cms_eol++)); else ((cms_life_unknown++)); fi
    elif [[ $product == wordpress ]] && version_le "$ver" 4.6.99; then ((cms_eol++))
    else ((cms_life_unknown++)); fi
done <<< "$CMS_LIST"
(( cms_eol>0 )) && cms_life='End Of Life Period'
(( cms_count>0 && cms_eol==0 && cms_life_unknown==0 )) && cms_life='Support Period Active'
emit CMS "$cms_life" "Detected CMS=$cms_count; unsupported branches=$cms_eol supported-branch=$cms_supported unverified=$cms_life_unknown. $WP_REFERENCE_NOTE WordPress officially supports its current major release; backports to older branches do not guarantee support. Joomla 3 upstream support ended 2023-08-17. Archive/staging candidates are included; confirm web exposure. Examples: $cms_ev Fresh report hints: ${report_cms:-none}. $REPORT_INFO" "$OFFPEAK"
stack_life=NA; stack_ev=''; stack_eol=0; stack_unknown=0; stack_seen=0
while IFS=$'\t' read -r ver bin; do
    [[ -n $ver ]] || continue; ((stack_seen++)); state=$(php_eol "$ver"); stack_ev+="PHP $ver: $state upstream; "
    [[ $state == 'End Of Life Period' ]] && ((stack_eol++)); [[ $state == NA ]] && ((stack_unknown++))
done <<< "$PHP_LIST"
while IFS=$'\t' read -r name ver; do
    [[ -n $name ]] || continue; ((stack_seen++)); end=${BL_EOL["pkg:$name"]:-}
    if [[ -z $end || $end == - ]]; then ((stack_unknown++))
    elif [[ $TODAY > $end ]]; then ((stack_eol++)); stack_ev+="$name support ended $end; "; fi
done < <(printf '%s\n%s\n%s\n' "$WEB_PKGS" "$DB_PKGS" "$OTHER_PKGS" | sort -u)
(( stack_eol>0 )) && stack_life='End Of Life Period'
(( stack_seen>0 && stack_unknown==0 && stack_eol==0 )) && stack_life='Support Period Active'
emit 'SOFTWARE STACK' "$stack_life" "$stack_ev Unverified component lifecycles=$stack_unknown. Upstream PHP EOL can differ from contracted distro/CloudLinux/TuxCare backport support; no entitlement inferred." "Confirm support for actual web, PHP, database, mail and DNS stack, including custom builds and vendor backports. $OFFPEAK"

section 'E : Proactive Defence'
tmp_status='Not Configured'; tmp_ev='UNVERIFIED: /tmp mount options unavailable.'
if have findmnt; then
    opts=$(run findmnt -n -T /tmp -o OPTIONS); perms=$(stat -c %a /tmp 2>/dev/null)
    tmp_ev="Effective /tmp mount options=$opts; permissions=$perms."
    if [[ ,$opts, == *,noexec,* && ,$opts, == *,nosuid,* && ,$opts, == *,nodev,* && $perms == 1777 ]]; then tmp_status=Configured; fi
fi
emit '/tmp SECURITY' "$tmp_status" "$tmp_ev noexec does not prevent an interpreter from reading a script in /tmp." 'Review noexec,nosuid,nodev and sticky permissions with application owners; also review /var/tmp and /dev/shm. No mount or permission changes were made.'
emit 'REBOOT PROCEDURE' '' '' ''
rdns_status='Not Configured'; rdns_ev='UNVERIFIED: requires public IPv4, dig and network access.'
if (( ! OFFLINE )) && [[ -n $TARGET_IP ]] && have dig; then
    ptrout=$(dns_query -x "$TARGET_IP"); ptr_status=$(printf '%s\n' "$ptrout" | dns_code)
    ptrs=$(printf '%s\n' "$ptrout" | awk '$4=="PTR"{print $5}')
    rdns_ev="IP=$TARGET_IP; PTR status=$ptr_status; records=${ptrs:-none}. "
    while read -r ptr; do
        [[ $ptr =~ ^[A-Za-z0-9_.-]+\.$ ]] || continue
        forward=$(dns_query "$ptr" A | dns_a)
        if printf '%s\n' "$forward" | grep -Fxq "$TARGET_IP"; then rdns_status=Configured; rdns_ev+='Forward-confirmed PTR found; '; fi
    done <<< "$ptrs"
fi
if (( IP_MISMATCH )); then rdns_status='Not Configured'; rdns_ev+=" OWNERSHIP UNVERIFIED: $IP_NOTE"; fi
emit 'IP RDNS' "$rdns_status" "$rdns_ev" 'Set PTR through the IP provider and confirm its forward A record matches the mail egress IP and SMTP hostname; PTR alone does not guarantee delivery.'
for kind in MALWARE ROOTKIT; do
    result=$MALWARE_RESULT; item='MALWARE SCAN'; [[ $kind == ROOTKIT ]] && { result=$ROOTKIT_RESULT; item='ROOTKIT CHECK'; }
    case "$result" in
        clean) status=Configured; issue="Recent completed $kind summary reports zero findings. $REPORT_INFO Report scope and authenticity require review; this is not proof of absence of compromise.";;
        found) status='Not Configured'; issue="$kind findings reported. $REPORT_INFO Findings need investigation; nothing removed or rescanned.";;
        *) status='MALWARE SCAN NEEDED'; issue="$kind result unverified: missing/stale/incomplete/unrecognized report section or warnings/errors in that section. $REPORT_INFO";;
    esac
    emit "$item" "$status" "$issue" 'Review the existing report, scope, timestamps and findings. Arrange a separately approved scan if evidence is missing or inconclusive; this audit never scans or cleans files.'
done
# SSH: evaluate the effective configuration for the root user, then flag only
# files that actually set a permissive PermitRootLogin value.
ssh_status='Not Configured'; ssh_ev='UNVERIFIED: effective OpenSSH configuration unavailable.'
if have sshd; then
    sshcfg=$(run sshd -T -C user=root,host=localhost,addr=127.0.0.1); sshrc=$?
    ssh_mode='effective config for user root (sshd -T -C)'
    if (( sshrc!=0 )); then sshcfg=$(run sshd -T); sshrc=$?; ssh_mode='sshd -T (no connection context)'; fi
    rootlogin=$(printf '%s\n' "$sshcfg" | awk '$1=="permitrootlogin"{print $2;exit}')
    permissive_files=$(run grep -rIliE '^[[:space:]]*PermitRootLogin[[:space:]]+(yes|without-password|prohibit-password|forced-commands-only)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d | flat)
    ssh_ev="$ssh_mode: PermitRootLogin=${rootlogin:-unknown} (sshd exit=$sshrc). Files with a permissive PermitRootLogin line: ${permissive_files:-none}."
    if (( sshrc==0 )) && [[ $rootlogin == no && -z $permissive_files ]]; then
        ssh_status=Configured
        ssh_ev+=' Root password and key login are both refused for root from the evaluated context; a daemon started with a non-default config path (-f) is not covered.'
    else
        ssh_ev+=' Root login is not confirmed disabled; prohibit-password still permits root keys.'
    fi
fi
emit 'SSH ROOT ACCESS SECURITY' "$ssh_status" "$ssh_ev" 'Review effective sshd settings for each Match context and actual daemon config path. If changing access, first verify a named sudo account and recovery access; this script changes nothing.'

# PHP functions: judge the PHP handlers actually in use, not every INI on disk.
php_required=(exec shell_exec system passthru popen proc_open)
php_missing() {
    local v f m=''
    v=$(awk '/^[[:space:]]*disable_functions[[:space:]]*=/ {x=substr($0,index($0,"=")+1);sub(/[;#].*/,"",x);print x}' "$1" 2>/dev/null | tail -n 1 | tr -d ' \t\r"')
    v=",${v,,},"
    for f in "${php_required[@]}"; do [[ $v == *",$f,"* ]] || m+="$f "; done
    printf '%s' "$m"
}
php_config_ev=''; php_configs=0; declare -A PHP_INI_MISSING PHP_INI_INUSE
for file in /etc/php.ini /etc/php.d/*.ini /etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini /etc/php/*/cli/php.ini /opt/remi/php*/root/etc/php.ini /opt/alt/php*/etc/php.ini /opt/cpanel/ea-php*/root/etc/php.ini; do
    [[ -f $file && -r $file ]] || continue; ((php_configs++))
    PHP_INI_MISSING[$file]=$(php_missing "$file")
done
php_inuse=''
if [[ $PANEL == cpanel && -d /var/cpanel/userdata ]]; then
    php_inuse=$(timeout -k 2s 20s grep -rhE '^phpversion:[[:space:]]*[A-Za-z0-9._-]+' /var/cpanel/userdata --exclude='*.cache' --exclude='*.json' 2>/dev/null | awk '{print $2}' | sort -u)
    php_default=$(awk -F: '$1=="default"{v=$2;gsub(/[[:space:]"\047]/,"",v);print v;exit}' /etc/cpanel/ea4/php.conf 2>/dev/null)
    [[ $php_default =~ ^[A-Za-z0-9._-]+$ ]] && php_inuse=$(printf '%s\n%s\n' "$php_inuse" "$php_default" | awk 'NF' | sort -u)
fi
php_inuse_ok=0; php_inuse_bad=''; php_inuse_unverified=''
while read -r handler; do
    [[ -n $handler ]] || continue
    case "$handler" in
        ea-php*) ini=/opt/cpanel/$handler/root/etc/php.ini;;
        alt-php*) ini=/opt/alt/${handler#alt-}/etc/php.ini;;
        *) php_inuse_unverified+="$handler (unknown handler type); "; continue;;
    esac
    if [[ -r $ini ]]; then
        PHP_INI_INUSE[$ini]=1
        pm=${PHP_INI_MISSING[$ini]-}; [[ -n ${PHP_INI_MISSING[$ini]+set} ]] || pm=$(php_missing "$ini")
        if [[ -z $pm ]]; then ((php_inuse_ok++)); else php_inuse_bad+="$handler ($ini) does not disable: $pm; "; fi
    else php_inuse_unverified+="$handler (INI $ini unreadable); "; fi
done <<< "$php_inuse"
php_sec=NA; php_config_ev=''
if [[ -n $php_inuse ]]; then
    php_config_ev="In-use PHP handlers (cPanel userdata + EasyApache default): $(printf '%s' "$php_inuse" | tr '\n' ' '). Compliant=$php_inuse_ok. ${php_inuse_bad:+Non-compliant: $php_inuse_bad}${php_inuse_unverified:+Unverified: $php_inuse_unverified}"
    if [[ -z $php_inuse_bad && -z $php_inuse_unverified ]] && (( php_inuse_ok>0 )); then php_sec=Configured; else php_sec='Not Configured'; fi
    review_list=''; review_count=0
    for ini in "${!PHP_INI_MISSING[@]}"; do
        [[ -n ${PHP_INI_INUSE[$ini]:-} || -z ${PHP_INI_MISSING[$ini]} ]] && continue
        ((review_count++)); (( review_count<=6 )) && review_list+="$ini; "
    done
    php_config_ev+=" Other INI files lacking restrictions and not matched to an in-use handler: $review_count (examples: ${review_list:-none}); informational only. CloudLinux PHP Selector per-user choices are not read, so review these if the selector is used."
elif (( php_configs>0 )); then
    php_bad_all=''
    for ini in "${!PHP_INI_MISSING[@]}"; do [[ -n ${PHP_INI_MISSING[$ini]} ]] && php_bad_all+="$ini lacks: ${PHP_INI_MISSING[$ini]}; "; done
    php_config_ev="In-use handlers could not be determined (no cPanel userdata); every discovered INI was evaluated ($php_configs files). ${php_bad_all:-All discovered INI files disable the required functions.}"
    if [[ -z $php_bad_all ]]; then php_sec=Configured; else php_sec='Not Configured'; fi
fi
[[ -n $PHP_LIST || $php_configs -gt 0 ]] || php_sec=NA
emit 'PHP FUNCTIONS SECURITY' "$php_sec" "${php_config_ev:-No conventional PHP INI files found.} Required: ${php_required[*]}. UNVERIFIED per-site .user.ini/php_admin_value overrides and container configuration. A CLI INI value is not proof of website settings." 'Review required restrictions for exec,passthru,shell_exec,system,proc_open,popen and application needs with developers. disable_functions is not a complete security boundary; do not disable functions blindly.'
pw_status='Not Configured'; pw_ev='UNVERIFIED root password age.'
if [[ -r /etc/shadow ]]; then
    # Emit only last-change day and lock classification, never password hashes.
    read -r changed lockstate < <(awk -F: '$1=="root" {s=($2 ~ /^[!*]/ ? "locked" : ($2==""?"empty":"set"));print $3,s;exit}' /etc/shadow)
    if [[ $changed =~ ^[0-9]+$ ]]; then
        pw_age=$((NOW/86400-changed)); pw_ev="Root password last-change age=$pw_age days; password state=$lockstate."
        if [[ $lockstate == locked ]]; then pw_status=NA; pw_ev+=' Password login is locked; this does not disable root SSH keys.'
        elif [[ $lockstate == set ]] && (( changed>0 && pw_age>=0 && pw_age<=90 )); then pw_status=Configured; fi
    fi
fi
emit 'ROOT PASSWORD HEALTH' "$pw_status" "$pw_ev" 'For password-enabled root, apply the requested 90-day policy through the approved credential process. Review key-only/locked accounts separately; no password hash is displayed.'

section 'F : Backup'
# Recognize backup jobs by command basename, not arbitrary comments or filenames.
backup_re='(^|[[:space:]/])(rsnapshot|restic|borg|borgmatic|duplicity|rdiff-backup|automysqlbackup|autopostgresqlbackup)([[:space:]]|$)'
cron_alive=0; active crond cron && cron_alive=1
schedule_ev=''; local_job=0; daily=0; weekly=0; monthly=0
cp_backup_enabled=0; cp_keep_local=0; cp_backup_config=''; cp_dir=''; cp_backup_type=''
cp_daily_ret=''; cp_weekly_ret=''; cp_monthly_ret=''; cp_monthly_dates=''; cp_weekly_day=''; cp_daily_days=''
cp_scheduler_seen=0; cp_remote_enabled=0; cp_local_dest_enabled=0; cp_dest_disabled=0; cp_dest_ev=''

# Read scalar YAML values only; never source config or run a backup/API mutation.
yaml_scalar() {
    awk -v wanted="$2" 'index($0,":") {k=substr($0,1,index($0,":")-1);gsub(/^[[:space:]]+|[[:space:]]+$/,"",k);if(k==wanted){v=substr($0,index($0,":")+1);sub(/[[:space:]]+#.*/,"",v);gsub(/^[[:space:]]+|[[:space:]]+$/,"",v);gsub(/^["\047]|["\047]$/,"",v);print v;exit}}' "$1" 2>/dev/null
}

if [[ $PANEL == cpanel && -r /var/cpanel/backups/config ]]; then
    cp_backup_config=/var/cpanel/backups/config
    cp_enable=$(yaml_scalar "$cp_backup_config" BACKUPENABLE)
    cp_keep=$(yaml_scalar "$cp_backup_config" KEEPLOCAL)
    cp_dir=$(yaml_scalar "$cp_backup_config" BACKUPDIR)
    cp_backup_type=$(yaml_scalar "$cp_backup_config" BACKUPTYPE)
    cp_daily_days=$(yaml_scalar "$cp_backup_config" BACKUPDAYS)
    cp_daily_ret=$(yaml_scalar "$cp_backup_config" BACKUP_DAILY_RETENTION)
    cp_weekly_ret=$(yaml_scalar "$cp_backup_config" BACKUP_WEEKLY_RETENTION)
    cp_monthly_ret=$(yaml_scalar "$cp_backup_config" BACKUP_MONTHLY_RETENTION)
    cp_monthly_dates=$(yaml_scalar "$cp_backup_config" BACKUP_MONTHLY_DATES)
    cp_weekly_day=$(yaml_scalar "$cp_backup_config" BACKUP_WEEKLY_DAY)
    [[ $cp_enable =~ ^(yes|1|true)$ ]] && cp_backup_enabled=1
    [[ $cp_keep =~ ^(yes|1|true)$ ]] && cp_keep_local=1
    if (( cp_backup_enabled )); then
        [[ $(yaml_scalar "$cp_backup_config" BACKUP_DAILY_ENABLE) =~ ^(yes|1|true)$ ]] && daily=1
        [[ $(yaml_scalar "$cp_backup_config" BACKUP_WEEKLY_ENABLE) =~ ^(yes|1|true)$ ]] && weekly=1
        [[ $(yaml_scalar "$cp_backup_config" BACKUP_MONTHLY_ENABLE) =~ ^(yes|1|true)$ ]] && monthly=1
    fi
    [[ $cp_dir == /* && -d $cp_dir ]] && BACKUP_DIRS+=("$cp_dir")
    schedule_ev+="cPanel backup enabled=$cp_backup_enabled KEEPLOCAL=$cp_keep_local directory=${cp_dir:-unknown} type=${cp_backup_type:-unknown}; daily=$daily days=${cp_daily_days:-unknown} retention=${cp_daily_ret:-unknown}; weekly=$weekly day=${cp_weekly_day:-unknown} retention=${cp_weekly_ret:-unknown}; monthly=$monthly dates=${cp_monthly_dates:-unknown} retention=${cp_monthly_ret:-unknown}; "

    for dest in /var/cpanel/backups/*.backup_destination; do
        [[ -f $dest && -r $dest && ! -L $dest ]] || continue
        dest_disabled=$(yaml_scalar "$dest" disabled); dest_type=$(yaml_scalar "$dest" type); dest_name=$(yaml_scalar "$dest" name)
        case "${dest_disabled,,}" in 1|yes|true) ((cp_dest_disabled++)); continue;; esac
        if [[ ${dest_type,,} == local* || ${dest_type,,} == *local*directory* ]]; then
            ((cp_local_dest_enabled++))
        else
            ((cp_remote_enabled++))
        fi
        cp_dest_ev+="enabled destination name=${dest_name:-unnamed} type=${dest_type:-unknown}; "
    done

    # Confirm the standard cPanel backup scheduler is present without running it.
    for sched in /etc/cron.d/* /etc/crontab; do
        [[ -f $sched && -r $sched && ! -L $sched ]] || continue
        if grep -Eq '/usr/local/cpanel/bin/backup([[:space:]]|$)' "$sched" 2>/dev/null; then cp_scheduler_seen=1; break; fi
    done
    schedule_ev+="cPanel scheduler entry detected=$cp_scheduler_seen; additional destinations remote=$cp_remote_enabled local=$cp_local_dest_enabled disabled=$cp_dest_disabled; "
fi

# JetBackup (read-only listing). Frequency is recognised from job NAMES only;
# the job schedule and enabled state are not parsed, and ISSUE says so.
jb_present=0; jb_ev=''; jb_daily=0; jb_weekly=0; jb_monthly=0; jb_jobs=0
if have jetbackup5api || active jetbackup5d jetbackupd; then jb_present=1; fi
if have jetbackup5api; then
    jb_out=$(run jetbackup5api -F listBackupJobs -D 'limit=0' -O json); jb_rc=$?
    printf '%s' "$jb_out" | grep -Eq '"success"[[:space:]]*:[[:space:]]*1' || { jb_out=$(run jetbackup5api -F listBackupJobs -D 'limit=0'); jb_rc=$?; }
    if (( jb_rc==0 )) && printf '%s' "$jb_out" | grep -Eq '"success"[[:space:]]*:[[:space:]]*1'; then
        jb_names=$(printf '%s' "$jb_out" | grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed -E 's/^"name"[[:space:]]*:[[:space:]]*"([^"]*)"/\1/' | sort -u)
        jb_jobs=$(printf '%s\n' "$jb_names" | awk 'NF{n++}END{print n+0}')
        printf '%s\n' "$jb_names" | grep -qi 'daily' && jb_daily=1
        printf '%s\n' "$jb_names" | grep -qi 'weekly' && jb_weekly=1
        printf '%s\n' "$jb_names" | grep -qi 'monthly' && jb_monthly=1
        jb_ev="JetBackup5 listBackupJobs responded; names seen=$(printf '%s' "$jb_names" | head -n 12 | tr '\n' ',' | flat) (heuristic: frequency taken from job NAME only; schedule/enabled state not parsed, verify in JetBackup); daily=$jb_daily weekly=$jb_weekly monthly=$jb_monthly. "
    else
        jb_ev="JetBackup5 present but listBackupJobs did not return a recognisable success response (exit=$jb_rc); UNVERIFIED. "
    fi
    unset jb_out
elif (( jb_present )); then
    jb_ev='JetBackup service/process seen but jetbackup5api is not available (JetBackup 4 or non-standard install); UNVERIFIED. '
fi
schedule_ev+="$jb_ev"

for file in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [[ -f $file && -r $file && ! -L $file ]] || continue
    while IFS= read -r line; do
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        printf '%s\n' "$line" | grep -Eq "$backup_re" || continue
        ((local_job++)); schedule_ev+="Backup-command candidate in $file; "
        # This is scheduling evidence only; backup may target a remote repository.
        read -r minute hour dom month dow rest <<< "$line"
        if (( cron_alive )); then
            case "$minute" in @daily|@midnight) daily=1;; @weekly) weekly=1;; @monthly) monthly=1;;
                *)
                    if [[ $minute =~ ^[0-9]+$ && $hour =~ ^[0-9]+$ && $month == '*' ]]; then
                        [[ $dom == '*' && $dow == '*' ]] && daily=1
                        [[ $dom == '*' && $dow =~ ^[0-7]$ ]] && weekly=1
                        [[ $dom =~ ^[0-9]+$ && $dow == '*' ]] && monthly=1
                    fi;;
            esac
        fi
    done < "$file"
done
for svc in restic borg borgmatic duplicity rsnapshot; do
    if have systemctl && [[ -d /run/systemd/system ]] && run systemctl is-active --quiet "$svc.timer" >/dev/null; then
        schedule_ev+="$svc.timer active (calendar needs manual review); "; ((local_job++))
    fi
done

# Prefer the newest complete-looking cPanel dated backup set over a single account archive.
cp_latest_set=''; cp_latest_epoch=0; cp_latest_set_size=0; cp_incomplete=0
cp_log_path=''; cp_log_state='unknown'; cp_log_age='unknown'
if [[ -n $cp_dir && $cp_dir == /* && -d $cp_dir ]]; then
    set_dirs=$(timeout -k 2s 20s find "$cp_dir" -xdev -mindepth 1 -maxdepth 3 -type d -name '20??-??-??' -print 2>/dev/null)
    while IFS= read -r setdir; do
        [[ -n $setdir ]] || continue
        setdate=${setdir##*/}; setepoch=$(date -d "$setdate" +%s 2>/dev/null)
        [[ $setepoch =~ ^[0-9]+$ ]] || continue
        if (( setepoch > cp_latest_epoch )); then cp_latest_epoch=$setepoch; cp_latest_set=$setdir; fi
    done <<< "$set_dirs"
    if [[ -n $cp_latest_set ]]; then
        cp_latest_set_size=$(timeout -k 2s 30s find "$cp_latest_set" -xdev -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1}END{printf "%.0f",s+0}')
        [[ $cp_latest_set_size =~ ^[0-9]+$ ]] || cp_latest_set_size=0
        [[ -e $cp_latest_set/backup_incomplete ]] && cp_incomplete=1
    fi
fi
if [[ -d /usr/local/cpanel/logs/cpbackup ]]; then
    logrow=$(timeout -k 2s 10s find /usr/local/cpanel/logs/cpbackup -maxdepth 1 -type f -printf '%T@\t%p\n' 2>/dev/null | sort -nr | head -n 1)
    logepoch=${logrow%%$'\t'*}; cp_log_path=${logrow#*$'\t'}; logepoch=${logepoch%%.*}
    if [[ -n $cp_log_path && -r $cp_log_path ]]; then
        cp_log_state=$(run tail -n 300 "$cp_log_path" | sed -nE 's/.*Final state is Backup::([^ (]+).*/\1/p' | tail -n 1)
        [[ -n $cp_log_state ]] || cp_log_state=unknown
        [[ $logepoch =~ ^[0-9]+$ && $NOW -ge $logepoch ]] && cp_log_age=$(((NOW-logepoch)/86400))
    fi
fi

backup_file=''; backup_time=0; backup_size=0; backup_partial=0; backup_kind='archive'
if [[ -n $cp_latest_set ]]; then
    backup_file=$cp_latest_set; backup_time=$cp_latest_epoch; backup_size=$cp_latest_set_size; backup_kind='cPanel backup set'
else
    for root in "${BACKUP_DIRS[@]}"; do
        [[ -d $root ]] || continue
        listing=$(timeout -k 2s 30s find "$root" -xdev -maxdepth 5 -type f \
            \( -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.tar.bz2' -o -iname '*.tar.xz' -o -iname '*.zip' -o -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.dump' \) \
            -printf '%T@\t%s\t%p\n' 2>/dev/null)
        (( $?==0 )) || backup_partial=1
        while IFS=$'\t' read -r time size path; do
            time=${time%%.*}
            [[ $time =~ ^[0-9]+$ && $size =~ ^[0-9]+$ ]] || continue
            if (( time>backup_time )); then backup_time=$time; backup_size=$size; backup_file=$path; fi
        done <<< "$listing"
    done
fi

local_status='Not configured'; local_note=''
if [[ -n $cp_backup_config ]]; then
    # cPanel always uses BACKUPDIR as its default local staging/destination. KEEPLOCAL=0
    # means it removes the staged local copy after a successful transfer. A recent
    # Success log in that case shows the local backup stage is working, so it is
    # accepted as Configured and the lack of a retained copy is stated in ISSUE.
    cp_log_recent_success=0
    [[ $cp_log_state == Success && $cp_log_age =~ ^[0-9]+$ ]] && (( cp_log_age <= 7 )) && cp_log_recent_success=1
    if (( cp_backup_enabled )) && [[ $cp_dir == /* && -d $cp_dir ]] && { (( cp_keep_local )) || (( cp_remote_enabled==0 )) || [[ -n $cp_latest_set ]] || (( cp_log_recent_success )); }; then
        local_status=Configured
        if (( ! cp_keep_local )) && [[ -z $cp_latest_set ]]; then
            local_note='cPanel backup is enabled and the latest log reports Success; KEEPLOCAL=0 so the staged local copy is removed after transfer and no local archive is retained on this server. '
        fi
    fi
elif [[ -n $backup_file ]]; then
    local_status=Configured
fi
emit 'LOCAL BACKUP' "$local_status" "${local_note}Latest local candidate=${backup_file:-not found} ($backup_kind); bytes=$backup_size. ${schedule_ev:-No recognized backup scheduler candidates.} $cp_dest_ev KEEPLOCAL=0 means local copies may be removed after successful transfer; current artifact presence and configured retention are reported separately. cPanel log state=$cp_log_state age=${cp_log_age} days; incomplete-marker=$cp_incomplete; search partial=$backup_partial." 'Verify the configured backup scope, retention, latest successful cPanel log and restore capability. If KEEPLOCAL=0 with remote destinations, confirm whether a retained local copy is required.'

remote_status=NA
if [[ $PANEL == cpanel && -n $cp_backup_config ]]; then
    remote_status='Not configured'; (( cp_remote_enabled > 0 )) && remote_status=Configured
fi
emit 'REMOTE BACKUP' "$remote_status" "Enabled cPanel remote destinations=$cp_remote_enabled; enabled additional local destinations=$cp_local_dest_enabled; disabled destinations=$cp_dest_disabled. ${cp_dest_ev:-No enabled cPanel additional destination metadata found.} Credentials/secret fields are never displayed or tested; transfer success requires log review." 'Verify the latest transporter log and restore access for every enabled off-server destination. Confirm independent retention and that credentials are managed securely.'

for frequency in DAILY WEEKLY MONTHLY; do
    seen=0; freq_detail=''; jb_seen=0
    case "$frequency" in
        DAILY) seen=$daily; jb_seen=$jb_daily; freq_detail="days=${cp_daily_days:-unknown} retention=${cp_daily_ret:-unknown}";;
        WEEKLY) seen=$weekly; jb_seen=$jb_weekly; freq_detail="day=${cp_weekly_day:-unknown} retention=${cp_weekly_ret:-unknown}";;
        MONTHLY) seen=$monthly; jb_seen=$jb_monthly; freq_detail="dates=${cp_monthly_dates:-unknown} retention=${cp_monthly_ret:-unknown}";;
    esac
    status='Not configured'; (( seen || jb_seen )) && status=Configured
    jb_text=''
    (( jb_seen )) && jb_text="JetBackup job whose name contains ${frequency,,} found (name-based; schedule/enabled state not parsed). "
    emit "$frequency BACKUP" "$status" "Recognized $frequency cPanel/cron configuration=$seen; $jb_text$freq_detail; cPanel backup enabled=$cp_backup_enabled; scheduler-entry=$cp_scheduler_seen; cron-running=$cron_alive; JetBackup present=$jb_present jobs=$jb_jobs. Configuration describes schedule/retention, not successful execution. Latest cPanel log state=$cp_log_state." 'Confirm the latest successful run for this frequency and periodically test recovery. A configured schedule alone does not prove every backup completed successfully.'
done

recent_status='No recent backups'; backup_age='unknown'
if (( backup_time>0 )); then
    backup_age=$(((NOW-backup_time)/86400))
    if (( NOW>=backup_time && NOW-backup_time<=BACKUP_MAX_DAYS*86400 && backup_size>0 && cp_incomplete==0 )); then
        recent_status='Recent Backups Available'
    fi
fi
[[ $cp_log_state == PartialFailure || $cp_log_state == Failure || $cp_log_state == Failed ]] && recent_status='No recent backups'
emit 'RECENT LAST BACKUP' "$recent_status" "Latest $backup_kind=${backup_file:-none}; age=$backup_age days; total size=$backup_size bytes; threshold=$BACKUP_MAX_DAYS days; incomplete-marker=$cp_incomplete; latest cPanel log state=$cp_log_state age=${cp_log_age} days. For cPanel, a dated backup set is preferred over an individual account archive." 'Review the matching cPanel backup log for Backup::Success and investigate any backup_incomplete/PartialFailure evidence. Validate the backup by restoring a representative account or data set.'

size_status=NA
if [[ -n $backup_file ]] && (( EXPECTED_BACKUP_BYTES>0 )); then
    if (( backup_size>=EXPECTED_BACKUP_BYTES )); then size_status='Expected size'; else size_status='Too small'; fi
fi
emit 'SIZE OF LAST BACKUP' "$size_status" "Candidate=$backup_file ($backup_kind); total bytes=$backup_size; supplied minimum=$EXPECTED_BACKUP_BYTES. For cPanel dated sets, size is the sum of regular files in the set. Unknown baseline remains NA; size alone cannot establish integrity." 'Use --expected-backup-bytes with an agreed baseline for this backup type, compare historical set sizes and validate restoration. Incremental or multi-destination backups require separate interpretation.'

printf 'Audit complete. No findings were remediated. Review every UNVERIFIED/manual item before submitting the audit.\n'
exit 0
