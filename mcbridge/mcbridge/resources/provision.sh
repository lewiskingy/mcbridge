#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[mcbridge provision] $*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

usage() {
  cat <<'EOF'
Usage: provision.sh [OPTIONS]

Required/optional arguments:
  --ap-interface <name>         AP interface to manage (default: wlan0ap)
  --upstream-interface <name>   Upstream interface for NAT (default: wlan0)
  --ap-service-path <path>      Destination for wlan0ap.service (default: /etc/systemd/system/wlan0ap.service)
  --ap-ip-service-path <path>   Destination for wlan0ap-ip.service (default: /etc/systemd/system/wlan0ap-ip.service)
  --ap-ip-cidr <cidr>           IP (CIDR) assigned to the AP interface; enables wlan0ap-ip.service when set
  --sysctl-conf-path <path>     Path for persistent sysctl config (default: /etc/sysctl.d/99-mcbridge.conf)
  --iptables-rules-path <path>  Path for iptables-save output (default: /etc/iptables/rules.v4)
  --apt-bin <path>              Override path to apt-get
  --systemctl-bin <path>        Override path to systemctl
  --sysctl-bin <path>           Override path to sysctl
  --iptables-bin <path>         Override path to iptables
  --iptables-save-bin <path>    Override path to iptables-save
  --hostapd-template <path>     Path to a hostapd.conf template to apply instead of rendering
  --dnsmasq-template <path>     Path to a dnsmasq.conf template to apply instead of rendering
  --unit-wlan0ap <path>         Path to an existing wlan0ap.service unit file to install instead of rendering
  --unit-wlan0ap-ip <path>      Path to an existing wlan0ap-ip.service unit file to install instead of rendering
  --force                       Re-run provisioning even if all preflight checks pass
EOF
}

trap 'fail "Provisioning failed at line ${LINENO}: ${BASH_COMMAND:-unknown command}"' ERR

APT_BIN="${APT_BIN:-apt-get}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
SYSCTL_BIN="${SYSCTL_BIN:-sysctl}"
IPTABLES_BIN="${IPTABLES_BIN:-iptables}"
IPTABLES_SAVE_BIN="${IPTABLES_SAVE_BIN:-iptables-save}"
PYTHON_BIN="${PYTHON_BIN:-}"

AP_INTERFACE="wlan0ap"
UPSTREAM_INTERFACE="wlan0"
AP_SERVICE_PATH="/etc/systemd/system/wlan0ap.service"
AP_IP_SERVICE_PATH="/etc/systemd/system/wlan0ap-ip.service"
AP_IP_CIDR=""
HOSTAPD_TEMPLATE_PATH="${MCBRIDGE_HOSTAPD_TEMPLATE:-}"
DNSMASQ_TEMPLATE_PATH="${MCBRIDGE_DNSMASQ_TEMPLATE:-}"
WLAN0AP_UNIT_SOURCE="${MCBRIDGE_UNIT_WLAN0AP:-}"
WLAN0AP_IP_UNIT_SOURCE="${MCBRIDGE_UNIT_WLAN0AP_IP:-}"
SYSCTL_CONF_PATH="/etc/sysctl.d/99-mcbridge.conf"
IPTABLES_RULES_V4="/etc/iptables/rules.v4"
ETC_DIR="${MCBRIDGE_ETC_DIR:-/etc/mcbridge}"
CONFIG_DIR="${ETC_DIR}/config"
GENERATED_DIR="${ETC_DIR}/generated"
HOSTAPD_CONF_PATH="/etc/hostapd/hostapd.conf"
HOSTAPD_GENERATED_CONF="${GENERATED_DIR}/hostapd.conf"
DNSMASQ_CONF_PATH="/etc/dnsmasq.conf"
DNSMASQ_GENERATED_CONF="${GENERATED_DIR}/dnsmasq.conf"
AP_JSON_PATH="${CONFIG_DIR}/ap.json"
if command -v realpath >/dev/null 2>&1; then
  AP_JSON_REAL_PATH="$(realpath -m "${AP_JSON_PATH}")"
else
  AP_JSON_REAL_PATH="${AP_JSON_PATH}"
fi
NETWORKMANAGER_CONF_DIR="/etc/NetworkManager/conf.d"
SERVICE_USER="${MCBRIDGE_SERVICE_USER:-mcbridge}"
SERVICE_GROUP="${MCBRIDGE_SERVICE_GROUP:-${SERVICE_USER}}"
SERVICE_HOME="${MCBRIDGE_SERVICE_HOME:-/var/lib/mcbridge}"
OPERATOR_GROUP="${MCBRIDGE_OPERATOR_GROUP:-mcbridge-operators}"
SUDOERS_DROPIN="${MCBRIDGE_SUDOERS_DROPIN:-/etc/sudoers.d/mcbridge}"
INSTALLER_USER="${MCBRIDGE_INSTALLER_USER:-${SUDO_USER:-${USER:-}}}"
FILE_OWNER="${MCBRIDGE_FILE_OWNER:-${SERVICE_USER}}"
FILE_GROUP="${MCBRIDGE_FILE_GROUP:-${OPERATOR_GROUP}}"
FILE_MODE="${MCBRIDGE_FILE_MODE:-660}"
DIR_MODE="${MCBRIDGE_DIR_MODE:-770}"
FORCE=0
PREFLIGHT_ISSUES=()
PREFLIGHT_NEEDS_AP_INTERFACE=0
PREFLIGHT_AP_UNIT_NEEDS_START=0
PREFLIGHT_NETWORKMANAGER_INTERFERING=0
DO_CLEANUP=0
DNSMASQ_CONF_UPDATED=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE_PACKAGES_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ESCALATE_BIN="${MCBRIDGE_ESCALATE:-sudo}"

MCBRIDGE_BIN="${MCBRIDGE_BIN:-$(command -v mcbridge || true)}"
MCBRIDGE_BIN_DIR=""
if [[ -n "${MCBRIDGE_BIN}" ]]; then
  MCBRIDGE_BIN_DIR="$(dirname "${MCBRIDGE_BIN}")"
fi

if [[ -z "${MCBRIDGE_INSTALLER_USER:-}" ]]; then
  export MCBRIDGE_INSTALLER_USER="${USER:-}"
fi

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  read -r -a ESCALATE_CMD <<<"${ESCALATE_BIN}"
  if [[ ${#ESCALATE_CMD[@]} -eq 0 ]] || ! command -v "${ESCALATE_CMD[0]}" >/dev/null 2>&1; then
    fail "mcbridge provisioning requires root privileges and could not find '${ESCALATE_BIN}'. Install sudo or set MCBRIDGE_ESCALATE."
  fi

  PRESERVE_ENV_NAMES=("PATH")
  while IFS='=' read -r name _; do
    if [[ "${name}" == MCBRIDGE_* ]]; then
      PRESERVE_ENV_NAMES+=("${name}")
    fi
  done < <(env)

  ESCALATE_ARGS=("${ESCALATE_CMD[@]}")
  if [[ "${ESCALATE_CMD[0]}" == "sudo" ]]; then
    if ! "${ESCALATE_CMD[@]}" -n true >/dev/null 2>&1; then
      fail "mcbridge provisioning must run as root. Configure passwordless sudo for $ - whoami or run the script as root so it can re-exec without a TTY."
    fi
    PRESERVE_ENV_SPEC=$(IFS=','; echo "${PRESERVE_ENV_NAMES[*]}")
    ESCALATE_ARGS+=("-n" "--preserve-env=${PRESERVE_ENV_SPEC}" "--")
  fi

  exec "${ESCALATE_ARGS[@]}" "$0" "$@"
fi

if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python3" ]]; then
    PYTHON_BIN="${VIRTUAL_ENV}/bin/python3"
  elif [[ -x "${SCRIPT_DIR}/../../../../bin/python3" ]]; then
    PYTHON_BIN="${SCRIPT_DIR}/../../../../bin/python3"
  else
    PYTHON_BIN="$(command -v python3)"
  fi
fi

export PYTHONPATH="${PYTHONPATH:+${PYTHONPATH}:}${SITE_PACKAGES_DIR}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ap-interface)
      AP_INTERFACE="$2"
      shift 2
      ;;
    --upstream-interface)
      UPSTREAM_INTERFACE="$2"
      shift 2
      ;;
    --ap-service-path)
      AP_SERVICE_PATH="$2"
      shift 2
      ;;
    --ap-ip-service-path)
      AP_IP_SERVICE_PATH="$2"
      shift 2
      ;;
    --ap-ip-cidr)
      AP_IP_CIDR="$2"
      shift 2
      ;;
    --sysctl-conf-path)
      SYSCTL_CONF_PATH="$2"
      shift 2
      ;;
    --iptables-rules-path)
      IPTABLES_RULES_V4="$2"
      shift 2
      ;;
    --apt-bin)
      APT_BIN="$2"
      shift 2
      ;;
    --systemctl-bin)
      SYSTEMCTL_BIN="$2"
      shift 2
      ;;
    --sysctl-bin)
      SYSCTL_BIN="$2"
      shift 2
      ;;
    --iptables-bin)
      IPTABLES_BIN="$2"
      shift 2
      ;;
    --iptables-save-bin)
      IPTABLES_SAVE_BIN="$2"
      shift 2
      ;;
    --hostapd-template)
      HOSTAPD_TEMPLATE_PATH="$2"
      shift 2
      ;;
    --dnsmasq-template)
      DNSMASQ_TEMPLATE_PATH="$2"
      shift 2
      ;;
    --unit-wlan0ap)
      WLAN0AP_UNIT_SOURCE="$2"
      shift 2
      ;;
    --unit-wlan0ap-ip)
      WLAN0AP_IP_UNIT_SOURCE="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

if [[ -z "${AP_INTERFACE}" ]] || [[ -z "${UPSTREAM_INTERFACE}" ]]; then
  fail "AP and upstream interfaces must be specified."
fi

require_command() {
  local bin="$1"
  if ! command -v "${bin}" >/dev/null 2>&1; then
    fail "Required command not found: ${bin}"
  fi
}

check_package_installed() {
  local pkg="$1"
  if dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"; then
    log "Package ${pkg} is installed"
    return 0
  fi
  log "Package ${pkg} is missing"
  return 1
}

check_file_present() {
  local path="$1"
  local label="${2:-${path}}"
  if [[ -f "${path}" ]]; then
    log "Found ${label} at ${path}"
    return 0
  fi
  log "Missing ${label} at ${path}"
  return 1
}

resolve_owner_and_group() {
  RESOLVED_OWNER="${FILE_OWNER}"
  RESOLVED_GROUP="${FILE_GROUP}"

  if ! id -u "${RESOLVED_OWNER}" >/dev/null 2>&1; then
    log "Requested owner ${RESOLVED_OWNER} is missing; falling back to root"
    RESOLVED_OWNER="root"
  fi
  if command -v getent >/dev/null 2>&1; then
    if ! getent group "${RESOLVED_GROUP}" >/dev/null 2>&1; then
      log "Requested group ${RESOLVED_GROUP} is missing; falling back to ${RESOLVED_OWNER}"
      RESOLVED_GROUP="${RESOLVED_OWNER}"
    fi
  else
    log "getent not available; skipping validation for group ${RESOLVED_GROUP}"
  fi
}

apply_owner_and_mode() {
  local path="$1"
  local mode="$2"

  chmod "${mode}" "${path}" >/dev/null 2>&1 || log "Could not chmod ${path} to ${mode}"
  chown "${RESOLVED_OWNER}:${RESOLVED_GROUP}" "${path}" >/dev/null 2>&1 || log "Could not chown ${path} to ${RESOLVED_OWNER}:${RESOLVED_GROUP}"
}

ensure_managed_dir() {
  local dir="$1"
  install -d -m"${DIR_MODE}" "${dir}"
  apply_owner_and_mode "${dir}" "${DIR_MODE}"
}

ensure_mcbridge_dirs() {
  ensure_managed_dir "${ETC_DIR}"
  ensure_managed_dir "${CONFIG_DIR}"
  ensure_managed_dir "${CONFIG_DIR}/history"
  ensure_managed_dir "${GENERATED_DIR}"
  ensure_managed_dir "${GENERATED_DIR}/history"
  ensure_managed_dir "${GENERATED_DIR}/failed"
}

check_sysctl_ip_forwarding() {
  local runtime
  runtime="$(${SYSCTL_BIN} -n net.ipv4.ip_forward 2>/dev/null || true)"
  local persistent="absent"
  if [[ -f "${SYSCTL_CONF_PATH}" ]] && grep -Eq '^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$' "${SYSCTL_CONF_PATH}"; then
    persistent="configured"
  fi

  if [[ "${runtime}" == "1" && "${persistent}" == "configured" ]]; then
    log "IPv4 forwarding is enabled  - runtime and persisted  - ${SYSCTL_CONF_PATH}"
    return 0
  fi

  log "IPv4 forwarding not fully configured  - runtime=${runtime:-absent}, persistent=${persistent}"
  return 1
}

iptables_rule_present() {
  if ! command -v "${IPTABLES_BIN}" >/dev/null 2>&1; then
    log "iptables not available; cannot verify rule: ${*}"
    return 1
  fi

  local table="$1"
  local chain="$2"
  shift 2
  local args=("$@")

  if "${IPTABLES_BIN}" ${table:+-t "${table}"} -C "${chain}" "${args[@]}" >/dev/null 2>&1; then
    log "iptables rule present: ${table:+-t ${table} }${chain} ${args[*]}"
    return 0
  fi

  log "iptables rule missing: ${table:+-t ${table} }${chain} ${args[*]}"
  return 1
}

networkmanager_unmanaged_conf_path() {
  echo "${NETWORKMANAGER_CONF_DIR}/99-mcbridge-unmanaged-${AP_INTERFACE}.conf"
}

networkmanager_manages_ap_interface() {
  local nm_state=""
  if command -v nmcli >/dev/null 2>&1; then
    nm_state="$(nmcli -t -f DEVICE,STATE dev status 2>/dev/null | awk -F: -v dev="${AP_INTERFACE}" '$1==dev {print $2}')"
    if [[ -n "${nm_state}" && "${nm_state}" != "unmanaged" ]]; then
      log "NetworkManager reports ${AP_INTERFACE} state=${nm_state}"
      return 0
    fi
  fi

  local keyfile
  keyfile="$(grep -El "^[[:space:]]*interface-name[[:space:]]*=[[:space:]]*${AP_INTERFACE}[[:space:]]*$" /etc/NetworkManager/system-connections/* 2>/dev/null | head -n1 || true)"
  if [[ -n "${keyfile}" ]]; then
    log "NetworkManager keyfile references ${AP_INTERFACE}: ${keyfile}"
    return 0
  fi

  if [[ -n "${nm_state}" ]]; then
    log "NetworkManager reports ${AP_INTERFACE} unmanaged"
  fi

  return 1
}

ensure_service_account() {
  if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    log "Creating system group ${SERVICE_GROUP}"
    groupadd --system "${SERVICE_GROUP}"
  fi

  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    log "Creating system user ${SERVICE_USER} with home ${SERVICE_HOME}"
    useradd --system --home "${SERVICE_HOME}" --shell /usr/sbin/nologin --gid "${SERVICE_GROUP}" "${SERVICE_USER}"
  fi

  install -d -m750 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${SERVICE_HOME}"
}

ensure_operator_group() {
  if ! getent group "${OPERATOR_GROUP}" >/dev/null 2>&1; then
    log "Creating operator group ${OPERATOR_GROUP}"
    groupadd "${OPERATOR_GROUP}"
  fi

  if [[ -n "${INSTALLER_USER}" && "${INSTALLER_USER}" != "root" ]]; then
    if id -u "${INSTALLER_USER}" >/dev/null 2>&1; then
      log "Adding installer ${INSTALLER_USER} to ${OPERATOR_GROUP}"
      usermod -a -G "${OPERATOR_GROUP}" "${INSTALLER_USER}" || log "Could not add ${INSTALLER_USER} to ${OPERATOR_GROUP}"
    else
      log "Installer user ${INSTALLER_USER} not found; skipping group membership update"
    fi
  fi
}

write_sudoers_dropin() {
  local sudoers_path="${SUDOERS_DROPIN}"
  log "Sudoers drop-in is managed by 'mcbridge init'; leaving ${sudoers_path} untouched."
}

run_preflight_checks() {
  log "Running mcbridge provisioning preflight checks"

  PREFLIGHT_NEEDS_AP_INTERFACE=0
  PREFLIGHT_AP_UNIT_NEEDS_START=0
  PREFLIGHT_NETWORKMANAGER_INTERFERING=0
  local issues=()
  local ap_unit
  ap_unit="$(basename "${AP_SERVICE_PATH}")"
  local ap_ip_unit
  ap_ip_unit="$(basename "${AP_IP_SERVICE_PATH}")"

  local dir
  for dir in "${ETC_DIR}" "${CONFIG_DIR}" "${CONFIG_DIR}/history" "${GENERATED_DIR}" "${GENERATED_DIR}/history" "${GENERATED_DIR}/failed"; do
    if [[ -e "${dir}" ]]; then
      local owner group mode
      owner="$(stat -c '%U' "${dir}" 2>/dev/null || true)"
      group="$(stat -c '%G' "${dir}" 2>/dev/null || true)"
      mode="$(stat -c '%a' "${dir}" 2>/dev/null || true)"
      if [[ "${owner}" != "${RESOLVED_OWNER}" || "${group}" != "${RESOLVED_GROUP}" || "${mode}" != "${DIR_MODE}" ]]; then
        log "Correcting directory permissions for ${dir}  - was ${owner}:${group} ${mode:-unknown}, expected ${RESOLVED_OWNER}:${RESOLVED_GROUP} ${DIR_MODE}"
        apply_owner_and_mode "${dir}" "${DIR_MODE}"
        issues+=("permissions:${dir}")
      fi
    fi
  done

  local file
  for file in \
    "${AP_JSON_PATH}" \
    "${CONFIG_DIR}/dns_overrides.json" \
    "${CONFIG_DIR}/dnsmasq.json" \
    "${HOSTAPD_CONF_PATH}" \
    "${HOSTAPD_GENERATED_CONF}" \
    "${DNSMASQ_CONF_PATH}" \
    "${DNSMASQ_GENERATED_CONF}" \
    "${AP_SERVICE_PATH}" \
    "${AP_IP_SERVICE_PATH}"
  do
    if [[ -e "${file}" ]]; then
      local owner group mode
      owner="$(stat -c '%U' "${file}" 2>/dev/null || true)"
      group="$(stat -c '%G' "${file}" 2>/dev/null || true)"
      mode="$(stat -c '%a' "${file}" 2>/dev/null || true)"
      if [[ "${owner}" != "${RESOLVED_OWNER}" || "${group}" != "${RESOLVED_GROUP}" || "${mode}" != "${FILE_MODE}" ]]; then
        log "Correcting file permissions for ${file} - was ${owner}:${group} ${mode:-unknown}, expected ${RESOLVED_OWNER}:${RESOLVED_GROUP} ${FILE_MODE}"
        apply_owner_and_mode "${file}" "${FILE_MODE}"
        issues+=("permissions:${file}")
      fi
    fi
  done

  for pkg in hostapd dnsmasq iptables; do
    check_package_installed "${pkg}" || issues+=("package:${pkg}")
  done

  check_file_present "${AP_SERVICE_PATH}" "systemd unit" || issues+=("unit:${AP_SERVICE_PATH}")
  if [[ -n "${AP_IP_CIDR}" ]]; then
    check_file_present "${AP_IP_SERVICE_PATH}" "systemd unit" || issues+=("unit:${AP_IP_SERVICE_PATH}")
  else
    log "AP IP CIDR not provided; skipping wlan0ap-ip.service presence check"
  fi

  check_file_present "/etc/hostapd/hostapd.conf" "hostapd configuration" || issues+=("config:/etc/hostapd/hostapd.conf")
  check_file_present "/etc/dnsmasq.conf" "dnsmasq configuration" || issues+=("config:/etc/dnsmasq.conf")

  check_sysctl_ip_forwarding || issues+=("sysctl:net.ipv4.ip_forward")

  iptables_rule_present nat POSTROUTING -o "${UPSTREAM_INTERFACE}" -j MASQUERADE || issues+=("iptables:nat POSTROUTING MASQUERADE")
  iptables_rule_present "" FORWARD -i "${AP_INTERFACE}" -o "${UPSTREAM_INTERFACE}" -j ACCEPT || issues+=("iptables:FORWARD ${AP_INTERFACE}->${UPSTREAM_INTERFACE}")
  iptables_rule_present "" FORWARD -i "${UPSTREAM_INTERFACE}" -o "${AP_INTERFACE}" -m state --state ESTABLISHED,RELATED -j ACCEPT || issues+=("iptables:FORWARD ${UPSTREAM_INTERFACE}->${AP_INTERFACE} established")

  local link_info flags state
  link_info="$(ip link show "${AP_INTERFACE}" 2>/dev/null | head -n1 || true)"
  if [[ -n "${link_info}" ]]; then
    parse_link_details "${link_info}" flags state
    log "AP interface ${AP_INTERFACE} is present  - flags=${flags:-unknown}, state=${state:-unknown}"
  else
    log "AP interface ${AP_INTERFACE} is missing"
    PREFLIGHT_NEEDS_AP_INTERFACE=1
    issues+=("interface:${AP_INTERFACE}")
  fi

  if networkmanager_manages_ap_interface; then
    PREFLIGHT_NETWORKMANAGER_INTERFERING=1
    issues+=("networkmanager:${AP_INTERFACE}")
  fi

  local unit_enabled unit_active
  unit_enabled="$("${SYSTEMCTL_BIN}" is-enabled "${ap_unit}" 2>/dev/null || true)"
  unit_active="$("${SYSTEMCTL_BIN}" is-active "${ap_unit}" 2>/dev/null || true)"
  if [[ "${unit_enabled}" != "enabled" ]]; then
    log "AP unit ${ap_unit} not enabled  - state=${unit_enabled:-unknown}"
    PREFLIGHT_AP_UNIT_NEEDS_START=1
    issues+=("unit-enabled:${ap_unit}:${unit_enabled:-unknown}")
  else
    log "AP unit ${ap_unit} is enabled"
  fi
  if [[ "${unit_active}" != "active" ]]; then
    log "AP unit ${ap_unit} not active  - state=${unit_active:-unknown}"
    PREFLIGHT_AP_UNIT_NEEDS_START=1
    issues+=("unit-active:${ap_unit}:${unit_active:-unknown}")
  else
    log "AP unit ${ap_unit} is active"
  fi

  if [[ -n "${AP_IP_CIDR}" ]]; then
    local ap_ip_enabled ap_ip_active
    ap_ip_enabled="$("${SYSTEMCTL_BIN}" is-enabled "${ap_ip_unit}" 2>/dev/null || true)"
    ap_ip_active="$("${SYSTEMCTL_BIN}" is-active "${ap_ip_unit}" 2>/dev/null || true)"
    if [[ "${ap_ip_enabled}" != "enabled" ]]; then
      log "AP IP unit ${ap_ip_unit} not enabled  - state=${ap_ip_enabled:-unknown}"
      issues+=("unit-enabled:${ap_ip_unit}:${ap_ip_enabled:-unknown}")
    else
      log "AP IP unit ${ap_ip_unit} is enabled"
    fi
    if [[ "${ap_ip_active}" != "active" ]]; then
      log "AP IP unit ${ap_ip_unit} not active  - state=${ap_ip_active:-unknown}"
      issues+=("unit-active:${ap_ip_unit}:${ap_ip_active:-unknown}")
    else
      log "AP IP unit ${ap_ip_unit} is active"
    fi

    if ap_interface_has_cidr "${AP_INTERFACE}" "${AP_IP_CIDR}"; then
      log "AP interface ${AP_INTERFACE} has expected IP ${AP_IP_CIDR}"
    else
      log "AP interface ${AP_INTERFACE} missing IP ${AP_IP_CIDR}"
      issues+=("ip:${AP_INTERFACE}:${AP_IP_CIDR}")
    fi
  fi

  for managed_unit in hostapd.service dnsmasq.service; do
    local managed_enabled managed_active
    managed_enabled="$("${SYSTEMCTL_BIN}" is-enabled "${managed_unit}" 2>/dev/null || true)"
    managed_active="$("${SYSTEMCTL_BIN}" is-active "${managed_unit}" 2>/dev/null || true)"
    if [[ "${managed_enabled}" != "enabled" ]]; then
      log "${managed_unit} not enabled  - state=${managed_enabled:-unknown}"
      issues+=("unit-enabled:${managed_unit}:${managed_enabled:-unknown}")
    else
      log "${managed_unit} is enabled"
    fi
    if [[ "${managed_active}" != "active" ]]; then
      log "${managed_unit} not active  - state=${managed_active:-unknown}"
      issues+=("unit-active:${managed_unit}:${managed_active:-unknown}")
    else
      log "${managed_unit} is active"
    fi
  done

  check_file_present "${IPTABLES_RULES_V4}" "iptables rules" || issues+=("file:${IPTABLES_RULES_V4}")

  PREFLIGHT_ISSUES=("${issues[@]}")

  if [[ ${#issues[@]} -eq 0 ]]; then
    log "Preflight checks passed; no provisioning actions appear necessary."
    return 0
  fi

  log "Preflight detected missing or out-of-date state:"
  for issue in "${issues[@]}"; do
    log " - ${issue}"
  done
  return 1
}

stop_conflicting_services() {
  local units=()
  units+=("$(basename "${AP_SERVICE_PATH}")")
  units+=("hostapd.service" "dnsmasq.service")
  if [[ -n "${AP_IP_CIDR}" ]]; then
    units+=("$(basename "${AP_IP_SERVICE_PATH}")")
  fi

  for unit in "${units[@]}"; do
    log "Disabling/stopping ${unit} to avoid conflicts"
    "${SYSTEMCTL_BIN}" disable --now "${unit}" >/dev/null 2>&1 || true
  done
}

remove_outdated_units() {
  log "Removing outdated wlan0ap unit files"
  shopt -s nullglob
  local keep_paths=("${AP_SERVICE_PATH}")
  if [[ -n "${AP_IP_SERVICE_PATH}" ]]; then
    keep_paths+=("${AP_IP_SERVICE_PATH}")
  fi
  local candidates=(/etc/systemd/system/wlan0ap*.service /lib/systemd/system/wlan0ap*.service)
  for candidate in "${candidates[@]}"; do
    local keep=0
    for keep_path in "${keep_paths[@]}"; do
      if [[ -n "${keep_path}" && "${candidate}" == "${keep_path}" ]]; then
        keep=1
        break
      fi
    done
    if [[ ${keep} -eq 0 && -f "${candidate}" ]]; then
      log "Deleting stale unit ${candidate}"
      rm -f "${candidate}"
    fi
  done
  shopt -u nullglob
}

stop_dnsmasq_for_apply() {
  log "Stopping dnsmasq before applying configuration changes"
  if ! "${SYSTEMCTL_BIN}" stop dnsmasq.service >/dev/null 2>&1; then
    fail "Failed to stop dnsmasq before updating configuration."
  fi
}

validate_dnsmasq_conf() {
  local path="$1"
  log "Validating dnsmasq configuration at ${path}"
  if ! dnsmasq --test --conf-file="${path}" >/dev/null; then
    return 1
  fi
}

restart_dnsmasq_after_apply() {
  log "Restarting dnsmasq to apply configuration"
  if ! "${SYSTEMCTL_BIN}" restart dnsmasq.service; then
    fail "dnsmasq restart failed after applying configuration."
  fi
}

reset_ap_configs() {
  local ap_json_path="${AP_JSON_REAL_PATH}"

  if [[ ! -f "${ap_json_path}" ]]; then
    if [[ -z "${HOSTAPD_TEMPLATE_PATH}" || -z "${DNSMASQ_TEMPLATE_PATH}" ]]; then
      fail "AP config missing at ${ap_json_path}; create this file or set AP_JSON_PATH to a valid config JSON."
    fi
    log "AP config missing at ${ap_json_path}; using provided hostapd/dnsmasq templates"
  else
    log "Resetting hostapd/dnsmasq configs from ${ap_json_path}"
  fi

  local hostapd_template
  if [[ -n "${HOSTAPD_TEMPLATE_PATH}" ]]; then
    log "Using hostapd template from ${HOSTAPD_TEMPLATE_PATH}"
    if [[ ! -f "${HOSTAPD_TEMPLATE_PATH}" ]]; then
      fail "Hostapd template not found at ${HOSTAPD_TEMPLATE_PATH}"
    fi
    hostapd_template="$(cat "${HOSTAPD_TEMPLATE_PATH}")"
  else
    if ! hostapd_template=$(AP_JSON_REAL_PATH="${ap_json_path}" "${PYTHON_BIN}" - <<'PY'
import json
import os
from pathlib import Path
from mcbridge import ap

path = Path(os.environ["AP_JSON_REAL_PATH"])
config = json.loads(path.read_text())
print(ap._hostapd_template(config), end="")
PY
    ); then
      log "Failed to render hostapd template; skipping config reset"
      return
    fi
  fi

  local dnsmasq_template
  if [[ -n "${DNSMASQ_TEMPLATE_PATH}" ]]; then
    log "Using dnsmasq template from ${DNSMASQ_TEMPLATE_PATH}"
    if [[ ! -f "${DNSMASQ_TEMPLATE_PATH}" ]]; then
      fail "dnsmasq template not found at ${DNSMASQ_TEMPLATE_PATH}"
    fi
    dnsmasq_template="$(cat "${DNSMASQ_TEMPLATE_PATH}")"
  else
    if ! dnsmasq_template=$(AP_JSON_REAL_PATH="${ap_json_path}" "${PYTHON_BIN}" - <<'PY'
import json
import os
from pathlib import Path
from mcbridge import ap

path = Path(os.environ["AP_JSON_REAL_PATH"])
config = json.loads(path.read_text())
print(ap._dnsmasq_template(config), end="")
PY
    ); then
      log "Failed to render dnsmasq template; skipping config reset"
      return
    fi
  fi

  local dnsmasq_backup=""
  if [[ -f "${DNSMASQ_CONF_PATH}" ]]; then
    dnsmasq_backup="$(mktemp)"
    cp "${DNSMASQ_CONF_PATH}" "${dnsmasq_backup}"
  fi

  stop_dnsmasq_for_apply
  install -Dm"${FILE_MODE}" /dev/stdin "${HOSTAPD_CONF_PATH}" <<<"${hostapd_template}"
  apply_owner_and_mode "${HOSTAPD_CONF_PATH}" "${FILE_MODE}"
  install -Dm"${FILE_MODE}" /dev/stdin "${HOSTAPD_GENERATED_CONF}" <<<"${hostapd_template}"
  apply_owner_and_mode "${HOSTAPD_GENERATED_CONF}" "${FILE_MODE}"
  install -Dm"${FILE_MODE}" /dev/stdin "${DNSMASQ_CONF_PATH}" <<<"${dnsmasq_template}"
  apply_owner_and_mode "${DNSMASQ_CONF_PATH}" "${FILE_MODE}"
  install -Dm"${FILE_MODE}" /dev/stdin "${DNSMASQ_GENERATED_CONF}" <<<"${dnsmasq_template}"
  apply_owner_and_mode "${DNSMASQ_GENERATED_CONF}" "${FILE_MODE}"
  if ! validate_dnsmasq_conf "${DNSMASQ_CONF_PATH}"; then
    log "dnsmasq validation failed; restoring previous configuration"
    if [[ -n "${dnsmasq_backup}" && -f "${dnsmasq_backup}" ]]; then
      install -Dm"${FILE_MODE}" "${dnsmasq_backup}" "${DNSMASQ_CONF_PATH}"
      apply_owner_and_mode "${DNSMASQ_CONF_PATH}" "${FILE_MODE}"
      install -Dm"${FILE_MODE}" "${dnsmasq_backup}" "${DNSMASQ_GENERATED_CONF}"
      apply_owner_and_mode "${DNSMASQ_GENERATED_CONF}" "${FILE_MODE}"
    else
      rm -f "${DNSMASQ_CONF_PATH}" "${DNSMASQ_GENERATED_CONF}"
    fi
    fail "dnsmasq configuration test failed for ${DNSMASQ_CONF_PATH}; see stderr for details."
  fi
  if [[ -n "${dnsmasq_backup}" ]]; then
    rm -f "${dnsmasq_backup}"
  fi
  DNSMASQ_CONF_UPDATED=1
}

delete_matching_rules() {
  local table="$1"
  local chain="$2"
  local pattern="$3"

  if ! command -v "${IPTABLES_BIN}" >/dev/null 2>&1; then
    log "iptables unavailable; skipping delete scan for ${chain}  - ${pattern}"
    return
  fi

  local rules
  rules=$("${IPTABLES_BIN}" ${table:+-t "${table}"} -S "${chain}" 2>/dev/null | grep -F -- "${pattern}" || true)
  while read -r rule; do
    [[ -z "${rule}" ]] && continue
    local delete_rule="${rule/-A /-D }"
    log "Removing iptables rule: ${table:+-t ${table} }${delete_rule}"
    "${IPTABLES_BIN}" ${table:+-t "${table}"} ${delete_rule} >/dev/null 2>&1 || true
  done <<<"${rules}"
}

write_unit() {
  local path="$1"
  log "Writing systemd unit to ${path}"
  install -Dm644 /dev/stdin "${path}"
}

write_drop_in() {
  local path="$1"
  log "Writing systemd drop-in to ${path}"
  install -Dm644 /dev/stdin "${path}"
}

render_unit() {
  local unit="$1"
  shift
  "${PYTHON_BIN}" -m mcbridge.systemd_units "${unit}" "$@"
}

install_unit_from_source_or_render() {
  local source="$1"
  local dest="$2"
  local unit="$3"
  shift 3
  local render_args=("$@")

  if [[ -n "${source}" ]]; then
    log "Installing ${unit} unit from ${source} to ${dest}"
    if [[ ! -f "${source}" ]]; then
      fail "Unit source not found at ${source}"
    fi
    install -Dm644 "${source}" "${dest}"
  else
    render_unit "${unit}" "${render_args[@]}" | write_unit "${dest}"
  fi
}

ensure_unit_unmasked() {
  local unit="$1"
  local state

  state="$("${SYSTEMCTL_BIN}" is-enabled "${unit}" 2>/dev/null || true)"
  if [[ "${state}" == masked* ]]; then
    log "Unit ${unit} is masked; attempting to unmask so provisioning can manage it"
    if ! "${SYSTEMCTL_BIN}" unmask "${unit}"; then
      fail "Unit ${unit} is masked and could not be unmasked. Remove the mask or run '${SYSTEMCTL_BIN} unmask ${unit}' before rerunning provisioning."
    fi
  fi
}

enable_service() {
  local unit="$1"
  ensure_unit_unmasked "${unit}"
  log "Enabling and starting ${unit}"
  "${SYSTEMCTL_BIN}" enable --now "${unit}"
}

parse_link_details() {
  local link_info="$1"
  local flags_var="$2"
  local state_var="$3"
  local parsed_flags=""
  local parsed_state=""

  if [[ "${link_info}" =~ \<([^>]*)\> ]]; then
    parsed_flags="${BASH_REMATCH[1]}"
  fi

  if [[ "${link_info}" =~ [[:space:]]state[[:space:]]+([^[:space:]]+) ]]; then
    parsed_state="${BASH_REMATCH[1]}"
  fi

  printf -v "${flags_var}" '%s' "${parsed_flags}"
  printf -v "${state_var}" '%s' "${parsed_state}"
}

ap_interface_has_cidr() {
  local iface="$1"
  local cidr="$2"

  ip addr show "${iface}" 2>/dev/null | grep -Eq "\\binet\\s+${cidr//\//\\/}\\b"
}

ensure_ap_interface_up() {
  local ap_unit
  ap_unit="$(basename "${AP_SERVICE_PATH}")"

  local link_info flags state has_up_flag flag_array
  link_info="$(ip link show "${AP_INTERFACE}" 2>/dev/null | head -n1 || true)"
  if [[ -z "${link_info}" ]]; then
    fail "$(cat <<EOF
AP interface ${AP_INTERFACE} is missing after starting ${ap_unit}.
Potential causes:
 - NetworkManager is managing ${AP_INTERFACE}; set it unmanaged (e.g., ${NETWORKMANAGER_CONF_DIR}/99-mcbridge-unmanaged-${AP_INTERFACE}.conf) and reload NetworkManager.
 - Upstream interface ${UPSTREAM_INTERFACE} is missing or down, preventing ${ap_unit} from creating ${AP_INTERFACE}.
 - wlan0ap service configuration is incorrect; inspect 'systemctl status ${ap_unit}' for errors.
Aborting before configuring hostapd/dnsmasq.
EOF
)"
  fi

  parse_link_details "${link_info}" flags state
  log "Detected ${AP_INTERFACE} after starting ${ap_unit}: flags=${flags:-unknown} state=${state:-unknown}"
  has_up_flag=0
  IFS=',' read -ra flag_array <<<"${flags}"
  for flag in "${flag_array[@]}"; do
    if [[ "${flag}" == "UP" ]]; then
      has_up_flag=1
      break
    fi
  done

  if [[ "${has_up_flag}" -eq 0 ]]; then
    log "AP interface ${AP_INTERFACE} present but not up after starting ${ap_unit}  - flags=${flags:-unknown}, state=${state:-unknown}; attempting to bring it up"
    if ! ip link set "${AP_INTERFACE}" up; then
      fail "$(cat <<EOF
AP interface ${AP_INTERFACE} could not be brought up after starting ${ap_unit}.
Potential causes:
 - NetworkManager is managing ${AP_INTERFACE}; set it unmanaged (e.g., ${NETWORKMANAGER_CONF_DIR}/99-mcbridge-unmanaged-${AP_INTERFACE}.conf) and reload NetworkManager.
 - Upstream interface ${UPSTREAM_INTERFACE} is missing or down, preventing ${ap_unit} from creating ${AP_INTERFACE}.
 - Driver or kernel support for ${AP_INTERFACE} is unavailable.
Aborting before configuring hostapd/dnsmasq.
EOF
)"
    fi

    link_info="$(ip link show "${AP_INTERFACE}" 2>/dev/null | head -n1 || true)"
    parse_link_details "${link_info}" flags state
    log "Rechecked ${AP_INTERFACE} after attempting to bring it up: flags=${flags:-unknown} state=${state:-unknown}"
    has_up_flag=0
    IFS=',' read -ra flag_array <<<"${flags}"
    for flag in "${flag_array[@]}"; do
      if [[ "${flag}" == "UP" ]]; then
        has_up_flag=1
        break
      fi
    done

    if [[ "${has_up_flag}" -eq 0 ]]; then
      fail "$(cat <<EOF
AP interface ${AP_INTERFACE} remains down after attempting to bring it up via ip link set.
Potential causes:
 - NetworkManager is managing ${AP_INTERFACE}; set it unmanaged (e.g., ${NETWORKMANAGER_CONF_DIR}/99-mcbridge-unmanaged-${AP_INTERFACE}.conf) and reload NetworkManager.
 - Upstream interface ${UPSTREAM_INTERFACE} is missing or down, preventing ${ap_unit} from creating ${AP_INTERFACE}.
 - Driver or kernel support for ${AP_INTERFACE} is unavailable.
Aborting before configuring hostapd/dnsmasq.
EOF
)"
    fi
  fi

  log "AP interface ${AP_INTERFACE} is up - flags=${flags:-unknown}, state=${state:-unknown}; proceeding  - hostapd will manage carrier"
}

recover_ap_interface_if_needed() {
  if [[ "${PREFLIGHT_NEEDS_AP_INTERFACE}" -eq 0 && "${PREFLIGHT_AP_UNIT_NEEDS_START}" -eq 0 ]]; then
    return
  fi

  local ap_unit
  ap_unit="$(basename "${AP_SERVICE_PATH}")"

  if ip link show "${AP_INTERFACE}" >/dev/null 2>&1; then
    log "AP interface ${AP_INTERFACE} present after cleanup; skipping recovery"
    return
  fi

  log "Attempting to create AP interface ${AP_INTERFACE} by starting ${ap_unit}"
  ensure_unit_unmasked "${ap_unit}"
  if [[ ! -f "${AP_SERVICE_PATH}" ]]; then
    log "${AP_SERVICE_PATH} is missing after cleanup; rendering it before starting ${ap_unit}"
    install_unit_from_source_or_render "${WLAN0AP_UNIT_SOURCE}" "${AP_SERVICE_PATH}" wlan0ap --ap-interface "${AP_INTERFACE}" --upstream-interface "${UPSTREAM_INTERFACE}"
    log "Reloading systemd units after rendering ${AP_SERVICE_PATH}"
    "${SYSTEMCTL_BIN}" daemon-reload
  fi
  if ! "${SYSTEMCTL_BIN}" start "${ap_unit}"; then
    fail "Failed to start ${ap_unit} while attempting to create ${AP_INTERFACE}"
  fi

  if ! ip link show "${AP_INTERFACE}" >/dev/null 2>&1; then
    fail "AP interface ${AP_INTERFACE} is still missing after starting ${ap_unit}; check 'systemctl status ${ap_unit}'."
  fi

  local link_info flags state has_up_flag flag_array
  link_info="$(ip link show "${AP_INTERFACE}" 2>/dev/null | head -n1 || true)"
  parse_link_details "${link_info}" flags state
  has_up_flag=0
  IFS=',' read -ra flag_array <<<"${flags}"
  for flag in "${flag_array[@]}"; do
    if [[ "${flag}" == "UP" ]]; then
      has_up_flag=1
      break
    fi
  done

  if [[ "${has_up_flag}" -eq 0 ]]; then
    log "AP interface ${AP_INTERFACE} created but lacks UP flag  - flags=${flags:-unknown}, state=${state:-unknown}; attempting to bring it up"
    ip link set "${AP_INTERFACE}" up || true
    link_info="$(ip link show "${AP_INTERFACE}" 2>/dev/null | head -n1 || true)"
    parse_link_details "${link_info}" flags state
    has_up_flag=0
    IFS=',' read -ra flag_array <<<"${flags}"
    for flag in "${flag_array[@]}"; do
      if [[ "${flag}" == "UP" ]]; then
        has_up_flag=1
        break
      fi
    done

    if [[ "${has_up_flag}" -eq 0 ]]; then
      fail "AP interface ${AP_INTERFACE} is not up after starting ${ap_unit}  - flags=${flags:-unknown}, state=${state:-unknown}."
    fi
  fi

  log "AP interface ${AP_INTERFACE} created and up after starting ${ap_unit}  - flags=${flags:-unknown}, state=${state:-unknown}"
}

ensure_ip_forwarding() {
  log "Enabling IPv4 forwarding via sysctl"
  "${SYSCTL_BIN}" -w net.ipv4.ip_forward=1 >/dev/null
  log "Persisting IPv4 forwarding to ${SYSCTL_CONF_PATH}"
  install -Dm644 /dev/stdin "${SYSCTL_CONF_PATH}" <<EOF
net.ipv4.ip_forward = 1
EOF
}

ensure_iptables_rule() {
  local table="$1"
  local chain="$2"
  shift 2
  local args=("$@")

  if ! "${IPTABLES_BIN}" ${table:+-t "${table}"} -C "${chain}" "${args[@]}" >/dev/null 2>&1; then
    log "Adding iptables rule: ${table:+-t ${table} }${chain} ${args[*]}"
    "${IPTABLES_BIN}" ${table:+-t "${table}"} -A "${chain}" "${args[@]}"
  else
    log "iptables rule already present: ${table:+-t ${table} }${chain} ${args[*]}"
  fi
}

configure_iptables() {
  log "Configuring iptables forwarding and MASQUERADE  - ${AP_INTERFACE} -> ${UPSTREAM_INTERFACE}"
  ensure_iptables_rule nat POSTROUTING -o "${UPSTREAM_INTERFACE}" -j MASQUERADE
  ensure_iptables_rule "" FORWARD -i "${AP_INTERFACE}" -o "${UPSTREAM_INTERFACE}" -j ACCEPT
  ensure_iptables_rule "" FORWARD -i "${UPSTREAM_INTERFACE}" -o "${AP_INTERFACE}" -m state --state ESTABLISHED,RELATED -j ACCEPT

  log "Saving iptables rules to ${IPTABLES_RULES_V4}"
  install -d -m755 "$(dirname "${IPTABLES_RULES_V4}")"
  "${IPTABLES_SAVE_BIN}" >"${IPTABLES_RULES_V4}"
}

reset_iptables_rules() {
  log "Normalizing iptables rules for ${AP_INTERFACE} <-> ${UPSTREAM_INTERFACE}"
  if ! command -v "${IPTABLES_BIN}" >/dev/null 2>&1; then
    log "iptables unavailable; skipping iptables normalization"
    return
  fi
  delete_matching_rules nat POSTROUTING "-o ${UPSTREAM_INTERFACE} -j MASQUERADE"
  delete_matching_rules "" FORWARD "-i ${AP_INTERFACE} -o ${UPSTREAM_INTERFACE}"
  delete_matching_rules "" FORWARD "-i ${UPSTREAM_INTERFACE} -o ${AP_INTERFACE}"
  configure_iptables
}

ensure_networkmanager_not_managing_ap() {
  if ! command -v nmcli >/dev/null 2>&1 && [[ ! -d /etc/NetworkManager ]]; then
    log "NetworkManager not detected; skipping unmanaged enforcement for ${AP_INTERFACE}"
    return
  fi

  if ! networkmanager_manages_ap_interface; then
    log "NetworkManager does not appear to manage ${AP_INTERFACE}"
    return
  fi

  local snippet_path
  snippet_path="$(networkmanager_unmanaged_conf_path)"

  log "NetworkManager appears to manage ${AP_INTERFACE}; marking it unmanaged via ${snippet_path}"
  install -d -m755 "${NETWORKMANAGER_CONF_DIR}"
  install -Dm644 /dev/stdin "${snippet_path}" <<EOF
[keyfile]
unmanaged-devices=interface-name:${AP_INTERFACE}
EOF

  if command -v nmcli >/dev/null 2>&1; then
    if nmcli general reload >/dev/null 2>&1; then
      log "Reloaded NetworkManager configuration via nmcli general reload"
    else
      log "nmcli general reload failed; attempting ${SYSTEMCTL_BIN} reload NetworkManager"
      if ! "${SYSTEMCTL_BIN}" reload NetworkManager >/dev/null 2>&1; then
        fail "NetworkManager appears to manage ${AP_INTERFACE}, and reloading NetworkManager failed. Reload or restart NetworkManager, then rerun provisioning."
      fi
    fi
  else
    fail "NetworkManager configuration indicates ${AP_INTERFACE} is managed, but nmcli is unavailable to reload. Reload or restart NetworkManager manually, then rerun provisioning."
  fi

  if networkmanager_manages_ap_interface; then
    fail "NetworkManager still reports managing ${AP_INTERFACE} after attempting to mark it unmanaged. Resolve NetworkManager configuration and rerun provisioning."
  fi
}

reset_ap_interface_address() {
  if [[ -z "${AP_IP_CIDR}" ]]; then
    log "No AP IP CIDR provided; skipping IP reset"
    return
  fi

  if ip link show "${AP_INTERFACE}" >/dev/null 2>&1; then
    log "Resetting ${AP_INTERFACE} address to ${AP_IP_CIDR}"
    ip addr flush dev "${AP_INTERFACE}" || true
    ip addr add "${AP_IP_CIDR}" dev "${AP_INTERFACE}" || true
    ip link set "${AP_INTERFACE}" up || true
  else
    log "AP interface ${AP_INTERFACE} missing; skipping IP reset"
  fi
}

normalize_runtime_state() {
  ensure_mcbridge_dirs
  ensure_networkmanager_not_managing_ap
  stop_conflicting_services
  remove_outdated_units
  reset_iptables_rules
  reset_ap_interface_address
  ensure_ip_forwarding
}

ensure_ap_unit_ready() {
  local ap_unit
  ap_unit="$(basename "${AP_SERVICE_PATH}")"

  ensure_unit_unmasked "${ap_unit}"
  log "Enabling ${ap_unit} to ensure ${AP_INTERFACE} exists"
  "${SYSTEMCTL_BIN}" enable "${ap_unit}"

  local ap_state
  ap_state="$("${SYSTEMCTL_BIN}" is-active "${ap_unit}" 2>/dev/null || true)"
  if [[ "${ap_state}" == "active" ]]; then
    log "Restarting ${ap_unit} to ensure ${AP_INTERFACE} exists"
    "${SYSTEMCTL_BIN}" restart "${ap_unit}"
  else
    log "Starting ${ap_unit} to ensure ${AP_INTERFACE} exists"
    "${SYSTEMCTL_BIN}" start "${ap_unit}"
  fi

  ensure_ap_interface_up
}

ensure_ap_ip_service_applied() {
  local ap_ip_unit
  ap_ip_unit="$(basename "${AP_IP_SERVICE_PATH}")"

  ensure_unit_unmasked "${ap_ip_unit}"
  log "Reloading systemd units before starting ${ap_ip_unit}"
  "${SYSTEMCTL_BIN}" daemon-reload
  log "Enabling and starting ${ap_ip_unit} for ${AP_INTERFACE} ${AP_IP_CIDR}"
  "${SYSTEMCTL_BIN}" enable --now "${ap_ip_unit}"

  if ! ap_interface_has_cidr "${AP_INTERFACE}" "${AP_IP_CIDR}"; then
    log "${ap_ip_unit} did not configure ${AP_INTERFACE} with ${AP_IP_CIDR} on first start; restarting"
    "${SYSTEMCTL_BIN}" restart "${ap_ip_unit}"
  fi

  if ! ap_interface_has_cidr "${AP_INTERFACE}" "${AP_IP_CIDR}"; then
    fail "$(cat <<EOF
${ap_ip_unit} started but ${AP_INTERFACE} is missing ${AP_IP_CIDR}.
Check systemctl status ${ap_ip_unit} and $(basename "${AP_SERVICE_PATH}") for errors, then rerun provisioning.
EOF
)"
  fi
}

ensure_service_depends_on_ap() {
  local service="$1"
  local ap_unit
  ap_unit="$(basename "${AP_SERVICE_PATH}")"
  local drop_in_dir="/etc/systemd/system/${service}.d"
  local drop_in_path="${drop_in_dir}/mcbridge-wlan0ap.conf"

  log "Ensuring ${service} depends on ${ap_unit} via drop-in"
  install -d -m755 "${drop_in_dir}"
  write_drop_in "${drop_in_path}" <<EOF
[Unit]
After=${ap_unit}
Requires=${ap_unit}
EOF
}

ensure_service_account
ensure_operator_group
write_sudoers_dropin
resolve_owner_and_group
log "Starting mcbridge provisioning with AP=${AP_INTERFACE}, upstream=${UPSTREAM_INTERFACE}"
PROVISION_STATUS="pending"

require_command "${APT_BIN}"
require_command "${SYSTEMCTL_BIN}"
require_command "${SYSCTL_BIN}"
require_command "${PYTHON_BIN}"

if run_preflight_checks; then
  if [[ "${FORCE}" -eq 0 ]]; then
    log "Preflight is clean; nothing required."
    PROVISION_STATUS="noop"
    echo "PROVISION_STATUS=${PROVISION_STATUS}"
    exit 0
  fi
  log "Preflight is clean but --force was supplied; continuing with provisioning."
  DO_CLEANUP=1
else
  log "Preflight failed; proceeding with provisioning to correct missing state."
  DO_CLEANUP=1
fi

if [[ "${DO_CLEANUP}" -eq 1 ]]; then
  log "Preflight drift or --force detected; running cleanup before applying configuration."
  normalize_runtime_state
  recover_ap_interface_if_needed
else
  log "Skipping cleanup; preflight clean and --force not set."
fi

log "Updating apt cache via ${APT_BIN}"
DEBIAN_FRONTEND=noninteractive "${APT_BIN}" update -y
log "Installing hostapd, dnsmasq, and iptables"
DEBIAN_FRONTEND=noninteractive "${APT_BIN}" install -y hostapd dnsmasq iptables

require_command "${IPTABLES_BIN}"
require_command "${IPTABLES_SAVE_BIN}"
reset_ap_configs

log "Dropping wlan0ap.service to ${AP_SERVICE_PATH}"
install_unit_from_source_or_render "${WLAN0AP_UNIT_SOURCE}" "${AP_SERVICE_PATH}" wlan0ap --ap-interface "${AP_INTERFACE}" --upstream-interface "${UPSTREAM_INTERFACE}"

if [[ -n "${AP_IP_CIDR}" ]]; then
  log "Dropping wlan0ap-ip.service to ${AP_IP_SERVICE_PATH} for ${AP_IP_CIDR}"
  install_unit_from_source_or_render "${WLAN0AP_IP_UNIT_SOURCE}" "${AP_IP_SERVICE_PATH}" wlan0ap-ip --ap-interface "${AP_INTERFACE}" --ap-ip-cidr "${AP_IP_CIDR}" --ap-service-unit "${AP_SERVICE_PATH##*/}"
fi

ensure_service_depends_on_ap hostapd.service
ensure_service_depends_on_ap dnsmasq.service

log "Reloading systemd units"
"${SYSTEMCTL_BIN}" daemon-reload

ensure_ap_unit_ready
if [[ -n "${AP_IP_CIDR}" ]]; then
  ensure_ap_ip_service_applied
fi
enable_service hostapd.service
enable_service dnsmasq.service
if [[ "${DNSMASQ_CONF_UPDATED}" -eq 1 ]]; then
  restart_dnsmasq_after_apply
fi

ensure_ip_forwarding
configure_iptables

log "Provisioning completed successfully."
PROVISION_STATUS="applied"
