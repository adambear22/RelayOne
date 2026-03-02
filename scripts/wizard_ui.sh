#!/usr/bin/env bash
# shellcheck shell=bash

# wizard_ui.sh — NodePass Deployment Wizard UI Library

if [[ "${NODEPASS_WIZARD_UI_LOADED:-0}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi
NODEPASS_WIZARD_UI_LOADED=1

RED='\033[0;31m'
LRED='\033[1;31m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
LBLUE='\033[1;34m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info() {
  echo -e "${CYAN} ℹ ${NC}$1"
}

success() {
  echo -e "${LGREEN} ✓ ${NC}$1"
}

warn() {
  echo -e "${YELLOW} ⚠ ${NC}$1"
}

error() {
  echo -e "${LRED} ✗ ${NC}$1" >&2
}

step() {
  local current="$1"
  local title="$2"
  local total="${TOTAL_STEPS:-?}"
  echo -e "\n${LBLUE}${BOLD}[ Step ${current}/${total} ] ${title}${NC}"
}

section() {
  echo -e "\n${PURPLE}${BOLD}━━━ $1 ━━━${NC}"
}

prompt() {
  echo -en "${BOLD} → $1${NC} "
}

hint() {
  echo -e "${DIM}   $1${NC}"
}

divider() {
  echo -e "${DIM}  ─────────────────────────────────────────${NC}"
}

show_banner() {
  if [[ -t 1 ]]; then
    clear
  fi

  echo -e "${BLUE}${BOLD}"
  echo '  ███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗  █████╗ ███████╗███████╗'
  echo '  ████╗  ██║██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝'
  echo '  ██╔██╗ ██║██║   ██║██║  ██║█████╗  ██████╔╝███████║███████╗███████╗'
  echo '  ██║╚██╗██║██║   ██║██║  ██║██╔══╝  ██╔═══╝ ██╔══██║╚════██║╚════██║'
  echo '  ██║ ╚████║╚██████╔╝██████╔╝███████╗██║     ██║  ██║███████║███████║'
  echo -e "${NC}"
  echo -e "  ${BOLD}NodePass 平台 · 交互式部署向导 v2.0${NC}"
  divider
}

ask_input() {
  local msg="$1"
  local default_value="$2"
  local varname="$3"
  local value=""

  if [[ -n "${default_value}" ]]; then
    prompt "${msg} ${DIM}[默认: ${default_value}]${NC}"
  else
    prompt "${msg} ${LRED}(必填)${NC}"
  fi
  read -r value
  value="${value:-$default_value}"
  printf -v "${varname}" '%s' "${value}"
}

ask_password() {
  local msg="$1"
  local varname="$2"
  local value=""

  prompt "${msg} ${LRED}(必填，输入不显示)${NC}"
  read -rs value
  echo
  printf -v "${varname}" '%s' "${value}"
}

ask_yn() {
  local msg="$1"
  local varname="$2"
  local default_value="${3:-n}"
  local options=""
  local yn=""

  if [[ "${default_value}" == "y" ]]; then
    options="[Y/n]"
  else
    options="[y/N]"
  fi

  prompt "${msg} ${options}"
  read -r yn
  yn="${yn:-$default_value}"
  if [[ "${yn}" =~ ^[Yy]$ ]]; then
    printf -v "${varname}" 'true'
  else
    printf -v "${varname}" 'false'
  fi
}

validate_domain() {
  [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]
}

validate_email() {
  [[ "$1" =~ ^[^@]+@[^@]+\.[^@]+$ ]]
}

gen_secret() {
  local length="${1:-32}"
  tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "${length}"
}

print_summary() {
  section "配置摘要确认"
  while [[ "$#" -gt 1 ]]; do
    printf "  ${BOLD}%-22s${NC} %s\n" "$1:" "$2"
    shift 2
  done
  divider
  ask_yn "以上配置是否正确？确认后开始部署" CONFIRMED y
  if [[ "${CONFIRMED}" != "true" ]]; then
    warn "已取消部署"
    exit 0
  fi
}

trap_exit() {
  echo
  warn "已中断，配置未写入"
  exit 130
}

trap trap_exit INT TERM
