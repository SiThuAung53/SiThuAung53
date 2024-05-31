#!/bin/bash
#
# Outline Server installation script
#
# Licensed under the Apache License, Version 2.0 (the "License");

set -euo pipefail

function display_usage() {
  cat <<EOF
Usage: install_server.sh [--hostname <hostname>] [--api-port <port>] [--keys-port <port>]

  --hostname   The hostname to be used to access the management API and access keys
  --api-port   The port number for the management API
  --keys-port  The port number for the access keys
EOF
}

readonly SENTRY_LOG_FILE=${SENTRY_LOG_FILE:-}

FULL_LOG="$(mktemp -t outline_logXXXXXXXXXX)"
LAST_ERROR="$(mktemp -t outline_last_errorXXXXXXXXXX)"
readonly FULL_LOG LAST_ERROR

function log_command() {
  "$@" > >(tee -a "${FULL_LOG}") 2> >(tee -a "${FULL_LOG}" > "${LAST_ERROR}")
}

function log_error() {
  local -r ERROR_TEXT="\033[0;31m"  # red
  local -r NO_COLOR="\033[0m"
  echo -e "${ERROR_TEXT}$1${NO_COLOR}"
  echo "$1" >> "${FULL_LOG}"
}

function log_start_step() {
  log_for_sentry "$@"
  local -r str="> $*"
  local -ir lineLength=47
  echo -n "${str}"
  local -ir numDots=$(( lineLength - ${#str} - 1 ))
  if (( numDots > 0 )); then
    echo -n " "
    for _ in $(seq 1 "${numDots}"); do echo -n .; done
  fi
  echo -n " "
}

function run_step() {
  local -r msg="$1"
  log_start_step "${msg}"
  shift 1
  if log_command "$@"; then
    echo "OK"
  else
    return
  fi
}

function confirm() {
  echo -n "> $1 [Y/n] "
  local RESPONSE
  read -r RESPONSE
  RESPONSE=$(echo "${RESPONSE}" | tr '[:upper:]' '[:lower:]') || return
  [[ -z "${RESPONSE}" || "${RESPONSE}" == "y" || "${RESPONSE}" == "yes" ]]
}

function command_exists {
  command -v "$@" &> /dev/null
}

function log_for_sentry() {
  if [[ -n "${SENTRY_LOG_FILE}" ]]; then
    echo "[$(date "+%Y-%m-%d@%H:%M:%S")] install_server.sh" "$@" >> "${SENTRY_LOG_FILE}"
  fi
  echo "$@" >> "${FULL_LOG}"
}

function verify_docker_installed() {
  if command_exists docker; then
    return 0
  fi
  log_error "NOT INSTALLED"
  if ! confirm "Would you like to install Docker? This will run 'curl https://get.docker.com/ | sh'."; then
    exit 0
  fi
  if ! run_step "Installing Docker" install_docker; then
    log_error "Docker installation failed, please visit https://docs.docker.com/install for instructions."
    exit 1
  fi
  log_start_step "Verifying Docker installation"
  command_exists docker
}

function verify_docker_running() {
  local STDERR_OUTPUT
  STDERR_OUTPUT="$(docker info 2>&1 >/dev/null)"
  local -ir RET=$?
  if (( RET == 0 )); then
    return 0
  elif [[ "${STDERR_OUTPUT}" == *"Is the docker daemon running"* ]]; then
    start_docker
    return
  fi
  return "${RET}"
}

function fetch() {
  curl --silent --show-error --fail "$@"
}

function install_docker() {
  (
    umask 0022
    fetch https://get.docker.com/ | sh
  ) >&2
}

function start_docker() {
  systemctl enable --now docker.service >&2
}

function docker_container_exists() {
  docker ps -a --format '{{.Names}}'| grep --quiet "^$1$"
}

function remove_shadowbox_container() {
  remove_docker_container "${CONTAINER_NAME}"
}

function remove_watchtower_container() {
  remove_docker_container watchtower
}

function remove_docker_container() {
  docker rm -f "$1" >&2
}

function handle_docker_container_conflict() {
  local -r CONTAINER_NAME="$1"
  local -r EXIT_ON_NEGATIVE_USER_RESPONSE="$2"
  local PROMPT="The container name \"${CONTAINER_NAME}\" is already in use by another container. This may happen when running this script multiple times."
  if [[ "${EXIT_ON_NEGATIVE_USER_RESPONSE}" == 'true' ]]; then
    PROMPT="${PROMPT} We will attempt to remove the existing container and restart it. Would you like to proceed?"
  else
    PROMPT="${PROMPT} Would you like to replace this container? If you answer no, we will proceed with the remainder of the installation."
  fi
  if ! confirm "${PROMPT}"; then
    if ${EXIT_ON_NEGATIVE_USER_RESPONSE}; then
      exit 0
    fi
    return 0
  fi
  if run_step "Removing ${CONTAINER_NAME} container" "remove_${CONTAINER_NAME}_container" ; then
    log_start_step "Restarting ${CONTAINER_NAME}"
    "start_${CONTAINER_NAME}"
    return $?
  fi
  return 1
}

function finish {
  local -ir EXIT_CODE=$?
  if (( EXIT_CODE != 0 )); then
    if [[ -s "${LAST_ERROR}" ]]; then
      log_error "\nLast error: $(< "${LAST_ERROR}")" >&2
    fi
    log_error "\nSorry! Something went wrong. If you can't figure this out, please copy and paste all this output into the Outline Manager screen, and send it to us, to see if we can help you." >&2
    log_error "Full log: ${FULL_LOG}" >&2
  else
    rm "${FULL_LOG}"
  fi
  rm "${LAST_ERROR}"
}

function get_random_port {
  local -i num=0  # Init to an invalid value, to prevent "unbound variable" errors.
  until (( 1024 <= num && num < 65536)); do
    num=$(( RANDOM + (RANDOM % 2) * 32768 ));
  done;
  echo "${num}";
}

function create_persisted_state_dir() {
  readonly STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
  mkdir -p "${STATE_DIR}"
  chmod ug+rwx,g+s,o-rwx "${STATE_DIR}"
}

function safe_base64() {
  local url_safe
  url_safe="$(base64 -w 0 - | tr '/+' '_-')"
  echo -n "${url_safe%%=*}"
}

function generate_secret_key() {
  SB_API_PREFIX="$(head -c 16 /dev/urandom | safe_base64)"
  readonly SB_API_PREFIX
}

function generate_certificate() {
  local -r CERTIFICATE_NAME="${STATE_DIR}/shadowbox-selfsigned"
  readonly SB_CERTIFICATE_FILE="${CERTIFICATE_NAME}.crt"
  readonly SB_PRIVATE_KEY_FILE="${CERTIFICATE_NAME}.key"
  declare -a openssl_req_flags=(
    -x509 -nodes -days 36500 -newkey rsa:4096
    -subj "/CN=${PUBLIC_HOSTNAME}"
    -keyout "${SB_PRIVATE_KEY_FILE}" -out "${SB_CERTIFICATE_FILE}"
  )
  openssl req "${openssl_req_flags[@]}" >&2
}

function generate_certificate_fingerprint() {
  local CERT_OPENSSL_FINGERPRINT
  CERT_OPENSSL_FINGERPRINT="$(openssl x509 -in "${SB_CERTIFICATE_FILE}" -noout -sha256 -fingerprint)" || return
  local CERT_HEX_FINGERPRINT
  CERT_HEX_FINGERPRINT="$(echo "${CERT_OPENSSL_FINGERPRINT#*=}" | tr -d :)" || return
  output_config "certSha256:${CERT_HEX_FINGERPRINT}"
}

function join() {
  local IFS="$1"
  shift
  echo "$*"
}

function write_config() {
  local -a config=()
  if (( FLAGS_KEYS_PORT != 0 )); then
    config+=("\"portForNewAccessKeys\": ${FLAGS_KEYS_PORT}")
  fi
  if [[ -n "${SB_DEFAULT_SERVER_NAME:-}" ]]; then
    config+=("\"name\": \"$(escape_json_string "${SB_DEFAULT_SERVER_NAME}")\"")   
  fi
  config+=("\"hostname\": \"$(escape_json_string "${PUBLIC_HOSTNAME}")\"")
  config+=("\"method\": \"none\"")
  echo "{$(join , "${config[@]}")}" > "${STATE_DIR}/shadowbox_server_config.json"
}

function start_shadowbox() {
  local -r START_SCRIPT="${STATE_DIR}/start_container.sh"
  local CERTIFICATE_VOLUME_FLAGS=""
  if [[ -n "${SB_CERTIFICATE_FILE:-}" ]]; then
    CERTIFICATE_VOLUME_FLAGS="-v ${SB_CERTIFICATE_FILE}:${SB_CERTIFICATE_FILE}:ro -v ${SB_PRIVATE_KEY_FILE}:${SB_PRIVATE_KEY_FILE}:ro"
  fi
  local SB_API_PORT_ARG="--port 8081:8081"
  if (( FLAGS_API_PORT != 0 )); then
    SB_API_PORT_ARG="--port ${FLAGS_API_PORT}:${FLAGS_API_PORT}"
  fi
  local DOCKER_ENV_ARGS=""
  if [[ -n "${SENTRY_LOG_FILE}" ]]; then
    DOCKER_ENV_ARGS+=" --env SENTRY_LOG_FILE=${SENTRY_LOG_FILE}"
  fi
  local -ar START_CMD=(
    docker run --name shadowbox --restart=always --net=host --cap-add=NET_ADMIN
      -v "${STATE_DIR}:${STATE_DIR}"
      ${CERTIFICATE_VOLUME_FLAGS}
      ${SB_IMAGE} "--metrics-url=${METRICS_URL:-}" --apiPrefix="${SB_API_PREFIX}" ${SB_API_PORT_ARG}
      -v "${STATE_DIR}/shadowbox_server_config.json:/opt/outline/persisted-state/shadowbox_server_config.json"
      ${DOCKER_ENV_ARGS}
  )
  printf "#!/bin/bash\n%s\n" "$(join " " "${START_CMD[@]}")" > "${START_SCRIPT}"
  chmod +x "${START_SCRIPT}"
  "${START_SCRIPT}"
}

function start_watchtower() {
  local -ar WATCHTOWER_CMD=(
    docker run --name watchtower --restart=always --net=host --cap-add=NET_ADMIN
      --volume /var/run/docker.sock:/var/run/docker.sock
      --volume "${STATE_DIR}:${STATE_DIR}"
      v2tec/watchtower --interval ${WATCHTOWER_REFRESH_SECONDS}
  )
  "${WATCHTOWER_CMD[@]}"
}

function wait_shadowbox() {
  for i in $(seq 1 10); do
    local SB_CONTAINER_STATUS
    SB_CONTAINER_STATUS="$(docker inspect -f '{{.State.Health.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo 'unknown')"
    if [[ "${SB_CONTAINER_STATUS}" == 'healthy' ]]; then
      return 0
    fi
    echo "Waiting for Outline Server to be healthy..."
    sleep 3
  done
  echo "Outline Server didn't start. Please check the logs and try again."
  exit 1
}

function create_first_user() {
  if run_step "Creating first user" curl -X POST -H "Content-Type: application/json" --data '{"userId":"initial_user"}' "http://localhost:8081/access-keys" ; then
    output_config "first_user_created:true"
  else
    log_error "Failed to create first user."
  fi
}

function output_config() {
  echo "$1" >> "${ACCESS_CONFIG}"
}

function add_api_url_to_config() {
  output_config "apiUrl:http://${PUBLIC_HOSTNAME}:${FLAGS_API_PORT:-8081}/$1"
}

function check_firewall() {
  if command_exists iptables && iptables --wait -L -nv; then
    iptables --wait -L -nv > "${STATE_DIR}/iptables.txt"
  fi
}

function set_hostname() {
  local -r URL="http://${PUBLIC_HOSTNAME}:${FLAGS_API_PORT:-8081}"
  output_config "hostname:${PUBLIC_HOSTNAME}"
  output_config "apiUrl:${URL}/$(< "${STATE_DIR}/api-prefix")"
  echo "Your Outline Server is set up and running. You can manage your server with the Outline Manager."
}

function install_shadowbox() {
  log_start_step "Verifying Docker is installed"
  if ! verify_docker_installed; then
    log_error "Docker is required to install Outline Server. Please install Docker and try again."
    exit 1
  fi

  log_start_step "Verifying Docker is running"
  if ! verify_docker_running; then
    log_error "Docker is not running. Please start Docker and try again."
    exit 1
  fi

  create_persisted_state_dir
  generate_secret_key
  generate_certificate
  write_config
  start_shadowbox
  wait_shadowbox
  create_first_user
  start_watchtower
  check_firewall
  set_hostname
}

function is_valid_port() {
  local -r port="$1"
  [[ "${port}" =~ ^[0-9]+$ ]] && (( 1024 <= port && port <= 65535 ))
}

function escape_json_string() {
  local input="$1"
  input="${input//\\/\\\\}"
  input="${input//\"/\\\"}"
  input="${input//	/\\t}"
  input="${input//
/\\n}"
  input="${input//
/\\r}"
  echo -n "${input}"
}

function parse_flags() {
  FLAGS_API_PORT=0
  FLAGS_KEYS_PORT=0
  FLAGS_HOSTNAME=""

  while (( "$#" )); do
    case "$1" in
      --api-port)
        FLAGS_API_PORT="$2"
        shift 2
        ;;
      --keys-port)
        FLAGS_KEYS_PORT="$2"
        shift 2
        ;;
      --hostname)
        FLAGS_HOSTNAME="$2"
        shift 2
        ;;
      *)
        log_error "Unknown flag: $1"
        display_usage
        exit 1
        ;;
    esac
  done

  if (( FLAGS_API_PORT != 0 && ! is_valid_port "${FLAGS_API_PORT}" )); then
    log_error "Invalid API port: ${FLAGS_API_PORT}"
    display_usage
    exit 1
  fi

  if (( FLAGS_KEYS_PORT != 0 && ! is_valid_port "${FLAGS_KEYS_PORT}" )); then
    log_error "Invalid keys port: ${FLAGS_KEYS_PORT}"
    display_usage
    exit 1
  fi

  if [[ -n "${FLAGS_HOSTNAME}" ]]; then
    PUBLIC_HOSTNAME="${FLAGS_HOSTNAME}"
  else
    PUBLIC_HOSTNAME="$(curl -s http://whatismyip.akamai.com/)"
  fi

  readonly FLAGS_API_PORT FLAGS_KEYS_PORT FLAGS_HOSTNAME PUBLIC_HOSTNAME
}

parse_flags "$@"
install_shadowbox

trap finish EXIT
