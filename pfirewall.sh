#!/bin/bash

FULL_SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
CURRDIR="$(dirname "$FULL_SCRIPT_PATH")"
SCRIPT_NAME="$(basename "$FULL_SCRIPT_PATH")"
APP_VERSION="v0.1.3";
REPO_URL="https://github.com/phonevox/pfirewall"
ZIP_URL="$REPO_URL/archive/refs/heads/main.zip"

source ./lib/useful.sh
source ./lib/easyflags.sh

# ---

add_flag "d" "dry" "Do NOT make changes to the system" bool
add_flag "v" "verbose" "Verbose mode" bool
add_flag "vv" "super-verbose" "Enter super verbose mode, and show all commands made" bool
add_flag "s" "" "IPs to whitelist on top of defaults. Example: 0.0.0.0/0,192.168.1.1" str
add_flag "p" "" "Ports to drop on top of defaults. Example: 20-23/tcp,5060,80/udp,80/tcp,443:force" str 
add_flag "l" "list" "List current firewall rules/configuration and exit" bool
add_flag "V" "version" "Show app version and exit" bool
add_flag "atp:HIDDEN" "install" "Add this script to the system path and exits" bool

#ignores
add_flag "idp:HIDDEN" "ignore-default-ports" "Do NOT use default ports" bool
add_flag "ids:HIDDEN" "ignore-default-ips" "Do NOT use default IPs" bool
add_flag "idx:HIDDEN" "ignore-defaults" "Do NOT use default ports and IPs" bool
add_flag "ifs:HIDDEN" "ignore-failsafe" "Do NOT use the failsafe system" bool
add_flag "nf:HIDDEN" "no-flush" "Do NOT flush zones" bool


# to implement
# add_flag "e" "engine" "Firewall engine to use (firewalld(default) or iptables)" str # this is not implemented yet
add_flag "upd:HIDDEN" "update" "Update this script to the newest version" bool

set_description "This script aims to set the default firewall rules used by Phonevox, with their default IPs and ports, plus the possibility of adding extra IPs and ports."
parse_flags "$@"

# ---

# ignore this --> 🗸 🞩 ↺
DRY=false # dont change my system (default: false)
VERBOSE=false # describe everything (default: false)
SILENT=true # dont echo-back commands (not even dry-ones) (default: true)
LISTING=false # list current rules and exit
ADD_TO_PATH=false # add this script to the system path and exit

FLUSH_ZONES=true # flush all rules added from this script (default: true)

IGNORE_FAILSAFE=false # ignore ip failsafe when flushing
FAILSAFE_USER_IP=$(echo $SSH_CLIENT | awk '{print $1}') # ip of the user ssh session that ran the command
TRUST_FAILSAFE_IP=false # in a flush, should we trust the user's IP? (add it to the trusted list while script is in execution so we guarantee we dont get booted off mid-changes)

ENGINE="firewalld" # to-do, not implemented yet

BUFFER_ADDED_IPS="" # user ips
BUFFER_ADDED_PORTS="" # user ports
TRUST_ZONE_NAME="ptrusted"
DROP_ZONE_NAME="pdrop"
DEFAULT_TRUSTED_IPS=(
    #"IP or IP/CIDR"
    "127.0.0.1"         # LOCALHOST
    "10.0.0.0/8"        # INTERNO
    "172.16.0.0/12"     # INTERNO
    "192.168.0.0/16"    # INTERNO
    "189.124.85.75"     # PHONEVOX PRINCIPAL
    "186.233.124.252"   # PHONEVOX SECUNDARIO
    "189.124.85.152/29" # PHONEVOX REDE
    "186.233.120.72/29" # PHONEVOX REDE
    "209.14.71.154"     # PHONEVOX MAGNUS 1
    "149.78.185.36"     # PHONEVOX MAGNUS 2
    "51.79.49.144"      # PHONEVOX INTERNO/ZABBIX
    "45.140.193.125"    # PHONEVOX HELPDESK
    "186.233.122.92"    # PHONEVOX ABNER
)
DEFAULT_DROP_PORTS=(
    #"port/type:forcedrop"
    # "1/tcp:force" # EXAMPLE: tcp, force
    # "1/tcp"       # EXAMPLE: tcp, dont force
    # "1:force"     # EXAMPLE: tcp and udp (default), force
    # "1"           # EXAMPLE: tcp and udp (default), dont force
    "995/udp"       # POP3D
    "995/tcp"       # POP3D
    "110/udp"       # POP3D
    "110/tcp"       # POP3D
    "4569/udp"      # IAX
    "5353/udp"      # mDNS
    "20-23:force"   # 20 ftp(data), 21 ftp, 22 ssh, 23 telnet
    "80/tcp"        # HTTP
    "443/tcp"       # HTTPS
    "3306/tcp"      # MySQL
    "5038/tcp"      # Asterisk Manager Interface
    "21122/tcp"     # Phonevox custom ssh
    "10050/tcp"     # Zabbix (agent)
    "10051/tcp"     # Zabbix (server)
)

FIREWALLD_IS_ENABLED=false
FIREWALLD_IS_RUNNING=false
if hasFlag "d"; then DRY=true; fi
if hasFlag "l"; then LISTING=true; fi
if hasFlag "v"; then VERBOSE=true; fi
if hasFlag "V"; then VERBOSE=true; SILENT=false; fi
if hasFlag "nf"; then FLUSH_ZONES=false; fi
if hasFlag "ifs"; then IGNORE_FAILSAFE=true; fi
if hasFlag "idp"; then DEFAULT_DROP_PORTS=(); fi
if hasFlag "ids"; then DEFAULT_TRUSTED_IPS=(); fi
if hasFlag "idx"; then DEFAULT_TRUSTED_IPS=(); DEFAULT_DROP_PORTS=(); fi
if hasFlag "atp"; then ADD_TO_PATH=true; fi
if hasFlag "vrs"; then echo "$APP_VERSION"; exit 0; fi

# inform user about failsafe
if ! valid_ip $FAILSAFE_USER_IP; then
    echo "WARNING: $(colorir vermelho "FAILSAFE DISABLED")! Found session IP: $FAILSAFE_USER_IP"
    echo "WARNING: $(colorir vermelho "We cannot trust the found IP address, as it is in a bad format.")"
    TRUST_FAILSAFE_IP=false
else
    if $VERBOSE; then echo "VERBOSE: $(colorir verde "FAILSAFE is enabled"). Session IP: $FAILSAFE_USER_IP"; fi
    TRUST_FAILSAFE_IP=true
fi

# obtaining user IPs from flag
IPS_TO_ALLOW=()
if hasFlag "s"; then
    IFS=","
    for ip in $(getFlag "s"); do
        if valid_ip "$ip"; then
            IPS_TO_ALLOW+=($ip)
        else
            if $VERBOSE; then echo "VERBOSE: Invalid IP in user input: '$ip'"; fi
        fi
    done
    unset IFS
fi
IPS_TO_ALLOW+=("${DEFAULT_TRUSTED_IPS[@]}")

# obtaining user ports from flag
PORTS_TO_DROP=()
if hasFlag "p"; then
    IFS=","
    for port in $(getFlag "p"); do
        if [[ -n "$port" ]]; then
            PORTS_TO_DROP+=($port)
        else
            if $VERBOSE; then echo "VERBOSE: Invalid port in user input: '$port'"; fi
        fi
    done
    unset IFS
fi
PORTS_TO_DROP+=("${DEFAULT_DROP_PORTS[@]}")

# obtaining user IPs from stdin (if any)
# read_stdin comes from lib/useful.sh
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        if $VERBOSE; then echo "VERBOSE: stdin: $line"; fi
        IPS_TO_ALLOW+=("$line")
    fi
done <<< "$(read_stdin)" 2>&1 # i dont this this input redirect does shit LOL

# ---

# safe-run
srun () {
    local COMMAND=$1
    local USER_ACCEPTABLE_EXIT_CODES=$2

    run "$COMMAND >/dev/null" "$USER_ACCEPTABLE_EXIT_CODES" "$DRY" "$SILENT"
}


# stops application if firewalld is not running
# sets FIREWALLD_IS_RUNNING and FIREWALLD_IS_ENABLED
# so you dont need to system call again (singleton-style)
firewalld_check_status() {
    i=$((i+1)) # debug
    # echo "$i: Checking firewalld status..."
    # echo "$i: RUNNING: $FIREWALLD_IS_RUNNING"
    # echo "$i: ENABLED: $FIREWALLD_IS_ENABLED"
    if $FIREWALLD_IS_RUNNING; then
        if $VERBOSE; then echo "VERBOSE: Service firewalld is running. Early return."; fi
        return 0
    fi

    if $VERBOSE; then echo "VERBOSE: Starting singleton FIREWALLD_IS_RUNNING"; fi

    FIREWALLD_IS_ENABLED=false
    FIREWALLD_IS_RUNNING=false
    if systemctl is-enabled firewalld >/dev/null; then FIREWALLD_IS_ENABLED=true; fi
    if firewall-cmd -q --state; then FIREWALLD_IS_RUNNING=true; fi

    if ! $FIREWALLD_IS_RUNNING; then
        echo "Error: Service firewalld is not running."
        exit 1
    fi

    if $VERBOSE; then 
        if $FIREWALLD_IS_ENABLED; then echo "VERBOSE: Enabled: true"; fi
        if $FIREWALLD_IS_RUNNING; then echo "VERBOSE: Running: true"; fi
    fi

    return 0
}


# guarantees that the specific zone exists.
# if it does not exist, create it
# if anything goes wrong, fails hard
# Usage: firewalld_create_zone "trusted"
firewalld_guarantee_zone() {
    local zone=$1
    local zone_target=$2
    local _text_message=""

    # argument validation
    if [ -z "$zone" ]; then
        echo "Error: No zone argument sent for firewalld_guarantee_zone."
        exit 1
    fi

    # checking if firewalld is running
    if ! $FIREWALLD_IS_RUNNING; then firewalld_check_status; fi

    # checking if we should create the zone
    if ! firewall-cmd --permanent --get-zones | grep -qw "$zone"; then
        if $VERBOSE; then echo "VERBOSE: Zone '$zone' does not exist. Creating..."; fi
        srun "firewall-cmd --permanent --new-zone=$zone" # if it fails, it will exit bc we only allow exit code 0
        if [ -n "$zone_target" ]; then
            srun "firewall-cmd --permanent --zone=$zone --set-target=$zone_target"
        fi
    else
        if $VERBOSE; then echo "VERBOSE: Zone '$zone' already exists."; fi

        # Check if the zone target is as expected
        local current_target=$(firewall-cmd --permanent --zone=$zone --get-target)
        if [ "$current_target" != "$zone_target" ]; then
            if $VERBOSE; then echo "VERBOSE: Zone '$zone' target is '$current_target', setting to '$zone_target'..."; fi
            srun "firewall-cmd --permanent --zone=$zone --set-target=$zone_target"
        else
            if $VERBOSE; then echo "VERBOSE: Zone '$zone' already has the target '$zone_target'."; fi
        fi
    fi

    # here, the zone is created

}


# akshually 🤓
# this doesnt flush, but instead, drops the zone so firewalld_guarantee_zone() 
# can create it again without any rules.
# Usage: firewalld_flush_zone "ptrusted"
firewalld_flush_zone() {
    local zone=$1
    local _text_message=""

    # argument validation
    if [ -z "$zone" ]; then
        echo "Error: No zone argument sent for firewalld_guarantee_zone."
        exit 1
    fi

    # checking if firewalld is running
    if ! $FIREWALLD_IS_RUNNING; then firewalld_check_status; fi

    # deleting zone to consider "flush"
    if firewall-cmd --permanent --get-zones | grep -qw "$zone"; then
        if $VERBOSE; then echo "VERBOSE: Flushing zone '$zone'"; fi
        srun "firewall-cmd --permanent --delete-zone=\"$zone\""
    fi
}


# adds a trusted ip to the firewalld
# if already whitelisted, does nothing
# checks if firewalld is running first, fails if not
# optionally, you can pass zone as second argument
# Usage: firewalld_add_trusted "192.168.1.1/24"
firewalld_add_trusted() {
    local ip=$1
    local zone=$TRUST_ZONE_NAME # default zone
    if  ! [ -z "$2" ]; then local zone=$2; fi # if second argument is passed, interpret as zone
    local _text_message=""

    # argument validation
    if [ -z "$ip" ]; then
        echo "Error: No IP argument sent for whitelist."
        exit 1
    fi

    # lets see if the firewalld is running
    if ! $FIREWALLD_IS_RUNNING; then firewalld_check_status; fi

    # adding to trusted zone, if its not added yet
    if ! valid_ip "$ip"; then
        local _text_color=vermelho
        local _text_message="[$(colorir $_text_color "✗")] $(colorir $_text_color "$zone : $ip") (bad address)"
    elif firewall-cmd --zone=$zone --list-sources | grep -q "$ip"; then
        local _text_color=cinza
        local _text_message="[$(colorir $_text_color "●")] $(colorir $_text_color "$zone : $ip") (already trusted)"
    else
        # not in zone
        if [[ "$BUFFER_ADDED_IPS" =~ (^| )$ip( |$) ]]; then
            local _text_color=cinza
            local _text_message="[$(colorir $_text_color "●")] $(colorir $_text_color "$zone : $ip") (previously added)"
        else
            srun "firewall-cmd --permanent --zone=$zone --add-source=\"$ip\"" "0,18"
            local _text_color=verde
            local _text_message="[$(colorir $_text_color "🗸")] $(colorir $_text_color "$zone : $ip")"
            BUFFER_ADDED_IPS="$BUFFER_ADDED_IPS $ip"
        fi
    fi

    echo "$_text_message"
    return 0
}


# uhh, yeah
# my creativity ran out right here
# Usage: firewall_do_zone_stuff
firewalld_do_zone_stuff() {
    echo "--- CHECKING ZONES, MIGHT TAKE A WHILE"

    if $IGNORE_FAILSAFE; then
        echo "--- $(colorir vermelho "FAILSAFE IS DISABLED")"
    elif $TRUST_FAILSAFE_IP; then
        # we can trust this ip, lets add it to the trusted zone (the one we wont mess with)
        # and keep running the script
        if $VERBOSE; then echo "VERBOSE: As a failsafe measure, we will add this session's IP ($FAILSAFE_USER_IP) to trusted zone."; fi
        firewalld_add_trusted "$FAILSAFE_USER_IP" trusted
    else 
        echo "Error: FAILSAFE: We cannot trust your session's IP address ($FAILSAFE_USER_IP). If you proceed, you might lose access to the system. Guarantee you won't loose access to the system. If this is wrong, run with --ignore-failsafe."
        exit 1
    fi

    if $FLUSH_ZONES; then
        firewalld_flush_zone "$TRUST_ZONE_NAME"
        firewalld_flush_zone "$DROP_ZONE_NAME"
        firewalld_reload # this HAS to be an early flush
    else
        echo "--- $(colorir vermelho "ZONE FLUSHING IS DISABLED")"
    fi

    firewalld_guarantee_zone "$TRUST_ZONE_NAME" "ACCEPT"
    firewalld_guarantee_zone "$DROP_ZONE_NAME" "DROP" # guarantee that zone exists, and its on drop mode
    firewalld_reload # apply creation
}


# drops a port in the firewalld
# if already dropped, does nothing
# checks if firewalld is running first, fails if not
# can force-drop a port, even if not in use, passing $3=true
# Usage: firewalld_drop_port "port:integer/range" "protocol:tcp/udp..." "force:true/false"
# i.e. firewalld_drop_port "80" "tcp" "true"
# i.e. firewalld_drop_port "20-23" "tcp" ""
firewalld_drop_port() {
    local port=$1
    local type=$2 # optional, if not present, will drop both tcp and udp
    local zone=$DROP_ZONE_NAME
    local force=$false # optionally force-drop the port, even if its not present
    if [[ "$3" == "true" ]]; then local force=true; fi
    local _port_is_open=0
    local _text_message=""

    # argument validation
    if [ -z "$port" ]; then
        echo "Error: No port argument sent for drop."
        return 1
    fi

    # type validation
    if [ -z "$type" ]; then
        if $VERBOSE; then echo "VERBOSE: Type not set, dropping udp and tcp"; fi

        if $VERBOSE; then echo "VERBOSE: Starting drop for $port/tcp. FORCE:$force"; fi
        firewalld_drop_port "$port" tcp $force
        if $VERBOSE; then echo "VERBOSE: Starting drop for $port/udp. FORCE:$force"; fi
        firewalld_drop_port "$port" udp $force
        return 0
    else
        if ! [[ "$type" =~ ^(tcp|udp|icmp|sctp|dccp|gre|ah|esp)$ ]]; then
            local _text_color=vermelho
            local _text_message="[$(colorir $_text_color "✗")] $(colorir $_text_color "$zone : $port/$type") (bad type)"
            echo $_text_message
            return 0
        fi
    fi

    # need to check if its a port-range (examples: 20-23, 10000-20000)
    local regex_port_range="^[0-9]+-[0-9]+$"
    local regex_is_integer="^[0-9]+$"

    if [[ "$port" =~ $regex_port_range ]]; then
        local start_port=$(echo "$port" | cut -d '-' -f 1)
        local end_port=$(echo "$port" | cut -d '-' -f 2)

        #failsafe: confirm both are integers
        if ! [[ "$start_port" =~ $regex_is_integer && "$end_port" =~ $regex_is_integer ]]; then
            local _text_color=vermelho
            local _text_message="[$(colorir $_text_color "✗")] $(colorir $_text_color "$zone : $port/$type") (bad range)"
            echo $_text_message
            return 0
        fi

        #failsafe: you write something like 23-20, which dont make sense. start on left, end on right
        if [[ "$start_port" -gt "$end_port" ]]; then
            local _text_color=vermelho
            local _text_message="[$(colorir $_text_color "✗")] $(colorir $_text_color "$zone : $port/$type") (bad range)"
            echo $_text_message
            return 0
        fi

        # loop through all ports in range
        for i in $(seq $start_port $end_port); do
            firewalld_drop_port "$i" "$type" $force
        done
        return 0
    fi

    # failsafe: port must be an integer
    if ! [[ "$port" =~ $regex_is_integer ]]; then
        # in respect for type validation, we will not display type
        local _text_color=vermelho
        local _text_message="[$(colorir $_text_color "✗")] $(colorir $_text_color "$port/$type") (bad port)"
        echo $_text_message
        return 0
    fi

    # before we proceed with any change, confirm firewalld is running
    if ! $FIREWALLD_IS_RUNNING; then firewalld_check_status; fi

    # obtaining port status
    firewall-cmd --zone=$zone --list-ports | grep -q "$port/$type" && _port_is_open=true || _port_is_open=false

    # if $VERBOSE; then echo "VERBOSE: Port $port/$type open? $_port_is_open"; fi

    if ! $_port_is_open; then
        # port is not open: its already dropped or not added yet
        if [[ "$force" == "true" ]]; then
            srun "firewall-cmd --permanent --zone=$zone --add-port=$port/$type"
            local _text_color=verde_lima
            local _text_message="[$(colorir $_text_color "🗸")] $(colorir $_text_color "$zone : $port/$type") (forced)"
        else
            local _text_color=cinza
            local _text_message="[$(colorir $_text_color "●")] $(colorir $_text_color "$zone : $port/$type") (not open)"
        fi
    else
        srun "firewall-cmd --permanent --zone=$zone --add-port=$port/$type"
        local _text_color=verde
        local _text_message="[$(colorir $_text_color "🗸")] $(colorir $_text_color "$zone : $port/$type")"
    fi

    echo  "$_text_message"
    return 0
}


# list the current firewalld configuration, and informations about this script
# Usage: firewalld_list_configuration
firewalld_list_configuration() {

    echo "=~= $(colorir "azul" "YOUR SESSION IP FOR FAILSAFE MEASURES IS: $FAILSAFE_USER_IP") =~="

    echo "=~= $(colorir "azul" "IPS TO BE ADDED (changes based on how you call this script)") =~="
    for i in "${IPS_TO_ALLOW[@]}"; do
        echo "  - $i"
    done

    echo "=~= $(colorir "azul" "PORTS TO BE BLOCKED (changes based on how you call this script)") =~="
    for i in "${PORTS_TO_DROP[@]}"; do
        echo "  - $i"
    done

    echo "=~= $(colorir "verde" "CURRENT trusted (failsafe) ZONE") =~="
    firewall-cmd --zone=trusted --list-all | egrep "target|sources"
    # firewall-cmd --zone=trusted --list-sources
    # firewall-cmd --permanent --zone=trusted --get-target

    echo "=~= $(colorir "verde" "CURRENT $TRUST_ZONE_NAME (allow) ZONE") =~="
    firewall-cmd --zone=$TRUST_ZONE_NAME --list-all | egrep "target|sources"
    # firewall-cmd --zone=$TRUST_ZONE_NAME --list-sources egrep "target|sources|ports"
    # firewall-cmd --permanent --zone=$TRUST_ZONE_NAME --get-target

    echo "=~= $(colorir "vermelho" "CURRENT $DROP_ZONE_NAME (port drop) ZONE") =~="
    firewall-cmd --zone=$DROP_ZONE_NAME --list-all | egrep "target| ports"
    # firewall-cmd --zone=$DROP_ZONE_NAME --list-ports | egrep "target|sources|ports"
    # firewall-cmd --permanent --zone=$DROP_ZONE_NAME --get-target
    exit 0
}


# add to system path
# THIS IS HEAVY TO-DO
# Usage: add_script_to_path 
add_script_to_path() {
    local _BIN_NAME="pfirewall"
    local _PATH="/usr/sbin/$_BIN_NAME"
    local _PATH_SCRIPT_BINARY="$FULL_SCRIPT_PATH"

    local _CURRENT_SYMLINK_PATH=$(readlink -f "$_PATH") # where the current symlink is pointing towards
    if [[ -f "$_CURRENT_SYMLINK_PATH" ]]; then _SYMLINK_FILE_EXISTS=true; else _SYMLINK_FILE_EXISTS=false; fi # does the file which the symlink is pointing towards to, exists?

    echo "- $(colorir "azul" "Trying to add '$FULL_SCRIPT_PATH' to path '$_PATH'")"
    if [[ "$_CURRENT_SYMLINK_PATH" == "$_PATH_SCRIPT_BINARY" ]]; then
        # symlink is pointing towards this script.
        echo "- $(colorir verde "Your symlink ($_PATH) is set up correctly: $_PATH")"
    else
        if $_SYMLINK_FILE_EXISTS; then # symlink is pointing towards something else
            echo "- $(colorir amarelo "Your symlink ($_PATH) is pointing to something else: $_CURRENT_SYMLINK_PATH (expected $FULL_SCRIPT_PATH)")"
            echo "> Do you want to update it? ($(colorir verde y)/$(colorir vermelho n))"
            read -r _answer
            if ! [[ "$_answer" == "y" ]]; then
                echo "Exiting..."
                exit 1
            fi
        fi

        # symlink does not exist, and user is fine with it being created
        echo "- $(colorir verde "Adding to path... ('$_PATH' -> '$_PATH_SCRIPT_BINARY')")"
        srun "ln -sf \"$_PATH_SCRIPT_BINARY\" \"$_PATH\""
    fi

    exit 0
}


# literally just a reload
# Usage: firewalld_reload
firewalld_reload() {
    srun "firewall-cmd --reload"
}

# ---===---
# For updates

check_for_updates() {
    local CURRENT_VERSION=$APP_VERSION
    local LATEST_VERSION="$(curl -s https://api.github.com/repos/phonevox/pfirewall/releases/latest | grep tag_name | sed -E 's/.*"([^"]+)".*/\1/')"

    echo "Latest version: $LATEST_VERSION"
    echo "Current version: $CURRENT_VERSION"

    if [[ "$CURRENT_VERSION" != "$LATEST_VERSION" ]]; then
    else
        echo "You are using the latest version. ($CURRENT_VERSION)"
    fi
}

function update_all_files() {
    echo "Baixando a versão mais recente..."
    tmp_dir=$(mktemp -d)
    
    # Baixa e extrai o repositório inteiro
    curl -L "$ZIP_URL" -o "$tmp_dir/repo.zip"
    unzip -qo "$tmp_dir/repo.zip" -d "$tmp_dir"
    
    # Substitui todos os arquivos no diretório de instalação
    cp -r "$tmp_dir/repo-main/"* "$INSTALL_DIR/"
    
    chmod +x "$INSTALL_DIR/script.sh"
    rm -rf "$tmp_dir"
    echo "Atualização completa! Versão atual: $LATEST_VERSION"
}


# ---===---

# --- RUNTIME

if $DRY; then echo "--- DRY MODE IS ENABLED"; fi
if $VERBOSE; then echo "--- VERBOSE MODE IS ENABLED"; fi
if $LISTING; then firewalld_list_configuration; fi
if $ADD_TO_PATH; then add_script_to_path; fi

# 1. Disable fail2ban

# do a check: if debian, disable fail2ban (magnusbilling)
# if centos/rocky/anything else, keep it enabled (maybe?)
srun "sudo systemctl stop fail2ban"
srun "sudo systemctl disable fail2ban"

# 1.5. make sure our engine is working/running. this is already done in other parts of the script

# 2. Create/confirm zones
firewalld_do_zone_stuff

# 3. Create exceptions
echo "--- WHITELIST"
for ip in "${IPS_TO_ALLOW[@]}"; do
    firewalld_add_trusted "$ip"
done

# 4. Create drops
echo "--- PORT DROPS"
for port_type_force in "${PORTS_TO_DROP[@]}"; do
    _port=""
    _type=""
    _force=false

    IFS=":" read -r port_type _force <<< "${port_type_force}" # isolate force option
    IFS="/" read -r _port _type <<< "$port_type" # separate remainder as port and type
    if [[ "$_force" == "force" || "$_force" == "true" ]]; then _force=true; fi

    firewalld_drop_port "$_port" "$_type" "$_force"

    unset IFS
done

# 5. Reload to apply changes
echo "--- RELOADING FIREWALLD TO APPLY CHANGES ---"
firewalld_reload
