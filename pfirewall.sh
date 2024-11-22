#!/bin/bash

FULL_SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
CURRDIR="$(dirname "$FULL_SCRIPT_PATH")"
SCRIPT_NAME="$(basename "$FULL_SCRIPT_PATH")"

# Application infor
REPO_OWNER="phonevox"
REPO_NAME="pfirewall"
REPO_URL="https://github.com/$REPO_OWNER/$REPO_NAME"
ZIP_URL="$REPO_URL/archive/refs/heads/main.zip"
APP_VERSION="v0.3.1" # honestly, I dont know how to do this better

source $CURRDIR/lib/useful.sh
source $CURRDIR/lib/easyflags.sh

SYSTEM_OS=$(get_os)

# ---

add_flag "d" "dry" "Do NOT make changes to the system" bool
add_flag "v" "verbose" "Verbose mode" bool
add_flag "vv" "super-verbose" "Enter super verbose mode, and show all commands made" bool
add_flag "s" "" "IPs to whitelist on top of 'allow' file. Example: 0.0.0.0/0,192.168.1.1" str
add_flag "p" "" "Ports to drop on top of 'drops' file. Example: 20-23/tcp,5060,80/udp,80/tcp,443:force" str 
add_flag "l" "list" "List current firewall rules/configuration and exit" bool
add_flag "V" "version" "Show app version and exit" bool
add_flag "atp:HIDDEN" "install" "Add this script to the system path and exits" bool
add_flag "t:HIDDEN" "test" "DEBUGGING TOOL" bool # runs function run_test() and exits
add_flag "upd:HIDDEN" "update" "Update this script to the newest version" bool
add_flag "fu:HIDDEN" "force-update" "Force the update even if its in the same version" bool

#ignores
add_flag "idp:HIDDEN" "ignore-default-ports" "Do NOT use values from 'drops' file" bool
add_flag "ids:HIDDEN" "ignore-default-ips" "Do NOT use values from 'allow' file" bool
add_flag "idx:HIDDEN" "ignore-defaults" "Do NOT use values from 'allow' AND 'drops' file" bool
add_flag "ifs:HIDDEN" "ignore-failsafe" "Do NOT use the failsafe system" bool
add_flag "nf:HIDDEN" "no-flush" "Do NOT flush zones" bool

# to implement
add_flag "e" "engine" "Firewall engine to use. Defaults as firewalld (firewalld|iptables)" str # this is not implemented yet

set_description "This script aims to set the default firewall rules used by Phonevox, with their default IPs and ports, plus the possibility of adding extra IPs and ports."
parse_flags "$@"

# ---

# ignore this --> 🗸 🞩 ↺

# config-related
DRY=false # dont change my system (default: false)
VERBOSE=false # describe everything (default: false)
SILENT=true # dont echo-back commands (not even dry-ones) (default: true)
LISTING=false # list current rules and exit
ADD_TO_PATH=false # add this script to the system path and exit
UPDATE=false # update this script to the newest version
FORCE_UPDATE=false # force update even if its the same version
TEST_RUN=false
FLUSH_ZONES=true # flush all rules added from this script (default: true)

# zone-related
TRUST_ZONE_NAME="ptrusted"
DROP_ZONE_NAME="pdrop"
IGNORE_FAILSAFE=false # ignore ip failsafe when flushing
FAILSAFE_USER_IP=$(echo $SSH_CLIENT | awk '{print $1}') # ip of the user ssh session that ran the command
TRUST_FAILSAFE_IP=false # in a flush, should we trust the user's IP? (add it to the trusted list while script is in execution so we guarantee we dont get booted off mid-changes)

# engine-related
DEFAULT_ENGINE="firewalld"
if [[ "$SYSTEM_OS" =~ "rocky" || "$SYSTEM_OS" =~ "centos" ]]; then DEFAULT_ENGINE="iptables"; fi
ENGINE=$DEFAULT_ENGINE

# userinput-related
BUFFER_ADDED_IPS="" # user ips
BUFFER_ADDED_PORTS="" # user ports

DEFAULT_TRUSTED_IPS=()
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        if $VERBOSE; then echo "VERBOSE: DEFAULT_TRUSTED_IPS : stdin: $line"; fi
        DEFAULT_TRUSTED_IPS+=("$line")
    fi
done <<< "$(read_stdin "$CURRDIR/allow")" 2>&1

DEFAULT_DROP_PORTS=()
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        if $VERBOSE; then echo "VERBOSE: DEFAULT_DROP_PORTS : stdin: $line"; fi
        DEFAULT_DROP_PORTS+=("$line")
    fi
done <<< "$(read_stdin "$CURRDIR/drops")" 2>&1

FIREWALLD_IS_ENABLED=false
FIREWALLD_IS_RUNNING=false
if hasFlag "d"; then DRY=true; fi
if hasFlag "l"; then LISTING=true; fi
if hasFlag "v"; then VERBOSE=true; fi
if hasFlag "vv"; then VERBOSE=true; SILENT=false; fi
if hasFlag "t"; then TEST_RUN=true; fi
if hasFlag "e"; then ENGINE=$(getFlag "e"); fi
if hasFlag "fu"; then FORCE_UPDATE=true; fi
if hasFlag "nf"; then FLUSH_ZONES=false; fi
if hasFlag "upd"; then UPDATE=true; fi
if hasFlag "ifs"; then IGNORE_FAILSAFE=true; fi
if hasFlag "idp"; then DEFAULT_DROP_PORTS=(); fi
if hasFlag "ids"; then DEFAULT_TRUSTED_IPS=(); fi
if hasFlag "idx"; then DEFAULT_TRUSTED_IPS=(); DEFAULT_DROP_PORTS=(); fi
if hasFlag "atp"; then ADD_TO_PATH=true; fi
if hasFlag "V"; then echo "$APP_VERSION"; exit 0; fi

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
done <<< "$(read_stdin)" 2>&1 # i dont think this input redirect does shit LOL

# ---

# safe-run
function srun () {
    local COMMAND=$1
    local USER_ACCEPTABLE_EXIT_CODES=$2

    run "$COMMAND >/dev/null" "$USER_ACCEPTABLE_EXIT_CODES" "$DRY" "$SILENT"
}

# ==============================================================================================================
# IPTABLES STEPS

function iptables_engine() {
    if $LISTING; then iptables_list_configuration; fi #iptables -S

    # 1. Disable fail2ban (wont do)
    :

    # 1.5. Make sure our engine is working/running. (? what does that mean in iptables)
    # make a way to confirm the order of input chain?? confirm our exceptions are first, etc...

    # 2. Create and/or confirm zones (pdrop, ptrusted)
    echo "--- CHECKING ZONES, MIGHT TAKE A WHILE"
    iptables_do_zone_stuff

    # 3. Add the exceptions (allow ips)
    echo "--- WHITELIST"
    for ip in "${IPS_TO_ALLOW[@]}"; do
        iptables_add_trusted "$ip"
    done

    # 4. Add the drops (block ports)
    echo "--- PORT DROPS"
    for port_type_force in "${PORTS_TO_DROP[@]}"; do
        local _port=""
        local _type=""
        local _force=false

        IFS=":" read -r port_type _force <<< "${port_type_force}" # isolate force option
        IFS="/" read -r _port _type <<< "$port_type" # separate remainder as port and type
        if [[ "$_force" == "force" || "$_force" == "true" ]]; then _force=true; fi

        iptables_drop_port "$_port" "$_type" "$_force"

        unset IFS
    done

    # 5. Reload to apply (? not necessary in iptables?)
    echo "--- ALL DONE!"
}


function iptables_do_zone_stuff() {

    if $IGNORE_FAILSAFE; then
        echo "--- $(colorir vermelho "FAILSAFE IS DISABLED")"
        srun "iptables -F"
    elif $TRUST_FAILSAFE_IP; then
        # add this session's IP to INPUT, as rule #1
        if $VERBOSE; then echo "VERBOSE: As a failsafe measure, we will add this session's IP ($FAILSAFE_USER_IP) to trusted zone."; fi
        iptables_purge_input_keep_failsafe # iptables -F but preserve our FAILSAFE rule
    else 
        echo "Error: FAILSAFE: We cannot trust your session's IP address ($FAILSAFE_USER_IP). If you proceed, you might lose access to the system. Guarantee you won't loose access to the system. If this is wrong, run with --ignore-failsafe."
        exit 1
    fi

    if $FLUSH_ZONES; then
        iptables_purge_jail "$TRUST_ZONE_NAME" # delete exception zone
        iptables_purge_jail "$DROP_ZONE_NAME" # delete port block zone
    else
        echo "--- $(colorir vermelho "ZONE FLUSHING IS DISABLED")"
    fi

    iptables_guarantee_jail "$TRUST_ZONE_NAME"
    iptables_guarantee_jail "$DROP_ZONE_NAME"

    echo "--- SETTING JAIL ORDER ---"
    # I WILL ASSUME THAT RULE NUMBER #1 IS OUR FAILSAFE. MIGHT BE WRONG. MIGHT BE RIGHT. I DONT KNOW
    srun "iptables -I INPUT 2 -j $TRUST_ZONE_NAME"
    srun "iptables -I INPUT 3 -j F2B_INPUT"
    srun "iptables -I INPUT 4 -j $DROP_ZONE_NAME"
}


function iptables_purge_input_keep_failsafe() {
    local FAILSAFE=$FAILSAFE_USER_IP  # IP de failsafe

    if $VERBOSE; then echo "VERBOSE: PURGING INPUT CHAIN"; fi

    # adding the IP
    if ! iptables -C INPUT -s "$FAILSAFE" -j ACCEPT 2>/dev/null; then
        iptables_add_trusted "$FAILSAFE" INPUT 1
    fi

    # current rules on INPUT chain
    rules=$(iptables -S | grep "A INPUT")

    # echo "DEBUG: FAILSAFE IP: $FAILSAFE"
    # echo -e "DEBUG: RULES: \n$rules"

    while read -r line; do

        # get one of the rules
        rule_content=$(echo "$line" | sed 's/^[ \t]*//')

        # removes "-A INPUT" prefix (for eventual -D command)
        rule_to_delete=$(echo "$rule_content" | sed 's/^[-]A INPUT//')

        # checks if its not the failsafe ip
        if [[ "$rule_to_delete" != *"-s $FAILSAFE"* ]]; then

            # deletes the rule (this is why we had to prune off "-A INPUT")
            if $VERBOSE; then echo "VERBOSE: Deleting rule '$rule_content'"; fi
            srun "iptables -D INPUT $rule_to_delete"
        fi
    done <<< "$rules" # iterate over the rules we found

    if $VERBOSE; then echo "VERBOSE: FAILSAFE IP $FAILSAFE kept, and everything else in INPUT was purged."; fi
}


function iptables_purge_jail() {
    local jail=$1

    # arg validation
    if [[ -z "$jail" ]]; then
        echo "ERROR: No jail provided for flushing."
        exit 1
    fi

    # jail exists
    if iptables -L "$jail" &>/dev/null; then
        if $VERBOSE; then echo "VERBOSE: [ $jail ] Flushing"; fi
        srun "iptables -F \"$jail\""

        if $VERBOSE; then echo "VERBOSE: [ $jail ] Removing references"; fi
        
        # INPUT JAIL
        if iptables -C INPUT -j "$jail" &>/dev/null; then
            srun "iptables -D INPUT -j \"$jail\""
        fi

        # OUTPUT JAIL
        if iptables -C OUTPUT -j "$jail" &>/dev/null; then
            srun "iptables -D OUTPUT -j \"$jail\""
        fi

        # FORWARD JAIL
        if iptables -C FORWARD -j "$jail" &>/dev/null; then
            srun "iptables -D FORWARD -j \"$jail\""
        fi

        if $VERBOSE; then echo "VERBOSE: [ $jail ] Deleting jail"; fi
        srun "iptables -X \"$jail\""
    fi

}


function iptables_guarantee_jail() {
    local jail=$1

    # arg validation
    if [[ -z "$jail" ]]; then
        echo "ERROR: No jail provided to guarantee."
        exit 1
    fi

    # confirms jail exist
    if iptables -L "$jail" &>/dev/null; then
        if $VERBOSE; then echo "VERBOSE: [ $jail ] Jail exists"; fi
    else
        if $VERBOSE; then echo "VERBOSE: [ $jail ] Creating jail"; fi
        srun "iptables -N \"$jail\""
    fi
}


function iptables_add_trusted() {
    local ip=$1
    local chain=$TRUST_ZONE_NAME; if [[ -n "$2" ]]; then local chain=$2; fi
    local rule_num=$3

    # arg validation
    if [[ -z "$ip" ]]; then
        echo "ERROR: No IP provided for allowing."
        exit 1
    fi

    # adding to trusted chain, if its not added yet
    if ! valid_ip "$ip"; then
        local _text_color=vermelho
        local _text_message="[$(colorir $_text_color "✗")] $(colorir $_text_color "$chain : $ip") (bad address)"
    elif iptables -C "$chain" -s "$ip" -j ACCEPT 2>/dev/null; then
        local _text_color="cinza"
        local _text_message="[$(colorir $_text_color "●")] $(colorir $_text_color "$chain : $ip") (already trusted)"
    else
        if [[ "$BUFFER_ADDED_IPS" =~ (^| )$ip( |$) ]]; then
            local _text_color="cinza"
            local _text_message="[$(colorir $_text_color "●")] $(colorir $_text_color "$chain : $ip") (previously added)"
        else
            srun "iptables -I $chain $rule_num -s $ip -j ACCEPT"
            local _text_color="verde"
            local _text_message="[$(colorir $_text_color "🗸")] $(colorir $_text_color "$chain : $ip")"
            BUFFER_ADDED_IPS="$BUFFER_ADDED_IPS $ip"
        fi
    fi

    echo "$_text_message"
}


function iptables_drop_port() {
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
        iptables_drop_port "$port" tcp $force
        if $VERBOSE; then echo "VERBOSE: Starting drop for $port/udp. FORCE:$force"; fi
        iptables_drop_port "$port" udp $force
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
            iptables_drop_port "$i" "$type" $force
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

    # CHORE(adrian): confirm iptables "is running"

    # CHORE(adrian): there is no "port is already open / port is already closed" verification. you straight up close it.
    # search if theres a way to do this better?

    srun "iptables -A $zone -p $type --destination-port $port -j DROP"
    local _text_color=verde
    local _text_message="[$(colorir $_text_color "🗸")] $(colorir $_text_color "$zone : $port/$type")"

    echo  "$_text_message"
    return 0
}


function iptables_list_configuration() {
    srun "iptables -S"
    exit 0
}

# ==============================================================================================================
# FIREWALLD STEPS

# everything needed to make the script work considering the firewalld engine
function firewalld_engine() {
    if $LISTING; then firewalld_list_configuration; fi

    # 1. Disable fail2ban
    srun "sudo systemctl stop fail2ban"
    srun "sudo systemctl disable fail2ban"

    # 1.5. make sure our engine is working/running. this is already done in other parts of the script

    # 2. Create/confirm zones
    echo "--- CHECKING ZONES, MIGHT TAKE A WHILE"
    firewalld_do_zone_stuff

    # 3. Create exceptions
    echo "--- WHITELIST"
    for ip in "${IPS_TO_ALLOW[@]}"; do
        firewalld_add_trusted "$ip"
    done

    # 4. Create drops
    echo "--- PORT DROPS"
    for port_type_force in "${PORTS_TO_DROP[@]}"; do
        local _port=""
        local _type=""
        local _force=false

        IFS=":" read -r port_type _force <<< "${port_type_force}" # isolate force option
        IFS="/" read -r _port _type <<< "$port_type" # separate remainder as port and type
        if [[ "$_force" == "force" || "$_force" == "true" ]]; then _force=true; fi

        firewalld_drop_port "$_port" "$_type" "$_force"

        unset IFS
    done

    # 5. Reload to apply changes
    echo "--- RELOADING FIREWALLD TO APPLY CHANGES ---"
    firewalld_reload

    echo "--- ALL DONE!"
}


# stops application if firewalld is not running
# sets FIREWALLD_IS_RUNNING and FIREWALLD_IS_ENABLED
# so you dont need to system call again (singleton-style)
function firewalld_check_status() {
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
function firewalld_guarantee_zone() {
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
function firewalld_flush_zone() {
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
function firewalld_add_trusted() {
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
function firewalld_do_zone_stuff() {

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
    firewalld_guarantee_zone "$DROP_ZONE_NAME" "ACCEPT"
    firewalld_reload # apply creation
}


# drops a port in the firewalld
# if already dropped, does nothing
# checks if firewalld is running first, fails if not
# can force-drop a port, even if not in use, passing $3=true
# Usage: firewalld_drop_port "port:integer/range" "protocol:tcp/udp..." "force:true/false"
# i.e. firewalld_drop_port "80" "tcp" "true"
# i.e. firewalld_drop_port "20-23" "tcp" ""
function firewalld_drop_port() {
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
    firewall-cmd --zone=$zone --list-rich-rules | grep -qi "$port.*$type.*reject$" && _port_is_open=false || _port_is_open=true

    # if $VERBOSE; then echo "VERBOSE: Port $port/$type open? $_port_is_open"; fi

    if ! $_port_is_open; then
        # port is not open: its already dropped or not added yet
        if [[ "$force" == "true" ]]; then 
            # @NOTE(adrian): this does not make sense: the rich rule already exists, theres no need to "force" it again. oh well.
            srun "firewall-cmd --zone=$zone --add-rich-rule='rule family=\"ipv4\" port port=\"$port\" protocol=\"$type\" reject' --permanent"
            local _text_color=verde_lima
            local _text_message="[$(colorir $_text_color "🗸")] $(colorir $_text_color "$zone : $port/$type") (forced)"
        else
            local _text_color=cinza
            local _text_message="[$(colorir $_text_color "●")] $(colorir $_text_color "$zone : $port/$type") (not open)"
        fi
    else
        srun "firewall-cmd --zone=$zone --add-rich-rule='rule family=\"ipv4\" port port=\"$port\" protocol=\"$type\" reject' --permanent"
        local _text_color=verde
        local _text_message="[$(colorir $_text_color "🗸")] $(colorir $_text_color "$zone : $port/$type")"
    fi

    echo  "$_text_message"
    return 0
}


# list the current firewalld configuration, and informations about this script
# Usage: firewalld_list_configuration
function firewalld_list_configuration() {

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

    echo "=~= $(colorir "verde" "CURRENT $TRUST_ZONE_NAME ZONE (allow, if invalid then it doesnt exist)") =~="
    firewall-cmd --zone=$TRUST_ZONE_NAME --list-all | egrep "target|sources"
    # firewall-cmd --zone=$TRUST_ZONE_NAME --list-sources egrep "target|sources|ports"
    # firewall-cmd --permanent --zone=$TRUST_ZONE_NAME --get-target

    echo "=~= $(colorir "vermelho" "CURRENT $DROP_ZONE_NAME ZONE (port drop, if invalid then it doesnt exist)") =~="
    firewall-cmd --zone=$DROP_ZONE_NAME --list-all | egrep "target| ports|rule "
    # firewall-cmd --zone=$DROP_ZONE_NAME --list-ports | egrep "target|sources|ports"
    # firewall-cmd --permanent --zone=$DROP_ZONE_NAME --get-target
    exit 0
}


# literally just a reload
# Usage: firewalld_reload
function firewalld_reload() {
    srun "firewall-cmd --reload"
}


# ==============================================================================================================
# SCRIPT MANAGEMENT, BINARY

# add to system path
# THIS IS HEAVY TO-DO
# Usage: add_script_to_path 
function add_script_to_path() {
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

# ==============================================================================================================
# VERSION CONTROL, UPDATES

function check_for_updates() {
    local CURRENT_VERSION=$APP_VERSION
    local LATEST_VERSION="$(curl -s https://api.github.com/repos/phonevox/pfirewall/tags | grep '"name":' | head -n 1 | sed 's/.*"name": "\(.*\)",/\1/')"

    echo "Latest source version: $LATEST_VERSION"
    echo "Current local version: $CURRENT_VERSION"

    # its the same version
    if ! version_is_greater "$LATEST_VERSION" "$CURRENT_VERSION"; then
        echo "$(colorir verde "You are using the latest version. ($CURRENT_VERSION)")"
        if ! $FORCE_UPDATE; then exit 1; fi
    else
        echo "You are not using the latest version. (CURRENT: '$CURRENT_VERSION', LATEST: '$LATEST_VERSION')"
    fi

    echo "Do you want to download the latest version from source? ($(colorir azul "$CURRENT_VERSION") -> $(colorir azul "$LATEST_VERSION")) ($(colorir verde y)/$(colorir vermelho n))"
    read -r _answer 
    if ! [[ "$_answer" == "y" ]]; then
        echo "Exiting..."
        exit 1
    fi
    update_all_files
    exit 0
}

# needs curl, unzip
function update_all_files() {
    local INSTALL_DIR=$CURRDIR
    local REPO_NAME=$REPO_NAME
    local ZIP_URL=$ZIP_URL

    echo "- Creating temp dir"
    tmp_dir=$(mktemp -d) # NOTE(adrian): this is not dry-able. dry will actually make change in the system just as this tmp folder.
    
    echo "- Downloading repository zip to '$tmp_dir/repo.zip'"
    srun "curl -L \"$ZIP_URL\" -o \"$tmp_dir/repo.zip\""

    echo "- Unzipping '$tmp_dir/repo.zip' to '$tmp_dir'"
    srun "unzip -qo \"$tmp_dir/repo.zip\" -d \"$tmp_dir\""

    echo "- Copying files from '$tmp_dir/$REPO_NAME-main' to '$INSTALL_DIR'"
    srun "cp -r \"$tmp_dir/$REPO_NAME-main/\"* \"$INSTALL_DIR/\""
    
    echo "- Updating permissions on '$INSTALL_DIR'"
    srun "find \"$INSTALL_DIR\" -type f -name \"*.sh\" -exec chmod +x {} \;"

    # cleaning
    echo "- Cleaning up"
    srun "rm -rf \"$tmp_dir\""
    echo "--- UPDATE FINISHED ---"
}


function version_is_greater() {
    # ignore metadata
    ver1=$(echo "$1" | grep -oE '^[vV]?[0-9]+\.[0-9]+\.[0-9]+')
    ver2=$(echo "$2" | grep -oE '^[vV]?[0-9]+\.[0-9]+\.[0-9]+')
    
    # remove "v" prefix
    ver1="${ver1#v}"
    ver2="${ver2#v}"

    # gets major, minor and patch
    IFS='.' read -r major1 minor1 patch1 <<< "$ver1"
    IFS='.' read -r major2 minor2 patch2 <<< "$ver2"

    # compares major, then minor, then patch
    if (( major1 > major2 )); then
        return 0
    elif (( major1 < major2 )); then
        return 1
    elif (( minor1 > minor2 )); then
        return 0
    elif (( minor1 < minor2 )); then
        return 1
    elif (( patch1 > patch2 )); then
        return 0
    else
        return 1
    fi
}

# ==============================================================================================================
# RUNTIME

function run_test() {
    echo "${DEFAULT_TRUSTED_IPS[@]}"
    echo "${DEFAULT_DROP_PORTS[@]}"
    exit 0
}

function main() {
    if $TEST_RUN; then run_test; fi
    if $UPDATE; then check_for_updates; fi
    if $DRY; then echo "--- DRY MODE IS ENABLED"; fi
    if $VERBOSE; then echo "--- VERBOSE MODE IS ENABLED"; fi
    if $ADD_TO_PATH; then add_script_to_path; fi

    if [ "$ENGINE" == "firewalld" ]; then
        firewalld_engine
    elif [ "$ENGINE" == "iptables" ]; then
        iptables_engine
    else
        echo "ERROR: Unknown engine: $ENGINE"
        exit 1
    fi
}

main
