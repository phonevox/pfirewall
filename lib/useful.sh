#!/bin/bash

# --- useful constants
declare -A COLORS_ARRAY
COLORS_ARRAY=(
    # Cores básicas
    [preto]="0;30"
    [vermelho]="0;31"
    [verde]="0;32"
    [amarelo]="0;33"
    [azul]="0;34"
    [magenta]="0;35"
    [ciano]="0;36"
    [branco]="0;37"

    # Cores claras
    [preto_claro]="1;30"
    [vermelho_claro]="1;31"
    [verde_claro]="1;32"
    [amarelo_claro]="1;33"
    [azul_claro]="1;34"
    [magenta_claro]="1;35"
    [ciano_claro]="1;36"
    [branco_claro]="1;37"

    # Cores 256 (adicionais)
    [laranja]="38;5;208"
    [rosa]="38;5;206"
    [azul_celeste]="38;5;45"
    [verde_lima]="38;5;118"
    [lavanda]="38;5;183"
    [violeta]="38;5;135"
    [caramelo]="38;5;130"
    [dourado]="38;5;220"
    [turquesa]="38;5;51"
    [cinza]="38;5;244"
    [cinza_claro]="38;5;250"
    [marrom]="38;5;94"
)
# --- useful functions

# returns the current operational system
# call in subshell and store the echo'ed value in a variable
# returns "ID"+"VERSION_ID" from /etc/os-release
# Usage: OS=$(get_os)
function get_os() {
    echo "$(echo $(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"') $(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release | tr -d '"') | tr '[:upper:]' '[:lower:]')"
}

# color your text using subshells
# this needs the COLORS_ARRAY array, declared outside this function
# Usage: echo "esse texto está sem cor, mas $(colorir "verde" "esse texto aqui está com cor") "
function colorir() {
    local cor=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    local texto=$2
    local string='${COLORS_ARRAY['"\"$cor\""']}'
    eval "local cor_ansi=$string" >/dev/null 2>&1
    local cor_reset="\e[0m"

    if [[ -z "$cor_ansi" ]]; then
        cor_ansi=${COLORS_ARRAY["branco"]}  # defaults to white if invalid
    fi

    # print with selected color
    echo -e "\e[${cor_ansi}m${texto}${cor_reset}"
}


# echo-back the first argument in every possible color
# so you can search for a cool color you want to use
# Usage: colortest "batata frita"
function colortest() {
    local ORDER=(
        # tons neutros
        "preto"
        "preto_claro"
        "cinza"
        "cinza_claro"
        "branco"
        "branco_claro"
        
        # tons de verde
        # "\n"
        "verde"
        "verde_claro"
        "verde_lima"
        
        # tons azuis
        # "\n"
        "azul"
        "azul_claro"
        "azul_celeste"
        "turquesa"

        # proibido
        "ciano"
        "ciano_claro"
        
        # tons amarelados
        # "\n"
        "amarelo"
        "amarelo_claro"
        "laranja"
        "caramelo"
        
        # tons vermelhos
        # "\n"
        "vermelho"
        "vermelho_claro"
        
        # tons rosa/roxos
        # "\n"
        "magenta"
        "magenta_claro"
        "violeta"
        "rosa"
        "lavanda"
    )
    local texto=$1
    local cor_reset="\e[0m"
    echo "inside colortest"

    # Loop para aplicar todas as cores do array "COLORS_ARRAY" ao texto
    for cor in "${ORDER[@]}"; do
        if [[ "$cor" == "\\n" ]]; then
            echo ""
            continue
        fi
        local cor_ansi="${COLORS_ARRAY[$cor]}"
        echo -e "\e[${cor_ansi}m${texto} (${cor})${cor_reset}"
    done
}


# Executes commands on system, in a secure way.
# This demands "colorir" function for aesthetics.
#
# Default allowed exit codes: "0,1"
# Default dry mode: "false"
#
# Usage: run "<full command escaped>" "<acceptable exit codes separated by comma>" "<dry:true/false>"
# run "asterisk -rx \"sip show peers\"" "0,1,2" "false"
function run() {
    local CODE_FAILED_COLOR="vermelho" # exit code diferente de 0 e não está nos aceitaveis
    local CODE_ACCEPTABLE_COLOR="amarelo" # exit code diferente de 0 mas está nos aceitáveis
    local CODE_SCUCESS_COLOR="verde" # exit code === 0
    local DRY_COLOR="azul"

    local COMMAND=$1
    local USER_ACCEPTABLE_EXIT_CODES=$2
    local RUN_DRY=false # default false
    if [[ "$3" == "true" ]]; then local RUN_DRY=true; fi
    local RUN_SILENT=false
    if [[ "$4" == "true" ]]; then local RUN_SILENT=true; fi

    # transforming exit codes into array
    local ACCEPTABLE_EXIT_CODES=1
    if [ $USER_ACCEPTABLE_EXIT_CODES ]; then ACCEPTABLE_EXIT_CODES=$ACCEPTABLE_EXIT_CODES,$USER_ACCEPTABLE_EXIT_CODES; fi
    {
        local IFS=',' # split with comma
        read -r -a acceptable_codes_array <<< "$ACCEPTABLE_EXIT_CODES" # add to array
    }

    # echo ""
    # echo -e "TEST: acceptable_codes_array : ${acceptable_codes_array[@]}"
    # echo -e "TEST: ACCEPTABLE EXIT CODES: $ACCEPTABLE_EXIT_CODES"
    # echo -e "TEST: USER EXIT CODES: $USER_ACCEPTABLE_EXIT_CODES"

    # if its dry, just exit with a "fake" command message
    # CHORE(adrian): could move this up maybe?
    if [[ "$RUN_DRY" == "true" ]]; then
        if ! $RUN_SILENT; then
            echo -e ">> DRY: $(colorir "$DRY_COLOR" "[$(echo -n $COMMAND)]")"
        fi
        return
    fi

    # actually run the command
    eval "$COMMAND"
    local EXIT_CODE=$?

    # Exit code SUCCESS
    if [ $EXIT_CODE -eq 0 ]; then
        if ! $RUN_SILENT; then
            echo -e "> command:[$(colorir "$CODE_SCUCESS_COLOR" "$COMMAND")], exit_code:$(colorir "$CODE_SCUCESS_COLOR" "$EXIT_CODE")"
        fi
        return 0
    fi

    # Exit code ACCEPTABLE
    for code in "${acceptable_codes_array[@]}"; do
        if [ $EXIT_CODE -eq $code ]; then
            if ! $RUN_SILENT; then
                echo -e "> command:[$(colorir "$CODE_ACCEPTABLE_COLOR" "$COMMAND")], exit_code:$(colorir "$CODE_ACCEPTABLE_COLOR" "$EXIT_CODE")"
            fi
            return
        fi
    done

    # Exit code FAIL
    echo -e "> command:[$(colorir "$CODE_FAILED_COLOR" "$COMMAND")], exit_code:$(colorir "$CODE_FAILED_COLOR+" "$EXIT_CODE")"
    echo -e "O exit-code do comando [$COMMAND] foi diferente de 0. Encerrando o SCRIPT por segurança!"
    exit 1
}


# echo and logs to a file
# file must be configured previously
# Usage: log "<message>"
function log() {
    local MENSAGEM=$1
    local LOG_DESTINATION="${settings[LOG_PATH]}/-$(date +%Y%m%d).log"
    local LOG_TIMESTAMP="$(date +%Y/%m/%d\ %H:%M:%S.%N)"

    echo -e "[$LOG_TIMESTAMP] $1" | tee -a $LOG_DESTINATION
}


# this is dark magic, i wont even try to explain
# in short it will make the script gets values from redirects
# Usage: STDIN=$(read_stdin)
# STDIN=$(read_stdin) 
# FILE=$(read_stdin "file.txt")
# on script call: ./script.sh < some_file.txt
# then, you can iterate over the STDIN variable to get every line of your input file
function read_stdin () {
    # 0: ignores last line (default bash behaviour)
    # 1: forces a trailing newline so that the last line is not ignored
    local FORCE_NEWLINE=1
    local IGNORE_EMPTY_INPUT=1

    # determine what we will read from: stdin or file
    local input_file="$1"
    local input_cmd="cat" # default cmd

    if [[ -n "$input_file" ]]; then
        if [[ -f "$input_file" ]]; then
            input_cmd="cat \"$input_file\""
        elif [[ "$IGNORE_EMPTY_INPUT" -eq 1 ]]; then
            return 0 # the file doesnt exist
        else
            echo -e "ERROR: read_stdin: File '$input_file' does not exist." >&2
            return 1
        fi
    elif [[ -t 0 ]]; then
        if [[ "$IGNORE_EMPTY_INPUT" -eq 1 ]]; then
            return 0 # no input to read
        else
            echo "ERROR: read_stdin: No input to read." >&2
            return 1
        fi
    fi

    # append newline if needed
    if [[ "$FORCE_NEWLINE" -eq 1 ]]; then
        input_cmd="($input_cmd; printf '\n')"
    fi

    # reads the eval result, that, in turn, cats the stdin
    # (check end of while loop)
    while read -r line; do
        i=$(($i+1))

        # remove comments
        if [[ -n "$line" && ${line:0:1} == "#" ]]; then continue; fi

        # remove inline comments (ignore if escaped)
        line=$(echo "$line" | sed -E 's/([^\\])#.*$/\1/' | sed 's/[[:space:]]*$//')

        # preserves escaped comments ("\#" to "#")
        line=$(echo "$line" | sed 's/\\#/#/g')

        echo $line
    done < <(eval $input_cmd)

    return 0
}


# validates if a string is a valid ipv4 address
# Usage: valid_ip "<ip_address>"
# CONFIG_ALLOW_CIDR to allow IPV4 with CIDR notations (consider them valid IPs)
function valid_ip() {
    CONFIG_ALLOW_CIDR=1
    local value=$1

    # defining the regex rule
    if [[ $CONFIG_ALLOW_CIDR -eq 1 ]]; then 
        # NOTE: this cidr allows from 0 to 32 (because you might want to use 0.0.0.0/0)
        local REGEX="^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))?$"
    else
        local REGEX="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    fi

    if [[ $value =~ $REGEX ]]; then
        return 0
    else
        return 1
    fi
}


# this is meant to be used as subshell command
# Usage: IP=$(get_session_ip)
function get_session_ip() {
    local DEBUG_MODE=0; if [[ -n "$1" ]]; then DEBUG_MODE=1; fi 
    local DEBUG_TEXT=""    
    local SESSION_IP=""
    local RETURN=""

    # from ssh client
    local FROM_SSHCLIENT=$(echo $SSH_CLIENT | awk '{print $1}')
    if [[ -n "$FROM_SSHCLIENT" ]]; then SESSION_IP=$FROM_SSHCLIENT; fi

    # from "who" cmd
    local FROM_WHO=$(who -m | awk '{print $NF}' | tr -d '()')
    if [[ -n "$FROM_WHO" ]]; then SESSION_IP=$FROM_WHO; fi

    # validating
    if valid_ip "$SESSION_IP"; then RETURN=$SESSION_IP; fi

    # debug information if needed
    local DEBUG_TEXT=" (DEBUG INFO // FROM_SSHCLIENT=$FROM_SSHCLIENT, FROM_WHO=$FROM_WHO, SESSION_IP=$SESSION_IP)"

    if [[ "$DEBUG_MODE" -eq 1 ]]; then RETURN="$RETURN$DEBUG_TEXT"; fi
    echo $RETURN
}
