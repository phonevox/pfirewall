#!/bin/bash

# HOW TO USE
# First, source this file in your script
# : be mindful that this will automatically add an "h/help" and c/check
# then, call add_flag "short" "long" "description" "type"
# : short is the single-dashed (-), single-letter part of the flag
# : : ADVANCED: you can remove the short flag from display on help by suffixing it with ":HIDDEN"
# : : you can still use the short flag, the short version simply wont be displayed on help
# : : also you need to use the short flag name to refer to it in your script
# : : example: add_flag "d:HIDDEN" "dry" "Executes in dry-mode" "boolean" will add the --dry on help, but hide -d.
# : : to reference it on your script, you still need to use the short without suffix, i.e hasFlag "d"
# : : Existing suffixes: 
# : : : ":HIDDEN" hide from help. wont work if you dont pass in a long flag too
# : : : ":BLOCK" block the flag from being used (if called, will throw error) (THIS IS NOT IMPLEMENTED YET!!!!)
# : long is the double-dashed (--), multi character part of the flag
# : description is the flag's description, what it does
# : type is the flag's type, what it is. it is optional (defaults boolean) and can be one of:
# :  : boolean > does not take arguments, only exists or not
# :  : string > takes a string argument
# :  : integer > takes an integer argument
# :  : float > takes a float argument (treat the same as string)
# :  : ip:loosely > accepts ip addresses or domain names
# :  : ip:forced > accepts ip addresses only
# :  : mail > accepts email addresses
# :  : : check (validate_flag_value) for more flag types
# : i.e: add_flag "d" "dry" "Executes in dry-mode" "boolean"
# then, call parse_flags "$@"
# : this will read all the script's arguments and parse them for expected flags, values and types

# Arrays para armazenar as flags
declare -A FLAGS
declare -A FLAG_VALUES
declare -A FLAG_TYPES
declare -A FLAG_DESCRIPTIONS
declare -A SPECIAL_FLAGS
declare -A FLAG_HIDDEN

FLAG_DEBUG=false

# flag debug message: only log on flag debug enabled
FDmsg() {
    local msg=$1
    if [[ "$FLAG_DEBUG" == true ]]; then
        echo "FLAG_DEBUG: $msg"
    fi
}

# adiciona uma flag nova
# Uso: add_flag "short" "long" "description"
# add_flag "d" "dry" "Execute application in dry-mode."
# : short = nome curto da flag, caractere único. usado com single-dash (-d, -f etc...) obrigatório
# : long = nome longo da flag, multiplos caracteres. usado com double-dash (--dry, --full etc...). opcional (default "")
# : description = descrição da flag, o que ela faz. opcional (default "")
add_flag() {
    local DEFAULT_NO_DESCRIPTION="No description"
    local DEFAULT_NO_TYPE="boolean"
    local short_flag=$1
    local long_flag=$2
    local description=${3:-$DEFAULT_NO_DESCRIPTION}
    local type=${4:-$DEFAULT_NO_TYPE}
    local hidden_flag=false


    # arg validation
    if [[ -z "$short_flag" ]]; then
        echo "Error: Short flag cannot be empty."
        exit 1
    fi

    # checking if its a hidden flag
    if [[ "$short_flag" == *":HIDDEN" ]]; then
        FDmsg "Flag  '$short_flag' is hidden."
        short_flag="${short_flag%%:HIDDEN}"
        FLAG_HIDDEN["-$short_flag"]=true

        # arg validation for hidden shorts
        if [[ -z "$long_flag" ]]; then
            echo "Error: Hidden flag '-$short_flag' requires a long flag."
            exit 1
        fi
    fi

    # standardizing the flag type
    case "$type" in
        flt|float|str|string) # yes i will treat float as strings, fuck you
            type="string"
            ;;
        bool|boolean)
            type="bool"
            ;;
        int|integer)
            type="int"
            ;;
        address|ip/domain|ip:loosely|ip:leaky)
            type="ip/domain"
            ;;
        ip|ip:forced)
            type="ip"
            ;;
        mail|email)
            type="mail"
            ;;
        *)
            echo "Error: Unknown flag type for $flag."
            return 1
            ;;
    esac

    FDmsg "add_flag :: Short: $short_flag | Long: $long_flag | Type: $type"

    # short flag validation
    if [[ -n "${FLAGS["-$short_flag"]}" ]]; then
        echo "Error: Flag -$short_flag already exists."
        exit 1
    fi

    # long flag validation
    if [[ -n "$long_flag" ]]; then
        for existing_short in "${!FLAGS[@]}"; do
            if [[ "${FLAGS[$existing_short]}" == "$long_flag" ]]; then
                echo "Error: Flag --$long_flag already exists."
                exit 1
            fi
        done
    else
        FDmsg "add_flag :: Long flag is empty, skipping duplicate verification."
    fi

    FLAGS["-$short_flag"]=$long_flag
    # FLAGS["--$long_flag"]=$short_flag
    FLAG_VALUES["-$short_flag"]=""
    FLAG_TYPES["-$short_flag"]="$type"
    FLAG_DESCRIPTIONS["-$short_flag"]="$description"
}


# valida o tipo de uma flag
validate_flag_value() {
    local flag=$1
    local value=$2
    local type=${FLAG_TYPES["$flag"]}

    FDmsg ": validate_flag_value :: f($flag) | v($value) | t($type)"

    case "$type" in
        string) # yes i will treat float as strings, fuck you
            if [[ -z "$value" ]]; then
                echo "Error: Flag $flag must have a text value (string)."
                return 1
            fi
            ;;
        bool)
            if [[ -n "$value" && "$value" != "true" && "$value" != "false" ]]; then
                echo "Error: Flag $flag is boolean and can't receive any argument."
                if [[ "$value" =~ idiot ]]; then
                    echo "Warng : Remove '$flag' to treat as false; Add '$flag' to treat as true. Boolean-like strings won't work either."
                fi
                return 1
            fi
            ;;
        int)
            if ! [[ "$value" =~ ^-?[0-9]+$ ]]; then
                echo "Error: Flag $flag must have an integer value."
                return 1
            fi
            ;;
        ip/domain)
            if ! [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^[a-zA-Z0-9.-]+$ ]]; then
                echo "Error: Flag $flag must have a valid domain or IP address."
                return 1
            fi
            ;;
        ip)
            if ! [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "Error: Flag $flag must have a valid IP address. No domains allowed."
                return 1
            fi
            ;;
        mail)
            if ! [[ "$value" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                echo "Error: Flag $flag must have a valid email address."
                return 1
            fi
            ;;
        *)
            # this should never happen because type-checking is ran at add_flag level.
            # but just in case... right?
            echo "Error: Unknown flag type for $flag."
            return 1
            ;;
    esac
    return 0
}


# seta uma descrição do app, para ser utilizado no print_usage()
# não é obrigatório de se utilizar para a aplicação funcionar!
# Uso: set_description "Um app qualquer." 
set_description() {
    _USAGE_DESCRIPTION="$1"
}


# exibir o modo de uso do script. dinamicamente atualiza baseado nas flags adicionadas
# Uso: -- não é pra ser chamado manualmente; automaticamente chamado pelo parse_flags na flag -h
print_usage() {
    echo "Usage:"
    echo "  $(basename "$0") [flags]"

    if  [[ -n "$_USAGE_DESCRIPTION" ]]; then
    echo ""
    echo "Description:"
    echo "  $_USAGE_DESCRIPTION"
    fi
    echo ""
    echo "Flags:"

    # calc column max length (short + long + type) to align description
    local max_length=0
    local BOOLEAN="bool"
    declare -A _FLAG_DISPLAY_TEMP


    # CALCULATING THE LENGTH
    for short_flag in "${!FLAGS[@]}"; do
        local long_flag=${FLAGS[$short_flag]}
        local type=${FLAG_TYPES[$short_flag]}
        local is_hidden=$([[ "${FLAG_HIDDEN[$short_flag]}" == true ]] && echo true || echo false)
        
        if ! [[ "$is_hidden" == true ]]; then
            local flag_display="  $short_flag"
        fi

        if [[ -n "$long_flag" ]]; then
            if [[ "$is_hidden" == true ]]; then
                local flag_display="  --$long_flag"
            else
                local flag_display="$flag_display, --$long_flag"
            fi
        fi
        
        # adds type to display only if not boolean
        if [[ "$type" != "$BOOLEAN" ]]; then
            local flag_display="$flag_display $type"
        fi
        
        # updates max length if necessary
        if (( ${#flag_display} > max_length )); then
            max_length=${#flag_display}
        fi

        _FLAG_DISPLAY_TEMP["$short_flag"]="$flag_display"
    done

    # BUILDING THE ACTUAL DISPLAY, AND MAKING IT ALIGNED
    for short_flag in "${!FLAGS[@]}"; do
        # Retrieves pre-formatted display from _FLAG_DISPLAY_TEMP
        local flag_display="${_FLAG_DISPLAY_TEMP[$short_flag]}"
        local description="${FLAG_DESCRIPTIONS["$short_flag"]}"

        # Uses printf to align the description
        printf "%-${max_length}s  %s\n" "$flag_display" "$description"
    done
}


# processar todos os argumentos e buscar flags existentes.
# Uso: parse_flags "$@"
parse_flags() {
    FDmsg " --- Flag parsing... --- "
    
    # special cases
    local help_flag=false
    local check_flag=false
    local last_added_flag=false
    
    while [[ "$#" -gt 0 ]]; do
        local arg="$1"

        FDmsg "Parsing: $arg"

        # # specifically help flag
        # if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
        #     help_flag=true
        #     last_added_flag="-h"
        #     flag="-h"

        # # specifically check flag
        # elif [[ "$arg" == "-c" || "$arg" == "--check" ]]; then
        #     check_flag=true
        #     last_added_flag="-c"
        #     flag="-c"

        # we got some text that starts with "-", so it must be a short or long flag (-* picks either -b and --baa).
        if [[ "$arg" == -* ]]; then
            flag=$arg

            # special flags that should be ran after everything finishes
            if [[ "$flag" == "-c" || "$flag" == "--check" ]]; then
                check_flag=true
            elif [[ "$flag" == "-h" || "$flag" == "--help" ]]; then
                help_flag=true
            fi

            # long flag validation
            for existing_short in "${!FLAGS[@]}"; do
                if [[ "${FLAGS[$existing_short]}" == "${flag#--}" ]]; then
                    flag=$existing_short
                    FDmsg ": long found, actual flag: $flag"
                fi
            done

            # check if that flag exists
            if [[ -n "${FLAGS[$flag]+_}" ]]; then
                FDmsg ": found"
                # found flag in list, for now lets just set it to true because its present
                # we will check if it should have a proper value later on
                FLAG_VALUES["$flag"]="true"
            else

                if [[ "$flag" == -* && ${#flag} -gt 2 ]]; then

                    FDmsg "Sorry! Can't get myself to do a decent implementation of multi-flag parsing. Please use individual flags."
                    echo "Error: Flag $flag >>> Multi-flag is not allowed as of now. Please use individual flags."
                    print_usage
                    exit 1


                    # FDmsg ": could be a multiflag: $flag"

                    # for (( i=1; i<${#flag}; i++ )); do
                    #     local single_flag="-${flag:i:1}"
                    #     local single_flag_type="${FLAG_TYPES[$single_flag]}"

                    #     # is not a valid flag
                    #     if [[ -z "${FLAGS[$single_flag]+_}" ]]; then
                    #         echo "Error: Multi-flag error: Flag $single_flag is not a valid flag."
                    #         print_usage
                    #         exit 1
                    #     fi

                    #     # not a boolean
                    #     if [[ -z "$single_flag_type" || "$single_flag_type" != "bool" ]]; then
                    #         echo "Error: Multi-flag error: Invalid flag $single_flag. Only boolean flags are allowed after the first flag in a multi-flag."
                    #         print_usage
                    #         exit 1
                    #     fi
                    # done
                    # # all flags from the multiflag passed without error
                    # SKIP_VALIDATION=true

                else
                    # flag is not listed on our flags list, cant proceed
                    echo "Error: Unknown flag $flag"
                    print_usage
                    exit 1
                fi

            fi
            
            # now lets see if theres a next argument after this flag (something that does not starts with - or --"
            if [[ "$#" -gt 1 && ! "${FLAGS[$2]+_}" && "$2" != -* && "$SKIP_VALIDATION" != true ]]; then
                FLAG_VALUES["$flag"]="$2"  # apparently this flag has some argument, so lets set it to that flag here
                FDmsg ": has argument: $2"
                if [[ "${FLAG_TYPES["$flag"]}" == "bool" ]]; then FLAG_VALUES["$flag"]="dont send for bools, idiot"; fi

                shift  # prepare pointer for next flag
                # PS: this will actually select the argument as pointer
                # but the shift outside this loop will move the pointer 
                # again, to  the next flag
            fi

        else

            # if we got here, it means that the argument is not a flag
            # either we throw error and say to use quotes, or accept and append to last flag
            # echo "Error: For multi-word value, use quotes."
            # print_usage
            # exit 1

            flag=$last_added_flag
            local value=${FLAG_VALUES["$flag"]}
            local new_value="$value $arg"
            FDmsg ": probably a value for the last flag. ($flag)"

            if [[ -n "$flag" ]]; then
                FLAG_VALUES["$flag"]="$new_value" # update value
            else
                echo "Error: Value sent but no corresponding flag."
                print_usage
                exit 1
            fi
        fi

        # check if should skip validation
        if [[ "$SKIP_VALIDATION" != true ]]; then
            FDmsg ": sending to validation with: ${FLAG_VALUES["$flag"]}"
            if ! validate_flag_value "$flag" "${FLAG_VALUES["$flag"]#false}"; then # if its false, ignore the false part
                echo "Error: Invalid value for flag $flag."
                exit 1
            fi
            last_added_flag="$flag"
        else
            FDmsg ": skipping validation (probably a multiflag)"
            SKIP_VALIDATION=false # reset for next iteration
        fi
        FDmsg ": valid flag"

        shift
    done

    # Chamadas para funções das flags especiais, se marcadas
    if $help_flag; then
        print_usage
        exit 0
    fi

    if $check_flag; then
        checkAllFlags
        exit 0
    fi
}


# verificar se uma flag está ativa
# Uso: if hasFlag "d"; then echo "true"; else echo "false"; fi
hasFlag() {
    local flag=$1

    # Verifica se a flag curta está ativa
    if [[ -n "${FLAG_VALUES["-$flag"]}" ]]; then
        return 0  # verdadeiro
    fi

    # Verifica se a flag longa está ativa
    for key in "${!FLAGS[@]}"; do
        if [[ "${FLAGS[$key]}" == "$flag" && "${FLAG_VALUES[$key]}" == true ]]; then
            return 0  # verdadeiro
        fi
    done

    return 1  # falso
}


# retorna o valor de uma flag
# idealmente usado em subshell
# Uso: getFlag "d"
# test = "$(getFlag 'd')"
getFlag() {
    local flag=$1
    local value=${FLAG_VALUES["-$flag"]}
    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo ""
    fi
}


# checa todas flags adicionadas, e se tem valores atribuidos nelas.
# Uso: -- não é pra ser chamado manualmente. automaticamente usado pelo parse_flags na flag -c
checkAllFlags() {
    echo "--- FLAGS AND VALUES ---"
    
    # Define o tamanho padrão para alinhamento
    local max_length=0
    
    # Determina o comprimento máximo de cada linha de flag para o alinhamento
    for short_flag in "${!FLAGS[@]}"; do
        long_flag=${FLAGS[$short_flag]}
        line_output="$short_flag"
        [[ -n "$long_flag" ]] && line_output="$line_output, --$long_flag"
        
        # Atualiza max_length para o comprimento máximo encontrado
        [[ ${#line_output} -gt $max_length ]] && max_length=${#line_output}
    done

    # Ordena as flags e exibe a saída alinhada
    for short_flag in $(printf "%s\n" "${!FLAGS[@]}" | sort); do
        long_flag=${FLAGS[$short_flag]}
        value=${FLAG_VALUES[$short_flag]}
        type=${FLAG_TYPES[$short_flag]:-boolean}
        
        # Prepara a linha de saída para cada flag
        line_output="$short_flag"
        [[ -n "$long_flag" ]] && line_output="$line_output, --$long_flag"
        
        # Imprime a linha formatada para o alinhamento
        printf "  %-*s : " "$max_length" "$line_output"
        if [[ "$value" == true ]]; then
            printf "true (%s)\n" "$type"
        elif [[ -n "$value" ]]; then
            printf "value: %-10s (%s)\n" "$value" "$type"
        else
            printf "false (%s)\n" "$type"
        fi
    done
}


# Adiciona flags obrigatórias/padrões
add_flag "h" "help" "Shows this help" "boolean"
add_flag "c" "check" "Checks all flags and values, and exit" "boolean"
