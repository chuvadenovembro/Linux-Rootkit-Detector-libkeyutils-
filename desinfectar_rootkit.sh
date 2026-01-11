#!/bin/bash

################################################################################
# Script de Desinfecção de Rootkit libkeyutils.so
#
# Descrição: Detecta e remove o rootkit/backdoor que infecta a biblioteca
#            libkeyutils.so em servidores Linux
#
# Uso: sudo ./desinfectar_rootkit.sh
#
# ATENÇÃO: Este script modifica arquivos críticos do sistema.
#          Faça backup antes de executar!
#
# Autor: Security Analysis Script
# Data: 2026
################################################################################

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

# Obter o diretório onde o script está localizado
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Variáveis globais
LOG_FILE="${SCRIPT_DIR}/desinfeccao_$(date +%Y%m%d_%H%M%S).log"
INFECTED=false
INFECTION_DATA=""

# Banner
show_banner() {
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}   DESINFECÇÃO DE ROOTKIT libkeyutils.so${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}ATENÇÃO: Este script modifica arquivos críticos do sistema!${NC}"
    echo -e "${YELLOW}         Certifique-se de ter backup antes de continuar.${NC}"
    echo ""
}

# Verificar se está rodando como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Este script precisa ser executado como root (sudo)${NC}"
        exit 1
    fi
}

# Função de log
log_message() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

# Função para exibir mensagens
print_msg() {
    local status="$1"
    local message="$2"

    case "$status" in
        "OK")
            echo -e "${GREEN}[✓]${NC} $message"
            log_message "INFO" "$message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[⚠]${NC} $message"
            log_message "WARNING" "$message"
            ;;
        "CRITICAL")
            echo -e "${RED}[✗]${NC} $message"
            log_message "CRITICAL" "$message"
            ;;
        "INFO")
            echo -e "${BLUE}[i]${NC} $message"
            log_message "INFO" "$message"
            ;;
        "ACTION")
            echo -e "${BOLD}[>]${NC} $message"
            log_message "ACTION" "$message"
            ;;
    esac
}

################################################################################
# INSTALAÇÃO DE DEPENDÊNCIAS
################################################################################
install_dependencies() {
    print_msg "INFO" "Verificando dependências..."

    if ! command -v strace &> /dev/null; then
        print_msg "WARNING" "strace não encontrado. Instalando..."

        if command -v dnf &> /dev/null; then
            dnf install -y -q strace > /dev/null 2>&1
        elif command -v yum &> /dev/null; then
            yum install -y -q strace > /dev/null 2>&1
        elif command -v apt-get &> /dev/null; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq > /dev/null 2>&1
            apt-get install -y -qq strace > /dev/null 2>&1
        fi

        if ! command -v strace &> /dev/null; then
            print_msg "CRITICAL" "Não foi possível instalar strace. Abortando."
            exit 1
        fi
    fi

    print_msg "OK" "Dependências OK"
}

################################################################################
# DETECÇÃO DE INFECÇÃO
################################################################################
detect_infection() {
    print_msg "INFO" "=== Iniciando detecção de infecção ==="

    local symlinks_to_check=(
        "/usr/lib64/libkeyutils.so.1"
        "/usr/lib/libkeyutils.so.1"
        "/lib64/libkeyutils.so.1"
        "/lib/libkeyutils.so.1"
        "/usr/lib/x86_64-linux-gnu/libkeyutils.so.1"
    )

    for symlink in "${symlinks_to_check[@]}"; do
        # Pular se não existe
        [[ ! -L "$symlink" ]] && continue

        # Resolver o diretório real (seguir symlinks de diretório)
        local dir=$(dirname "$symlink")
        local real_dir=$(readlink -f "$dir")
        local real_symlink="${real_dir}/$(basename "$symlink")"

        [[ ! -L "$real_symlink" ]] && continue

        print_msg "INFO" "Verificando: $real_symlink"

        # Método 1: readlink normal (pode estar sendo manipulado)
        local readlink_normal=$(readlink "$real_symlink" 2>/dev/null)

        # Método 2: Capturar o resultado REAL da syscall via strace
        local readlink_strace=$(strace -e readlink readlink "$real_symlink" 2>&1 | grep "^readlink" | head -1 | sed -n 's/.*"\([^"]*\)".*/\1/p')

        # Se strace não retornou nada, tentar com readlinkat
        if [[ -z "$readlink_strace" ]]; then
            readlink_strace=$(strace -e readlinkat readlink "$real_symlink" 2>&1 | grep "readlinkat" | head -1 | sed -n 's/.*"\([^"]*\)".*/\1/p')
        fi

        echo "  Symlink reportado (manipulado): $readlink_normal"
        echo "  Symlink real (via syscall):     $readlink_strace"

        # Comparar os resultados
        if [[ -n "$readlink_normal" && -n "$readlink_strace" && "$readlink_normal" != "$readlink_strace" ]]; then
            INFECTED=true

            local malicious_file="${real_dir}/${readlink_strace}"
            local legitimate_file="${real_dir}/${readlink_normal}"

            print_msg "CRITICAL" "!!! INFECÇÃO DETECTADA !!!"
            echo ""
            echo -e "  ${RED}Diretório afetado:${NC}    $real_dir"
            echo -e "  ${RED}Symlink afetado:${NC}      $real_symlink"
            echo -e "  ${RED}Arquivo MALICIOSO:${NC}    $malicious_file"
            echo -e "  ${GREEN}Arquivo LEGÍTIMO:${NC}     $legitimate_file"
            echo ""

            # Verificar informações do arquivo malicioso via strace
            local file_size=$(strace -e statx stat "$malicious_file" 2>&1 | grep "stx_size" | head -1 | grep -oP 'stx_size=\K[0-9]+')
            local has_suid=$(strace -e statx stat "$malicious_file" 2>&1 | grep "S_ISUID" | head -1)

            echo -e "  ${RED}Tamanho do malware:${NC}   ${file_size:-desconhecido} bytes"
            if [[ -n "$has_suid" ]]; then
                echo -e "  ${RED}SUID BIT:${NC}             ATIVADO (backdoor)"
            fi
            echo ""

            # Armazenar dados da infecção para desinfecção
            INFECTION_DATA="${real_dir}|${real_symlink}|${malicious_file}|${legitimate_file}|${readlink_normal}"

            # Só processar a primeira infecção encontrada (geralmente são symlinks para o mesmo local)
            return 0
        else
            print_msg "OK" "Symlink íntegro: $real_symlink -> $readlink_normal"
        fi
    done

    if [[ "$INFECTED" == false ]]; then
        echo ""
        print_msg "OK" "Nenhuma infecção de rootkit libkeyutils detectada!"
        echo ""
        return 1
    fi
}

################################################################################
# CONFIRMAÇÃO DO USUÁRIO
################################################################################
confirm_disinfection() {
    echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}   CONFIRMAÇÃO DE DESINFECÇÃO${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BOLD}O processo de desinfecção irá:${NC}"
    echo "  1. Remover o arquivo malicioso (usando strace para bypass)"
    echo "  2. Remover o symlink comprometido"
    echo "  3. Recriar o symlink apontando para o arquivo legítimo"
    echo ""
    echo -e "${RED}AVISO: Certifique-se de ter acesso físico ou console ao servidor${NC}"
    echo -e "${RED}       caso algo dê errado durante o processo.${NC}"
    echo ""

    while true; do
        read -p "Deseja prosseguir com a desinfecção? (sim/nao): " resposta
        case "${resposta,,}" in
            sim|s|yes|y)
                return 0
                ;;
            nao|n|no)
                print_msg "INFO" "Desinfecção cancelada pelo usuário."
                exit 0
                ;;
            *)
                echo "Por favor, responda 'sim' ou 'nao'"
                ;;
        esac
    done
}

################################################################################
# PROCESSO DE DESINFECÇÃO
################################################################################
disinfect() {
    print_msg "INFO" "=== Iniciando processo de desinfecção ==="

    # Extrair dados da infecção
    IFS='|' read -r real_dir real_symlink malicious_file legitimate_file legitimate_name <<< "$INFECTION_DATA"

    echo ""
    print_msg "ACTION" "Passo 1/3: Removendo arquivo malicioso..."
    echo "  Comando: strace -o /dev/null rm -fv \"$malicious_file\""

    # Usar strace para bypass do rootkit ao remover
    local rm_output=$(strace -o /dev/null rm -fv "$malicious_file" 2>&1)
    echo "  Resultado: $rm_output"

    # Verificar se foi removido
    local check_removed=$(strace -o /dev/null ls "$malicious_file" 2>&1)
    if echo "$check_removed" | grep -q "No such file"; then
        print_msg "OK" "Arquivo malicioso removido com sucesso!"
    else
        print_msg "WARNING" "Verificar se o arquivo foi removido (pode haver erro de exibição)"
    fi

    echo ""
    print_msg "ACTION" "Passo 2/3: Removendo symlink comprometido..."
    echo "  Comando: rm -fv \"$real_symlink\""

    # Remover symlink (pode mostrar erro de LD_PRELOAD, é normal)
    rm -fv "$real_symlink" 2>&1 | grep -v "LD_PRELOAD" | sed 's/^/  /'

    print_msg "OK" "Symlink removido!"

    echo ""
    print_msg "ACTION" "Passo 3/3: Recriando symlink para arquivo legítimo..."
    echo "  Comando: ln -s \"$legitimate_name\" \"$real_symlink\""

    # Recriar symlink para o arquivo legítimo
    ln -s "$legitimate_name" "$real_symlink" 2>&1 | grep -v "LD_PRELOAD" | sed 's/^/  /'

    print_msg "OK" "Symlink recriado!"

    echo ""
    print_msg "INFO" "=== Verificando resultado da desinfecção ==="

    # Verificar se o symlink agora aponta corretamente
    local new_target=$(readlink "$real_symlink" 2>/dev/null)
    local new_target_strace=$(strace -e readlink readlink "$real_symlink" 2>&1 | grep "^readlink" | head -1 | sed -n 's/.*"\([^"]*\)".*/\1/p')

    if [[ -z "$new_target_strace" ]]; then
        new_target_strace=$(strace -e readlinkat readlink "$real_symlink" 2>&1 | grep "readlinkat" | head -1 | sed -n 's/.*"\([^"]*\)".*/\1/p')
    fi

    echo "  Symlink normal:  $new_target"
    echo "  Symlink syscall: $new_target_strace"

    if [[ "$new_target" == "$new_target_strace" && "$new_target" == "$legitimate_name" ]]; then
        echo ""
        print_msg "OK" "╔══════════════════════════════════════════════════════════════╗"
        print_msg "OK" "║  DESINFECÇÃO CONCLUÍDA COM SUCESSO!                          ║"
        print_msg "OK" "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo -e "${GREEN}O rootkit foi removido e o symlink restaurado.${NC}"
        echo ""
        echo -e "${YELLOW}Recomendações pós-desinfecção:${NC}"
        echo "  1. Altere TODAS as senhas SSH do servidor"
        echo "  2. Revogue e regenere chaves SSH"
        echo "  3. Verifique logs de acesso (/var/log/secure, /var/log/auth.log)"
        echo "  4. Considere reinstalar o pacote keyutils:"
        if command -v dnf &> /dev/null || command -v yum &> /dev/null; then
            echo "     yum reinstall keyutils-libs -y"
        else
            echo "     apt-get install --reinstall libkeyutils1"
        fi
        echo "  5. Investigue como o atacante obteve acesso inicial"
        echo ""
    else
        print_msg "WARNING" "Verificação pós-desinfecção inconclusiva."
        print_msg "WARNING" "Por favor, verifique manualmente:"
        echo "  ls -la $real_symlink"
        echo "  strace -o /dev/null ls -la ${real_dir}/libkeyutils.so*"
    fi
}

################################################################################
# FUNÇÃO PRINCIPAL
################################################################################
main() {
    show_banner
    check_root

    echo "Log será salvo em: $LOG_FILE"
    echo ""

    install_dependencies
    echo ""

    # Detectar infecção
    if detect_infection; then
        # Confirmar com o usuário
        confirm_disinfection

        # Executar desinfecção
        disinfect
    fi

    echo -e "${BLUE}Log completo salvo em:${NC} $LOG_FILE"
    echo ""
}

# Executar
main
