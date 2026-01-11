#!/bin/bash

################################################################################
# Script de Detecção de Rootkit/Backdoor em libkeyutils.so
#
# Descrição: Detecta variantes maliciosas de libkeyutils usando múltiplas
#            técnicas para contornar hooks de rootkits
#
# Uso: sudo ./verificar_rootkit_03.sh
#
# Autor: Security Analysis Script
# Data: 2025
################################################################################

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;36m'  # Azul claro (Cyan brilhante)
NC='\033[0m' # Sem cor

# Obter o diretório onde o script está localizado
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Variáveis globais
SUSPICIOUS_COUNT=0
LOG_FILE="${SCRIPT_DIR}/rootkit_detection_$(date +%Y%m%d_%H%M%S).log"
TEMP_DIR="/tmp/rootkit_check_$$"

# Banner
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Detector de Rootkit/Backdoor em libkeyutils.so${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Verificar se está rodando como root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Este script precisa ser executado como root (sudo)${NC}"
   exit 1
fi

# Criar diretório temporário
mkdir -p "$TEMP_DIR"

################################################################################
# INSTALAÇÃO AUTOMÁTICA DE DEPENDÊNCIAS
################################################################################
install_dependencies() {
    echo -e "${BLUE}[i]${NC} Verificando e instalando dependências necessárias..."

    local packages_to_install=()
    local is_rhel_based=false

    # Detectar se é sistema baseado em RHEL (AlmaLinux, Rocky, CentOS, Fedora)
    if [[ -f /etc/redhat-release ]] || command -v dnf &> /dev/null || command -v yum &> /dev/null; then
        is_rhel_based=true
    fi

    # Lista de comandos e seus pacotes correspondentes
    # Formato: comando:pacote_debian:pacote_rhel
    declare -A cmd_to_pkg_deb
    declare -A cmd_to_pkg_rhel

    cmd_to_pkg_deb=(
        ["strace"]="strace"
        ["strings"]="binutils"
        ["netstat"]="net-tools"
        ["lsof"]="lsof"
        ["ss"]="iproute2"
    )

    cmd_to_pkg_rhel=(
        ["strace"]="strace"
        ["strings"]="binutils"
        ["netstat"]="net-tools"
        ["lsof"]="lsof"
        ["ss"]="iproute"
    )

    # Verificar quais comandos estão faltando
    for cmd in "${!cmd_to_pkg_deb[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            if [[ "$is_rhel_based" == true ]]; then
                packages_to_install+=("${cmd_to_pkg_rhel[$cmd]}")
            else
                packages_to_install+=("${cmd_to_pkg_deb[$cmd]}")
            fi
        fi
    done

    # Se não há nada para instalar, retornar
    if [[ ${#packages_to_install[@]} -eq 0 ]]; then
        echo -e "${GREEN}[✓]${NC} Todas as dependências já estão instaladas"
        return 0
    fi

    # Remover duplicatas
    local unique_packages=($(echo "${packages_to_install[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

    echo -e "${YELLOW}[⚠]${NC} Pacotes a instalar: ${unique_packages[*]}"

    # Detectar o gerenciador de pacotes e instalar
    if command -v dnf &> /dev/null; then
        # AlmaLinux, Rocky Linux, Fedora, RHEL 8+
        dnf install -y -q "${unique_packages[@]}" > /dev/null 2>&1
    elif command -v yum &> /dev/null; then
        # CentOS 7, RHEL 7
        yum install -y -q "${unique_packages[@]}" > /dev/null 2>&1
    elif command -v apt-get &> /dev/null; then
        # Debian, Ubuntu
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y -qq "${unique_packages[@]}" > /dev/null 2>&1
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        pacman -S --noconfirm --quiet "${unique_packages[@]}" > /dev/null 2>&1
    elif command -v zypper &> /dev/null; then
        # openSUSE
        zypper install -y -q "${unique_packages[@]}" > /dev/null 2>&1
    else
        echo -e "${RED}[✗]${NC} Gerenciador de pacotes não suportado. Instale manualmente: ${unique_packages[*]}"
        return 1
    fi

    echo -e "${GREEN}[✓]${NC} Dependências instaladas com sucesso"
    return 0
}

# Instalar dependências antes de iniciar
install_dependencies

# Função de log
log_message() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

# Função para exibir resultados
print_result() {
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
            ((SUSPICIOUS_COUNT++))
            ;;
        "CRITICAL")
            echo -e "${RED}[✗]${NC} $message"
            log_message "CRITICAL" "$message"
            ((SUSPICIOUS_COUNT++))
            ;;
        "INFO")
            echo -e "${BLUE}[i]${NC} $message"
            log_message "INFO" "$message"
            ;;
    esac
}

################################################################################
# 1. DETECÇÃO DE MANIPULAÇÃO DE SYMLINKS (TÉCNICA PRINCIPAL)
# Esta é a técnica mais efetiva para detectar rootkits que interceptam saídas
################################################################################
check_symlink_manipulation() {
    print_result "INFO" "=== Verificando manipulação de symlinks via strace ==="

    local symlinks_to_check=(
        "/usr/lib64/libkeyutils.so.1"
        "/usr/lib/libkeyutils.so.1"
        "/lib64/libkeyutils.so.1"
        "/lib/libkeyutils.so.1"
        "/usr/lib/x86_64-linux-gnu/libkeyutils.so.1"
    )

    local infection_detected=false

    for symlink in "${symlinks_to_check[@]}"; do
        # Pular se não existe
        [[ ! -L "$symlink" ]] && continue

        # Resolver o diretório real (seguir symlinks de diretório)
        local real_symlink=$(readlink -f "$(dirname "$symlink")")/$(basename "$symlink")
        [[ ! -L "$real_symlink" ]] && continue

        print_result "INFO" "Verificando: $real_symlink"

        # Método 1: readlink normal (pode estar sendo manipulado pelo rootkit)
        local readlink_normal=$(readlink "$real_symlink" 2>/dev/null)

        # Método 2: Capturar o resultado REAL da syscall readlink via strace
        # O rootkit pode manipular a saída do comando, mas não a syscall em si
        local readlink_strace=$(strace -e readlink readlink "$real_symlink" 2>&1 | grep "^readlink" | head -1 | sed -n 's/.*"\([^"]*\)".*/\1/p')

        echo "  readlink normal:  $readlink_normal"
        echo "  readlink syscall: $readlink_strace"

        # Comparar os resultados
        if [[ -n "$readlink_normal" && -n "$readlink_strace" && "$readlink_normal" != "$readlink_strace" ]]; then
            print_result "CRITICAL" "!!! MANIPULAÇÃO DE SYMLINK DETECTADA !!!"
            print_result "CRITICAL" "O rootkit está ocultando o arquivo real!"
            echo -e "  ${RED}Symlink reportado: ${NC}$readlink_normal"
            echo -e "  ${RED}Symlink REAL:      ${NC}$readlink_strace"
            infection_detected=true

            # Tentar obter informações do arquivo oculto via strace
            local hidden_file="$(dirname "$real_symlink")/$readlink_strace"
            print_result "CRITICAL" "Arquivo oculto: $hidden_file"

            # Verificar se o arquivo oculto existe (via strace)
            local file_info=$(strace -e statx,fstat stat "$hidden_file" 2>&1 | grep -E "st_size|stx_size" | head -1)
            if [[ -n "$file_info" ]]; then
                echo -e "  ${RED}Informações do arquivo malicioso:${NC}"
                # Extrair tamanho
                local size=$(echo "$file_info" | grep -oP 'st[x]?_size=\K[0-9]+')
                echo "    Tamanho: $size bytes"

                # Verificar se tem SUID
                local mode_info=$(strace -e statx stat "$hidden_file" 2>&1 | grep "stx_mode" | head -1)
                if echo "$mode_info" | grep -q "S_ISUID"; then
                    print_result "CRITICAL" "ARQUIVO TEM SUID BIT! (Backdoor com escalação de privilégios)"
                fi
            fi
        else
            print_result "OK" "Symlink íntegro: $real_symlink -> $readlink_normal"
        fi
    done

    if [[ "$infection_detected" == true ]]; then
        echo ""
        print_result "CRITICAL" "╔══════════════════════════════════════════════════════════════╗"
        print_result "CRITICAL" "║  SERVIDOR INFECTADO COM ROOTKIT LIBKEYUTILS!                 ║"
        print_result "CRITICAL" "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo -e "${RED}Este é um rootkit conhecido que:${NC}"
        echo "  • Intercepta chamadas de sistema para ocultar arquivos"
        echo "  • Captura credenciais SSH"
        echo "  • Pode fornecer acesso backdoor ao atacante"
        echo ""
    fi
}

################################################################################
# 2. DETECÇÃO POR MÚLTIPLOS MÉTODOS DE LISTAGEM
################################################################################
check_file_visibility() {
    print_result "INFO" "=== Verificando visibilidade de arquivos libkeyutils ==="

    local paths=(
        "/usr/lib64/libkeyutils.so*"
        "/usr/lib/libkeyutils.so*"
        "/lib64/libkeyutils.so*"
        "/lib/libkeyutils.so*"
        "/usr/lib/x86_64-linux-gnu/libkeyutils.so*"
    )

    for path_pattern in "${paths[@]}"; do
        local dir=$(dirname "$path_pattern")
        [[ ! -d "$dir" ]] && continue

        # Pular diretórios que são symlinks (como /lib64 -> /usr/lib64 no RHEL/AlmaLinux)
        # Isso evita falsos positivos pois ls segue o symlink mas find não
        if [[ -L "$dir" ]]; then
            local real_dir=$(readlink -f "$dir")
            print_result "INFO" "Pulando $dir (symlink para $real_dir)"
            continue
        fi

        print_result "INFO" "Verificando: $dir"

        # Método 1: ls normal (pode estar hookado)
        local ls_output=$(ls -la $path_pattern 2>/dev/null | grep -v '^total' | awk '{print $NF}')

        # Método 2: find (geralmente mais confiável)
        local find_output=$(find "$dir" -maxdepth 1 -name "libkeyutils.so*" 2>/dev/null)

        # Comparar resultados (extrair apenas nomes de arquivo base)
        echo "$ls_output" | grep -o 'libkeyutils\.so[^ ]*' | sort -u > "$TEMP_DIR/ls.txt"
        echo "$find_output" | xargs -n1 basename 2>/dev/null | sort -u > "$TEMP_DIR/find.txt"

        # Contar arquivos em cada método (remover linhas vazias e contar)
        local ls_count=$(grep -v '^$' "$TEMP_DIR/ls.txt" 2>/dev/null | wc -l | tr -d ' ')
        local find_count=$(grep -v '^$' "$TEMP_DIR/find.txt" 2>/dev/null | wc -l | tr -d ' ')

        # Garantir que são números
        ls_count=${ls_count:-0}
        find_count=${find_count:-0}

        print_result "INFO" "  Arquivos detectados: ls=$ls_count, find=$find_count"

        # Detectar discrepâncias significativas (diferença > 1 arquivo)
        local diff=$((ls_count - find_count))
        local abs_diff=${diff#-}
        abs_diff=${abs_diff:-0}

        if [[ $abs_diff -gt 1 ]]; then
            print_result "CRITICAL" "DISCREPÂNCIA SIGNIFICATIVA DETECTADA: Diferença de $abs_diff arquivo(s)!"
            echo -e "  ${RED}ls normal ($ls_count arquivos):${NC}"
            cat "$TEMP_DIR/ls.txt" | sed 's/^/    /'
            echo -e "  ${RED}find ($find_count arquivos):${NC}"
            cat "$TEMP_DIR/find.txt" | sed 's/^/    /'
        else
            print_result "OK" "Visibilidade de arquivos consistente em $dir"
        fi
    done
}

################################################################################
# 2. VERIFICAÇÃO DE INTEGRIDADE COM RPM/DPKG
################################################################################
check_package_integrity() {
    print_result "INFO" "=== Verificando integridade do pacote keyutils ==="

    # Para sistemas RedHat/CentOS/Rocky
    if command -v rpm &> /dev/null; then
        local rpm_verify=$(rpm -V keyutils-libs 2>&1)

        if [[ -n "$rpm_verify" ]]; then
            print_result "CRITICAL" "Arquivos do pacote keyutils-libs foram modificados:"
            echo "$rpm_verify" | sed 's/^/    /'

            # Explicar os códigos
            echo -e "\n  ${YELLOW}Legenda RPM:${NC}"
            echo "    S = Tamanho diferente"
            echo "    M = Permissões/tipo modificado"
            echo "    5 = Hash MD5 diferente"
            echo "    D = Device major/minor diferente"
            echo "    L = Link simbólico alterado"
            echo "    U = Usuário modificado"
            echo "    G = Grupo modificado"
            echo "    T = Timestamp modificado"
        else
            print_result "OK" "Integridade do pacote keyutils-libs está OK"
        fi
    fi

    # Para sistemas Debian/Ubuntu
    if command -v dpkg &> /dev/null; then
        local dpkg_verify=$(dpkg -V libkeyutils1 2>&1 | grep -v "^$")

        if [[ -n "$dpkg_verify" ]]; then
            print_result "CRITICAL" "Arquivos do pacote libkeyutils1 foram modificados:"
            echo "$dpkg_verify" | sed 's/^/    /'
        else
            print_result "OK" "Integridade do pacote libkeyutils1 está OK"
        fi
    fi
}

################################################################################
# 3. ANÁLISE DE HASH E ASSINATURA DOS ARQUIVOS
################################################################################
check_file_hashes() {
    print_result "INFO" "=== Calculando hashes dos arquivos libkeyutils ==="

    # Encontrar todos os arquivos
    local files=$(find /usr/lib64 /usr/lib /lib64 /lib /usr/lib/x86_64-linux-gnu -name "libkeyutils.so*" 2>/dev/null | sort -u)

    if [[ -z "$files" ]]; then
        print_result "WARNING" "Nenhum arquivo libkeyutils encontrado"
        return
    fi

    while IFS= read -r file; do
        [[ -z "$file" || ! -e "$file" ]] && continue

        # Pular links simbólicos
        if [[ -L "$file" ]]; then
            local target=$(readlink -f "$file")
            print_result "INFO" "Link: $file -> $target"
            continue
        fi

        print_result "INFO" "Analisando: $file"

        # Calcular hash
        local md5_hash=$(md5sum "$file" 2>/dev/null | awk '{print $1}')
        local sha256_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')

        echo "  MD5:    $md5_hash"
        echo "  SHA256: $sha256_hash"

        # Verificar tamanho do arquivo
        local size=$(stat -c%s "$file" 2>/dev/null)
        echo "  Tamanho: $size bytes"

        # Verificar permissões (bibliotecas normais são 644 ou 755)
        local perms=$(stat -c%a "$file" 2>/dev/null)

        # Verificar SUID/SGID - apenas se o primeiro dígito for 4, 5, 6 ou 7 em permissões de 4 dígitos
        if [[ ${#perms} -eq 4 && "${perms:0:1}" =~ [4567] ]]; then
            print_result "CRITICAL" "SUID/SGID BIT DETECTADO! Permissões: $perms (muito suspeito para biblioteca)"
        else
            echo "  Permissões: $perms (OK)"
        fi

        # Verificar strings suspeitas no binário
        print_result "INFO" "Procurando strings suspeitas no arquivo..."
        local suspicious_strings=$(strings "$file" 2>/dev/null | grep -iE 'backdoor|rootkit|keylog|/tmp/\.|hide|hook|payload|bitcoin|miner|xmrig' | head -5)

        if [[ -n "$suspicious_strings" ]]; then
            print_result "CRITICAL" "STRINGS SUSPEITAS ENCONTRADAS:"
            echo "$suspicious_strings" | sed 's/^/    /'
        fi

        echo ""
    done <<< "$files"
}

################################################################################
# 4. DETECÇÃO DE ARQUIVOS OCULTOS POR NOME
################################################################################
check_hidden_versions() {
    print_result "INFO" "=== Procurando versões ocultas conhecidas ==="

    # Lista de variantes conhecidas do malware (apenas versões não-oficiais)
    # Versões oficiais do Debian/Ubuntu: 1.5, 1.6, 1.9, 1.10
    # Versões suspeitas são as com subversões adicionais ou prefixadas com ponto
    local known_variants=(
        "libkeyutils.so.1.6.2"
        "libkeyutils.so.1.10.2"
        "libkeyutils.so.2"
        ".libkeyutils.so"
        ".libkeyutils.so.1"
        "libkeyutils.so.1.3.2"
        "libkeyutils.so.1.3.3"
    )

    local search_paths=("/usr/lib64" "/usr/lib" "/lib64" "/lib" "/usr/lib/x86_64-linux-gnu")

    for path in "${search_paths[@]}"; do
        [[ ! -d "$path" ]] && continue

        for variant in "${known_variants[@]}"; do
            local full_path="$path/$variant"

            if [[ -e "$full_path" ]]; then
                print_result "CRITICAL" "ARQUIVO SUSPEITO DETECTADO: $full_path"
                ls -la "$full_path" 2>/dev/null | sed 's/^/    /'
            fi
        done
    done

    print_result "OK" "Verificação de arquivos ocultos concluída"
}

################################################################################
# 5. VERIFICAÇÃO DE MÓDULOS DE KERNEL SUSPEITOS
################################################################################
check_kernel_modules() {
    print_result "INFO" "=== Verificando módulos de kernel suspeitos ==="

    # Módulos conhecidos de rootkits
    local suspicious_modules=(
        "diamorphine"
        "reptile"
        "suterusu"
        "kelogd"
        "hider"
        "keyutils_hook"
    )

    local loaded_modules=$(lsmod | awk '{print $1}')

    for module in "${suspicious_modules[@]}"; do
        if echo "$loaded_modules" | grep -qi "$module"; then
            print_result "CRITICAL" "MÓDULO SUSPEITO CARREGADO: $module"
        fi
    done

    # Verificar módulos ocultos (diferença entre lsmod e /proc/modules)
    # lsmod inclui linha de cabeçalho, então subtraímos 1
    local lsmod_count=$(($(lsmod | wc -l) - 1))
    local proc_count=$(wc -l < /proc/modules)

    local diff=$((lsmod_count - proc_count))
    local abs_diff=${diff#-}  # Valor absoluto

    echo "  Módulos via lsmod:      $lsmod_count"
    echo "  Módulos via /proc:      $proc_count"
    echo "  Diferença:              $diff"

    # Diferença de 2+ módulos é suspeito (margem de 1 para threads/timing)
    if [[ $abs_diff -gt 1 ]]; then
        print_result "CRITICAL" "DISCREPÂNCIA DE MÓDULOS SIGNIFICATIVA: lsmod($lsmod_count) vs /proc/modules($proc_count)"
        print_result "CRITICAL" "Possível módulo de kernel rootkit oculto!"

        # Tentar identificar qual módulo está faltando
        print_result "INFO" "Analisando diferenças..."
        lsmod | tail -n +2 | awk '{print $1}' | sort > "$TEMP_DIR/lsmod_modules.txt"
        awk '{print $1}' /proc/modules | sort > "$TEMP_DIR/proc_modules.txt"

        local missing=$(comm -23 "$TEMP_DIR/lsmod_modules.txt" "$TEMP_DIR/proc_modules.txt")
        local extra=$(comm -13 "$TEMP_DIR/lsmod_modules.txt" "$TEMP_DIR/proc_modules.txt")

        if [[ -n "$missing" ]]; then
            print_result "WARNING" "Módulos em lsmod mas não em /proc/modules:"
            echo "$missing" | sed 's/^/    /'
        fi
        if [[ -n "$extra" ]]; then
            print_result "WARNING" "Módulos em /proc/modules mas não em lsmod:"
            echo "$extra" | sed 's/^/    /'
        fi
    else
        print_result "OK" "Contagem de módulos consistente (diferença de $diff é normal)"
    fi
}

################################################################################
# 6. VERIFICAÇÃO DE PROCESSOS OCULTOS
################################################################################
check_hidden_processes() {
    print_result "INFO" "=== Verificando processos ocultos ==="

    # Contar processos por diferentes métodos
    local ps_count=$(ps aux | wc -l)
    local proc_count=$(ls /proc | grep -E '^[0-9]+$' | wc -l)

    echo "  Processos via ps:    $ps_count"
    echo "  Processos via /proc: $proc_count"

    # Margem de erro aceitável (alguns podem ser threads)
    local diff=$((ps_count - proc_count))
    local abs_diff=${diff#-}  # Valor absoluto

    if [[ $abs_diff -gt 10 ]]; then
        print_result "CRITICAL" "GRANDE DISCREPÂNCIA na contagem de processos! Possível ocultação de processos."
        print_result "CRITICAL" "Diferença absoluta: $abs_diff processos"
    else
        print_result "OK" "Contagem de processos consistente (diferença de $diff dentro do esperado)"
    fi
}

################################################################################
# 7. VERIFICAÇÃO DE CONEXÕES DE REDE SUSPEITAS
################################################################################
check_network_connections() {
    print_result "INFO" "=== Verificando conexões de rede suspeitas ==="

    # Procurar conexões para portas conhecidas de mineração/C&C
    local suspicious_ports=(
        "3333"  # Pool de mineração
        "4444"  # Porta comum de backdoor
        "5555"  # Metasploit
        "8333"  # Bitcoin
        "14444" # XMR Mining
    )

    for port in "${suspicious_ports[@]}"; do
        local connections=""
        if command -v ss &> /dev/null; then
            connections=$(ss -antup 2>/dev/null | grep ":$port" | grep ESTAB)
        elif command -v netstat &> /dev/null; then
            connections=$(netstat -antup 2>/dev/null | grep ":$port" | grep ESTABLISHED)
        fi

        if [[ -n "$connections" ]]; then
            print_result "WARNING" "Conexão suspeita na porta $port detectada:"
            echo "$connections" | sed 's/^/    /'
        fi
    done

    print_result "OK" "Verificação de conexões concluída"
}

################################################################################
# 8. VERIFICAÇÃO DE TAREFAS CRON MALICIOSAS
################################################################################
check_cron_jobs() {
    print_result "INFO" "=== Verificando tarefas cron suspeitas ==="

    # Verificar crontabs do sistema
    local cron_files=$(find /etc/cron* /var/spool/cron -type f 2>/dev/null)

    if [[ -z "$cron_files" ]]; then
        print_result "OK" "Nenhum arquivo cron encontrado para verificar"
        return
    fi

    while IFS= read -r cron_file; do
        [[ -z "$cron_file" ]] && continue
        local suspicious=$(grep -iE 'curl.*sh|wget.*sh|\.so|libkeyutils|/tmp/\.|chmod \+x' "$cron_file" 2>/dev/null)

        if [[ -n "$suspicious" ]]; then
            print_result "CRITICAL" "CRON SUSPEITO em $cron_file:"
            echo "$suspicious" | sed 's/^/    /'
        fi
    done <<< "$cron_files"

    print_result "OK" "Verificação de cron concluída"
}

################################################################################
# 9. ANÁLISE DE DEPENDÊNCIAS E LINKED LIBRARIES
################################################################################
check_library_dependencies() {
    print_result "INFO" "=== Analisando dependências de bibliotecas ==="

    # Verificar quais binários dependem de libkeyutils
    local dependent_bins=$(ldd /bin/* /sbin/* /usr/bin/* /usr/sbin/* 2>/dev/null | grep libkeyutils | awk -F: '{print $1}' | sort -u | head -20)

    if [[ -n "$dependent_bins" ]]; then
        print_result "INFO" "Binários que dependem de libkeyutils (primeiros 20):"
        echo "$dependent_bins" | sed 's/^/    /'
    fi

    print_result "OK" "Verificação de dependências concluída"
}

################################################################################
# 10. GERAÇÃO DE RELATÓRIO FINAL
################################################################################
generate_report() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}   RELATÓRIO FINAL${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ $SUSPICIOUS_COUNT -eq 0 ]]; then
        print_result "OK" "NENHUMA AMEAÇA DETECTADA - Sistema aparenta estar limpo"
        echo ""
        echo -e "${GREEN}Recomendações:${NC}"
        echo "  • Continue monitorando o sistema regularmente"
        echo "  • Mantenha o sistema atualizado"
    else
        print_result "CRITICAL" "TOTAL DE ALERTAS CRÍTICOS/SUSPEITOS: $SUSPICIOUS_COUNT"
        echo ""
        echo -e "${RED}SISTEMA POSSIVELMENTE COMPROMETIDO!${NC}"
        echo ""
        echo -e "${YELLOW}Ações Recomendadas:${NC}"
        echo "  1. Revisar os alertas acima manualmente"
        echo "  2. Verificar logs de acesso e autenticação"
        echo "  3. Considerar análise forense mais profunda"
    fi

    echo ""
    echo -e "${BLUE}Log completo salvo em: ${NC}$LOG_FILE"
    echo ""
}

################################################################################
# EXECUÇÃO PRINCIPAL
################################################################################
main() {
    print_result "INFO" "Iniciando varredura em $(date)"
    echo ""

    # Verificação PRINCIPAL - Detecta manipulação de symlinks por rootkit
    check_symlink_manipulation
    echo ""

    # Executar demais verificações
    check_file_visibility
    echo ""

    check_package_integrity
    echo ""

    check_file_hashes
    echo ""

    check_hidden_versions
    echo ""

    check_kernel_modules
    echo ""

    check_hidden_processes
    echo ""

    check_network_connections
    echo ""

    check_cron_jobs
    echo ""

    check_library_dependencies
    echo ""

    # Gerar relatório final
    generate_report

    # Limpeza
    rm -rf "$TEMP_DIR"

    # Retornar código de saída apropriado
    if [[ $SUSPICIOUS_COUNT -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Trap para limpeza em caso de interrupção
trap "rm -rf $TEMP_DIR; echo 'Script interrompido'; exit 130" INT TERM

# Executar o script
main
