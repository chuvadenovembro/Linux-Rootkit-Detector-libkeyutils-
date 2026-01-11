Este repositório contém um conjunto de ferramentas para detecção e resposta a incidentes envolvendo o rootkit Ebury, que infecta a biblioteca libkeyutils.so para roubar credenciais SSH.

[!CAUTION]

🚨 AVISO CRÍTICO DE SEGURANÇA
No meio da administração de sistemas e segurança ofensiva, existe uma regra de ouro: "Servidor comprometido é servidor reinstalado".

Embora o script de desinfecção fornecido aqui tente remover o malware, não há garantias de que o invasor não tenha deixado outros "presentes" (backdoors ocultos, modificações no kernel ou tarefas agendadas). A recomendação técnica oficial é sempre fazer backup dos dados e formatar o sistema do zero.

🧰 O que há neste Toolkit?
Este repositório é composto por dois scripts principais:

1. verificar_rootkit.sh (O Detetive)
Finalidade: Realiza uma varredura profunda e silenciosa para confirmar se o servidor está infectado.

Técnica: Utiliza strace para contornar os truques de ocultação do vírus e compara o que o sistema operacional reporta com a realidade dos arquivos no disco.

2. desinfectar_rootkit.sh (O Cirurgião)
Finalidade: Tenta remover o arquivo malicioso e restaurar o link original da biblioteca do sistema.

Técnica: Força a remoção do malware através de chamadas de sistema (syscalls) diretas para evitar que o rootkit bloqueie a exclusão.

🚀 Como utilizar
Passo 1: Verificação
Sempre comece pela verificação para entender o estado do servidor:

Bash

chmod +x verificar_rootkit.sh
sudo ./verificar_rootkit.sh
Passo 2: Desinfecção (Uso Emergencial)
Caso a infecção seja confirmada e você precise manter o servidor online antes de uma formatação programada:

Bash

chmod +x desinfectar_rootkit.sh
sudo ./desinfectar_rootkit.sh
📋 Práticas de Pós-Desinfecção
Se você optou por desinfectar o servidor em vez de formatá-lo, siga obrigatoriamente estes passos imediatamente:

Troque todas as senhas: Especialmente as de usuários com acesso SSH.

Troque Chaves SSH: Revogue as chaves atuais e gere novas.

Reinstale a Biblioteca: Force a reinstalação do pacote oficial para garantir integridade:

Debian/Ubuntu: apt-get install --reinstall libkeyutils1

RHEL/AlmaLinux: yum reinstall keyutils-libs -y

Analise os Logs: Verifique /var/log/auth.log ou /var/log/secure em busca de acessos de IPs desconhecidos.

⚠️ Aviso Legal: Estes scripts são para fins educacionais e de diagnóstico. O uso em ambientes de produção é de total responsabilidade do usuário.
