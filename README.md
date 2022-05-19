# Estudos LPI Linux.

## Permissões avançadas e ALC Linux.
https://www.youtube.com/watch?v=tT69ipXOzfc

## Comando LS, ele nos trás uma resposta com 10 caracteres na primeira coluna:
drwxrwxr-x

1º caracter = qual tipo do arquivo.
- Arquivo comum = -
- Diretório = d 
- link simbólico = l
- dispositivo de bloco = b
- dispositivo de caracter = c

2º, 3º e 4º = Permissões do dono do arquivo.
r = read
w = write
x = execute

5º, 6º, 7º = Grupo dono desse arquivo e seus membros.
r = read
w = write
x = execute

8º, 9º e 10º = Outros, todos que não forem dono ou do grupo.
r = read
w = write
x = execute

## Valor modo octal linux (define um tipo de acesso diferente)
r = 4
w = 2
x = 1

Ex de permissão:

644 = -rw-r--r--

r w -  r - -  r - -
4 2 0  4 0 0  4 0 0 
4+2+0  4+0+0  4+0+0
  6      4      4


CHMOD (da permissão ao arquivo) = indicando o dono do arquivo U, indicando o grupo G, indicando outros O ou o A para mudar para todos.

```chmod g=w``` = dando permissão de escrita para o grupo. Quando usamos dessa forma, o comando faz com que o grupo fique exatamente com essa permissão de escrita removendo outras se tiver.
```chmod g+r``` = adiciona permissão de leitura.

CHOWN (muda o dono ou grupo dono <nome:grupo> ou <dono:> ou <:grupo>) ex:

```chown jaoliberato:users strigus``` = muda o dono para jaoliberato o grupo users pro arquivo strigus.
```chown jaoliberato: strigus``` = muda somente o dono.
```chown :users strigus``` = muda somente o grupo.

CHMOD - modo octal (numérico)

```chmod 664 strigus```

```chmod -R 777 teste1/```   = da a permissão 777 para o diretorio teste1/ e para o que tem dentro dele recursivamente.

## Permissões Especiais

suid = 4  (usuário)
sgid = 2  (grupo)
stick bit (t) = 1  (quer dizer que qualquer arquivo abaixo do diretorio com stick bit, somente o dono poderá apaga-lo ou renomea-lo) o diretório tmp tem o stick bit nele.

## setfacl e getfacl 
ACL = lista de permissões

```setfacl -m user:vliberato:rwx strigus``` = Setamos a permissão para que o usuário vliberato mesmo não sendo dono do arquivo ou fazendo parte do grupo dono do arquivo ele vai ter acesso ao arquivo com rwx.
```setfacl -m group:work:rwx strigus``` = Setamos permissão para o grupo work.

```getfacl``` = serve para verificar as acls de um determinado arquivo.

```getfacl strigus``` = visualizar as ACL do arquivo.



# Gerenciamento de pacotes.

## Debian

### dpkg

```dpkg -i pacote.deb``` = faz instalação de pacotes .deb (não resolve dependência).
```dpkg -l <nome-pacote>``` = verifica se o pacote realmente foi instalado.
```dpgk -r <nome-pacote>``` = remove o pacote instalado.
```dpkg -P <nome-pacote>``` = remove o pacote e suas dependências.
```dpkg -c pacote.deb``` = verifica o conteúdo do pacote.deb.
```dpkg -I pacote.deb``` = mostra as informações do pacote.
```dpkg -L pacote.deb``` = mostra todos os arquivos adicionados pelo pacote.

### apt-get
https://www.youtube.com/watch?v=Dj1dh2Ve0vE

Utilitário para fazer a instação de pacotes e softwares e resolve dependências. É necessário ter configurado na máquina o endereço do repositório do pacote

Como listar os repositórios adicionados:
```cat /etc/apt/sources.list```

Fazer download da lista dos repositório e deixar disponível na máquina:
```apt-get update``` = porque utilizar o comando? Quando usamos o apt-get install para instalar um pacote, ele busca o pacote nesse repositório. Caso não tenha, ele não sai para internet para procurar.
```apt-get install <nome-pacote>``` = Vai até o repositório, faz o download desse pacote e instala na máquina.
```apt-get remove <nome-pacote>``` = Remove o pacote instalado.
```apt-cache search <nome-pacote>``` =  Procurar o nome de umd determinado pacote.
```apt-get remove --purge <nome-pacote>``` = remove o pacote e suas dependências.
```apt-get upgrade``` = faz a atualização de todos os pacotes da máquina.
```apt-get dist-upgrade``` = atualiza a versão do debian.
```apt-get clean``` = remove todos os pacotes .deb que ele utilizou para instalar pacotes (/var/cache/apt/archives).
```apt-get show <nome-pacote>``` = traz informações referentes ao pacote.
```apt-cache depends <nome-pacote>``` = visualização das dependências do pacote.


# Gerenciamento de processos.

Um processo nada mais é do que um programa em execução, ou **qualquer coisa em execução** no linux é considerado um processo.
Por exemplo, quando você executa o comando ```ls``` ele é um processo em execução, ele foi um processo.

Quando você starta um processo, você recebe o PID = Process Identification (Identificação do processo).

Características comum de um processo.
Lifetime = Tempo de execução.
PID = Process Identification
PPID = Parent Process Identification (processo que de origem a esse outro processo).
UID = User Identification (usuário que startou o processo, responsável pelo processo).


## Comando PS
O comando ```ps``` serve para visualizar processos no Linux.

O comando ```ps``` sozinho, mostra somente os processos que estão rodando em primeiro plano no terminal.

```ps aux``` = parâmetro **a** mostra todos os processos, o parâmetro **x** mostra todos os processos que não estão conectados nesse terminal, o parâmetro **u** mostra o horário e o usuário responsável. 

O comando ps não é dinâmico, então ele mostra os processos na hora que ele foi executado.

Infos importantes nas colunas do comando ps:
RSS = Mostra a quantidade de memória física consumida.

STAT = Mostra o status do processo ex:
- R = Runing
- D = Uninterruptible sleep
- S = Sleep
- T = Stopped
- Z = Zombie
- W = Paging

TIME = tempo de cpu do processo.

COMMAND = O processo propriamente dito.

O comando ```ps auxwww``` joga na tela o comando inteiro do processo.

```ps -ef``` = Parâmetro -ef, -e = all process, -f = full-format, including command lines.
 
## Comando TOP
Ajuda a visualizar os procesos em tempo real.
Podemos usar o shift + > ou shift + < para navegar nos processos.

## Comando HTOP
Semelhante ao comando ```TOP``` porém melhorado.
F1 - help
F2 - setup (realizar ajustes)
F3 - Search 
F5 - Deixa em árvore.
F7 e F8 - Diminui e aumenta a prioridade do processo.
F9 - Kill


## Comando Kill
Comando utilizado para mater ou finalizar outros processos.
```kill <pid.processo>```

Como descobrir o PID de um processo: ex: ```pgrep vim```

kill 15 (defalut) = encerra o processo de forma correta, do jeito que deve ser.
Nos outros comandos precisamos colocar o sinal de "-":
kill -9 = Força a finalização do processo.
kill -1 = Da um reload no processo.

Podemos ver outros sinal do comando ```kill``` no man.

# Procurando arquivos no Linux.

## Locate
Comando utilizado para procurar algum arquivo.
Ex:
```locate teste.txt```
Ele depende da utilização do **updatedb** e não procura arquivos no **/tmp**.

## Find
```find / -name <nome.arquivo>``` = find depois colocamos o diretório -name e o nome do arquvi.

É sensitive case, para retirar isso usamos o parâmetro **-iname**.
Aceita metacaracteres: ```find / -iname arqui*``` = tudo que tiver arqui no inicio do nome ele vai pegar.
```find / -iname arquiv?``` = interrogação substitui um carcater.

```find / -iname SENHAS -user root -group root -perm 640``` = Irá procurar arquivos com o nome SENHA, que o dono seja o **root**, que o grupo do arquivo seja **root** e a permissão do arquivo seja 640.

```find / -iname SENHAS -type d``` = Irá procurar o arquivo SENHAS, o **-type*** quer dizer o tipo do arquivo, nesse casa o *d* seria um *diretório*.

```find / -iname SENHAS -atime -30``` = Irá procurar por arquivos de nome SENHAS, tiveram as permissões modificadas nos últimos 30 dias.

```find / -iname SENHAS -mtime -10``` = Irá procurar por arquivos de nome SENHAS, que foram modificados a menos de 10 dias.

```find / -iname SENHAS -ctime +20``` = Vemos as permissões, arquivos modificados a mais de 20 dias.

```find / -iname linux.MD -exec echo "Achei o arquivo: " {} \;``` = exec faz com que você consiga executar um comendo com a saída do **find**.


# Comandos que devemos conhecer no Linux.

## Comando df

```df -h``` = Mostra as partições e dispositivos adicionados na máquina e suas informações.
```dh -i``` = i = **inodes**, são número limitados de "gavetas" no nosso disco que podemos guardar coisas. Arquivos com 0bytes também ocupam **inodes**. Caso tenha algum problema com criação de arquivos, mesmo com espaço em disco liberado, devemos verificar os **inodes**.

## Comando netstat
Mostram as portas do servidor que estão abertas, em listen. Qual IP que determinada porta está bindando, conseguimos ver qual programa, processo, está sendo executado naquela porta.

```netstat -atunp``` = os parâmetros do **atunp** a = all, t = tcp, u = udp, n = don't resolve names, p = PID. Sendo assim uma saída bem completa.

## Comando du
Disk used. Verifica o quanto está sendo utilizado de disco.

Podemos usar da seguinte forma:
```du -sh *``` = para verificar quanto está sendo usado de disco em todo o repositório que você executa o comando. Parâmetro -s = summaryze mostra o total de cada argumento no caso diretório abaixo do que você está executando, -h human-readable joga em formato humando para leitura ex: 1K, 234M, 23G.

## Comando history
Joga o histórico de comandos.

Podemos utilizar de várias formas:
```history | tail``` = mostra as últimas 10 linhas, no caso os últimos 10 comandos.

Podemos utilizar o ```ctrl + r``` conseguimos fazer buscas no history.

## Chets

Ex: vamos criar 3 arquivos no repositório.
```touch teste1 teste2 teste3```
Agora precisamos dar permissão de execução nesses 3 arquivos. Para não ter que escrever o nome de cada arquivo novamente, podemos utilizar o comando:
```chmod +x !*``` = o !* trás todos os argumentos do último comando, que seria o nome dos 3 arquivos. Assim dando a permissão para os 3 de vez.

```alt + T``` = altera a ordem dos argumentos do comando (atalho do bash).


# Gerenciamento de logs Linux.

```cd /var/log/``` = local onde o sistema armazena os logs.
*auth.log* = logs de autenticação.
*daemon.log* = logs de serviços, daemon.
*kern.log* = kernel do linux.
*user.log* = logs de usuário.
*syslog* = pega praticamente tudo do sistema.
*messages* = semelhante ao *syslog* tudo que for mensagem vai pra ele.

```/etc/rsyslog.conf``` = arquivo de configuração de logs.
```module(load="imuxsock")``` = suporte de logs do sistema local.
```module(load="imklog" permitnonkernelfacility="on")``` = suporte de logs do kernel.

### FACILIDADE.PRIORIDADE

Facilidade = Tipo de serviço.

| FACILIDADE | DEFINIÇÃO |
| --- | --- |
| **auth** | Mensagens de segurança/autorização. |
| **authpriv** | Mensagens de segurança/autorização (privativas). |
| **cron** | Daemons de agendamento (cront e at). |
|**daemon** | Outros daemons do sistema que não possuem facilidades específicas. |
|**ftp** | Daemon de ftp do sistema. |
|**kern** | Mensagens do kernel. |
|**lpr** | Subsistema de impressão. |
|**local10 a local17** | Reservados para uso local. |
|**mail** | Subsistema de e|mail. |
|**news** | Subsistema de notícias da USENET. |
|**security** | Sinônimo para a facilidade auth (evite usa-la). |
|**syslog** | Mensagens internas geradas peo syslogd. |
|**user** | Mensagens geréricas de nível usuário. |
|**uucp** | Subsistema de UUCP. |
|**"*"** | Confere com todas as facilidades. |

Prioridade = São os leveis das mensagens

| PRIORIDADE | DEFINIÇÃO |
| --- | --- |
| **emerg** | Emergência |
| **alert** | Alerta |
| **crit** | Crítico |
| **err** | Error |
| **warn** | Warning |
| **notice** | Notice |
| **info** | Informação | 
| **debug** | Debug |

Ex de configuração de arquivos de logs.
```/etc/rsyslog.conf``` ou ```/etc/rsyslog.d/50-default.conf ``` = Podemos configurar em um desses dois arquivos, vai depender do sistema.
Vamos adicionar os arquivos na parte de arquivos de log padrão.

Ex: 
```*.*            /var/log/centraldelogs.log``` = Aqui está sendo criado um arquivo com nome centraldelogs, e que irá receber todas as facilidades e todas as prioridade, em teses receberá todos os logs do sistema.
Após adicionar arquivos novos, precisamos restartar o serviço de logs: ```systemctl restart rsyslog.service```

Quando estivermos com dúvidas sobre o que contém em cada arquivo de logs, podemos ir na fonte (arquivos citados anteriormente em /etc/) e verificar o que está logando neles.

## Journalctl

Ferramenta para consulta de logs do journal. Journald é o serviço do systemd responsável pelo gerenciamento de logs, faz logs de tudo que for uma unit no systemd. Faz também os logs do kernel.

```journalctl --utc``` = joga os logs com o timezone utc.

```journalctl --since "2 hour ago"``` = pega os logs das últimas 2 horas.

```journalctl --since "2 days ago" --until "2 hour ago"``` = pega os logs de 2 dias atrás até 2 horas atrás.

```journalctl --since "2022-05-10 01:00:00" --until "2022-05-19 12:00:00``` = trazendo logs em horas exatas.

```journalctl -u ssh``` = Verificando logs através da Unit, nesse caso logs do ssh.

```journalctl -u ssh -r``` = Utilizando o parâmetro **r** = revert, coloca os logs mais recentes primeiro. Utilizado quando queremos ver os logs mais recentes.

```journalctl -u ssh -p "err"``` = Utilizando o parâmetro **p** = priority. Irá pegar apenas os logs que tem a prioridade error.


## LVM
