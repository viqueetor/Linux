# Permissões avançadas e ALC Linux.
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
