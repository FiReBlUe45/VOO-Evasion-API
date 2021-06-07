# .evasion-API

Ayant découvert ce [post](https://forum.voo.be/ma-box-evasion-10/api-de-la-box-evasion-7227) sur le forum de VOO et ce [GitHub](https://github.com/FiReBlUe45/VOO-Evasion-API) parlant de la création d'une API pour la box .evasion, je me suis lancé dans la création d'une API permettant de contrôler la box par le biais du réseau, mais aussi de trouver son adresse IP (probable), d'afficher les commandes connues et d'effectuer une conversion du nom de la commande au code envoyé et vice versa.

Attention, il est possible que votre pare-feu bloque l'exécution de cette API. Si tel est le cas tester l'API sans pare-feu et ajouter une autorisation pour le script (normalement seul le port 5900 est utilisé).

## LICENSE

> ​    evasion.py is an API which allows to detect and control an .évasion box from VOO
>
> ​    Copyright (C) 2019 Vincent STRAGIER (vincent.stragier@outlook.com)
>
> 
>
> ​    This program is free software: you can redistribute it and/or modify
>
> ​    it under the terms of the GNU General Public License as published by
>
> ​    the Free Software Foundation, either version 3 of the License, or
>
> ​    (at your option) any later version.
>
> 
>
> ​    This program is distributed in the hope that it will be useful,
>
> ​    but WITHOUT ANY WARRANTY; without even the implied warranty of
>
> ​    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
>
> ​    GNU General Public License for more details.
>
> 
>
> ​    You should have received a copy of the GNU General Public License
>
> ​    along with this program.  If not, see <https://www.gnu.org/licenses/>.

## Installation et *requirements*

L'API a été développé sous Python 3 (sous Windows 10 et Debian). La détection de la box nécessite l'installation du module `netifaces`. L'installation de ce module est optionnel, car il n'est nécessaire que pour l'option de recherche de la box.

### Sous Linux

Installation de `python3` et de `pip3` afin d'installer `netifaces`, en ouvrant un terminal ou en SSH :

> sudo apt update
>
> sudo apt upgrade
>
> sudo apt install -y python3 pip3 python3-pip
>
> pip3 install netifaces



### Sous Windows

Installation de `Python 3` (`pip` est installé automatiquement) :

1. télécharger la dernière version stable de Python 3 sur le site du logiciel;
2. installer l'exécutable.

Installation de `netifaces` :

1. en tant qu'administrateur, dans l'invité des commandes (`Windows` + `R`, *`cmd`*, `SHIFT` + `MAJ` + `ENTER`) ou dans PowerShell (`Windows` + `X`, `A`, "`Oui`");
2. saisir `py -3 -m pip install netifaces` .



## Description de l'API

L'API est un simple script Python qui se trouve dans une machine qui est sur le même réseau que la box .evasion. Il suffit donc de lancer le script (**sans** les droits de l'administrateur) avec les options souhaitées.

`py .\evasion.py -h` lance l'aide de l'API et affiche toutes les options disponibles :

##### Remarque : `py` peut-être remplacé par `py -3` sous Windows et par `python3` sous Linux qui ne connait pas cette commande.

> PS C:\User\chemin_vers_API> py .\\evasion.py -h
> usage: evasion.py [-h] [-v] [-f] [-s] [-a ADDRESS] [-p PORT]
>                   [-c COMMAND [COMMAND ...]] [-ch CHANNEL]
>                   [-cv CONVERT_COMMAND [CONVERT_COMMAND ...]] [-lc]
>
> optional arguments:
>   -h, --help            show this help message and exit
>   -v, --verbose         increase output verbosity
>   -f, --find            return a list of potential .evasion boxes.
>   -s, --status          return 'success' if the command has been send else it
>                         return 'fail'.
>   -a ADDRESS, --address ADDRESS
>                         IP address of the .evasion box
>   -p PORT, --port PORT  port of the .evasion box, default is 5900 [optional]
>   -c COMMAND [COMMAND ...], --command COMMAND [COMMAND ...]
>                         command to send to the .evasion box (the command is
>                         checked), name of the command and value are accepted
>   -ch CHANNEL, --channel CHANNEL
>                         send the command to the .evasion box to change the
>                         channel (must be an integer)
>   -cv CONVERT_COMMAND [CONVERT_COMMAND ...], --convert_command CONVERT_COMMAND [CONVERT_COMMAND ...]
>                         convert a valid command from name to value or from
>                         value to name
>   -lc, --list_commands  display the list of known commands



### Liste des options

- -h, --help : affiche l'aide du programme et le quitte;
- -v, --verbose : permet au programme d'afficher plus d'informations lors de son exécution;
- -f, --find : permet d'effectuer une recherche de la box .evasion en se basant sur l'ouverture du port utilisé pour le protocole [RFB](https://fr.wikipedia.org/wiki/Remote_Frame_Buffer) et en effectuant une connexion ainsi qu'un *handshake* typique à la box;
- -s, --status : permet de savoir si l'envoie de la commande a bien eu lieu (on ne sait cependant pas si elle sera prise en compte par la box);
- -a, --address : permet de spécifier l'adresse vers laquelle envoyer la commande;
- -p, --port : permet de changer le port de destination (par default, le port 5900 est le port utilisé et **il ne sert donc à rien de fournir une valeur**);
- -c,  --command : permet de spécifier la commande (nom ou valeur) à envoyer à la box (voir **liste des commandes**), le programme n'est pas sensible à la casse;
- -ch, --channel : permet de changer de chaîne en envoyant un entier (seul la valeur absolue est prise en compte);
- -cv, --convert_command : permet de convertir une commande en son nom ou en sa valeur;
- -lc, --list_commands : affiche la liste des commandes connues.

A priori, les options qui nous intéresse le plus sont -a, -c, -s, -f et -lc. L'option -v est plus destinée à réalisé du débogue, -cv n'est pas vraiment utile.



### Liste des commandes

| Nom de la commande | Valeur |
| ------------------ | ------ |
| REMOTE_0           | 58112  |
| REMOTE_1           | 58113  |
| REMOTE_2           | 58114  |
| REMOTE_3           | 58115  |
| REMOTE_4           | 58116  |
| REMOTE_5           | 58117  |
| REMOTE_6           | 58118  |
| REMOTE_7           | 58119  |
| REMOTE_8           | 58120  |
| REMOTE_9           | 58121  |
| FAST_REVERSE       | 58375  |
| FAST_FORWARD       | 58373  |
| PLAY               | 58368  |
| MUTE               | 57349  |
| STAND_BY           | 57344  |
| STOP               | 58370  |
| RECORD             | 58371  |
| TV                 | 57360  |
| VOD                | 61224  |
| GUIDE              | 57355  |
| INFO               | 57358  |
| MY_RECORDINGS      | 61235  |
| VIDEO_WALL         | 61234  |
| APPLICATION        | 57352  |
| BE_ON_DEMAND       | 61236  |
| BACK               | 57346  |
| HOME               | 61184  |
| VOL_UP             | 57347  |
| VOL_DOWN           | 57348  |
| UP                 | 57600  |
| DOWN               | 57601  |
| LEFT               | 57602  |
| RIGHT              | 57603  |
| RED_KEY            | 57856  |
| BE_TV              | 57359  |
| OK                 | 57345  |



## Utilisation de l'API

Démonstration des fonctionnalités de l'API.

### Scan du réseau

`py .\evasion.py -f -v` lance un scan du réseau en mode *verbose* depuis l'hôte sur lequel le script est exécuté. L'interface réseau par défaut est utilisée, ensuite, les adresses IP du réseau sont calculés pour finalement être analysées par différents process.

> PS C:\User\chemin_vers_API> py .\\evasion.py -f -v
> Verbosity turned on.
>
> Arguments:
>
> 'verbose': True
> 'find': True
> 'status': False
> 'port': 5900
> 'command': None
> 'raw_command': None
> 'convert_command': None
> 'list_commands': False
>
> Start scanning network (this is a CPU intensive task, which needs the 'netifaces' module):
> 192.168.0.0/24
> Pool size (max=256): 200
> ['192.168.0.15']
> Scan is done
> Potential .evasion box:
> IP: 192.168.0.15

`py .\evasion.py -f` idem ici, mais sans toutes les informations apportées par l'option *verbose*.

> PS C:\User\chemin_vers_API> py .\\evasion.py -f
> Start scanning network (this is a CPU intensive task, which needs the 'netifaces' module):
> Potential .evasion box:
> IP: 192.168.0.15

### Affichage de la liste des commandes

`py .\evasion.py -lc` affiche la liste des commandes connues.

> PS C:\User\chemin_vers_API> py .\\evasion.py -lc
> APPLICATION = 57352
> BACK = 57346
> BE_ON_DEMAND = 61236
> BE_TV = 57359
> DOWN = 57601
> FAST_FORWARD = 58373
> FAST_REVERSE = 58375
> GUIDE = 57355
> HOME = 61184
> INFO = 57358
> LEFT = 57602
> MUTE = 57349
> MY_RECORDINGS = 61235
> OK = 57345
> PLAY = 58368
> RECORD = 58371
> RED_KEY = 57856
> REMOTE_0 = 58112
> REMOTE_1 = 58113
> REMOTE_2 = 58114
> REMOTE_4 = 58116
> REMOTE_6 = 58118
> REMOTE_7 = 58119
> REMOTE_8 = 58120
> REMOTE_9 = 58121
> RIGHT = 57603
> STAND_BY = 57344
> STOP = 58370
> TV = 57360
> UP = 57600
> VIDEO_WALL = 61234
> VOD = 61224
> VOL_DOWN = 57348
> VOL_UP = 57347

### Conversion de commandes

`py .\evasion.py -cv NOM_COMMANDE_OU_VALEUR_1 [NOM_COMMANDE_OU_VALEUR_2] [...]`  permet de convertir un nom ou une valeur de command en sa valeur ou en son nom.

> PS C:\User\chemin_vers_API> py .\\evasion.py -cv tv
> 57360
> PS C:\User\chemin_vers_API> py .\\evasion.py -cv 57600
> UP

### Envoie de commandes

`py .\evasion.py -a 192.168.0.x -c NOM_COMMANDE_OU_VALEUR_1 [NOM_COMMANDE_OU_VALEUR_2] [...]` où `192.168.0.x` est l'adresse IP de votre box .evasion (pensez à lui imposer une IP fixe sur base de son adresse MAC depuis le modem VOO).

Veuillez noter que cette commande ne retourne rien. L'utilisation de l'option `-s` est donc une bonne option si vous souhaitez avoir un retour sur le statut de l'envoie ("Success"/"Fail").

### Changer de chaîne

`py .\evasion.py -a 192.168.0.x -ch NUMÉRO_DE_CHAÎNE`, tout comme la commande précédente il n'y a aucun retour et l'option `-s` peut être utilisée de la même manière.