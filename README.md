# VOO-Evasion-API (avant la mise à jour VOO TV+)

# Avertissement
Avant de commencer, notez quelques points:
> Toutes les informations fournies ici sont fournies «telles quelles» et «telles que disponibles» et vous acceptez d'utiliser ces informations entièrement à vos risques et périls. En aucun cas, je ne serai tenu pour responsable de quelque manière que ce soit des dommages, pertes, dépenses, coûts ou responsabilités de quelque nature que ce soit résultant de votre utilisation des informations et documents présentés ici.

> Je ne suis pas un ingénieur, mais j’ai quelques connaissances qui me permettent pour comprendre le fonctionnement. Toutefois, si vous connaissez une meilleure alternative, merci de me le faire savoir. Je serai plus qu'heureux d'apprendre de nouvelles choses!
Après ces petites mondanités plus que nécessaires pour ne pas être tenues comme responsables de vos agissements, passons aux choses sérieuses.


# Mon approche
Voici la méthodologie que j'ai suivie:
1.	Effectuer un reverse engineering pour comprendre le fonctionnement du système de contrôle de la box évasion.
2.	Trouver un moyen d'envoyer les signaux de contrôle sans utiliser la télécommande ou l'application.
3.	Créer un programme pour faire le job précédent de façon automatisée.

## 1 Comprendre le fonctionnement
Si on identifie les possibilités de contrôler la box évasion, il y a deux moyens, la télécommande ou l'application voomotion.

La télécommande à première vue fonctionne avec des signaux Rf et non via des signaux Ir. Ne voulant un n ème boîtier dans la maison je ne choisis pas cette solution, mais cette approche pourrait convenir à certains d'entre vous.

Donc là solution restante est l'application mobile. Bien évidemment, si vous avez besoin de comprendre le fonctionnement de communication entre deux appareils, il faut trouver le protocole qu'ils utilisent pour communiquer. Pour cela rien de mieux qu'analyser le réseau avec wireshark ou packet ne capture sur mobile. Dans mon cas j'ai utilisé les deux ce qui m'a permis de trouver d'autres fonctionnalités si vous voulez que j'en parle demandées  . Pour plus de facilité, je vous expose la solution la plus rapide qui est via l'application packet capture.
Voici un exemple de message capturé : 
```
--> Received : 52 46 42 20 30 30 33 2e   30 30 38 0a
<-- Sent : 52 46 42 20 30 30 33 2e 30   30 38 0a
--> Received : 01 01
<-- Sent : 01
--> Received : 00 00 00 00
<-- Sent : 01
--> Received : 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
<-- Sent : 04 01 00 00 00 00 e0 03   04 00 00 00 00 00 e0 03
```

Si l'on cherche un peu sur le net, nous trouvons que cela fait référence au protocole [RFB](https://vncdotool.readthedocs.io/en/0.8.0/rfbproto.html) et il fonctionne avec des sockets. Un peu violent comme solution mais c'est fonctionnelle.

Le protocole RFB a besoin de vérifier la connexion avant de pouvoir lui envoyer un message. Cette vérification est représentée par les 3 premiers échanges et la box évasion renvoi une suite de 00 pour signifier qu’elle attend une commande qui est notre dernier « sent ». Pour l’envoi de la commande, nous remarquons que nous avons deux fois la même séquence, mais avec un bit de différence qui signifie appuyer sur une touche puis relâcher cette touche. 

## 2. Envoyer manuellement un signal
Avant d'automatiser tout cela, essayons d'abord de tester notre approche manuellement.
Pour cela rien de plus simple, je prends les messages précédents capturés et je le rejoue...

![Alt Text](https://media.giphy.com/media/nXxOjZrbnbRxS/giphy.gif)

| Amazing je vois le volume descendre de la box évasion. |

Bon on a réussi à réduire le son, mais je me voyais mal capturer toutes les possibilités et les rejouer quand j'en avais besoin. Je voulais rendre cela un peu plus intelligent et l'automatiser.

## 3. Automatiser par la programmation
Afin de ne pas capturer toutes les possibilités de message, j'ai décidé de m'attaquer à la décompilation de l'application.
Énormément de code, mais j'ai identifié les fichiers qui peut nous intéresser. 
Le premier est une interface avec toutes les valeurs des boutons possibles.
```
        REMOTE_0(58112),
        REMOTE_1(58113),
        REMOTE_2(58114),
        REMOTE_3(58115),
        REMOTE_4(58116),
        REMOTE_5(58117),
        REMOTE_6(58118),
        REMOTE_7(58119),
        REMOTE_8(58120),
        REMOTE_9(58121),
        FAST_REVERSE(58375),
        FAST_FORWARD(58373),
        PLAY(58368),
        MUTE(57349),
        STAND_BY(57344),
        STOP(58370),
        RECORD(58371),
        TV(57360),
        VOD(61224),
        GUIDE(57355),
        INFO(57358),
        MY_RECORDINGS(61235),
        VIDEO_WALL(61234),
        APPLICATION(57352),
        BE_ON_DEMAND(61236),
        BACK(57346),
        HOME(61184),
        VOL_UP(57347),
        VOL_DOWN(57348),
        UP(57600),
        DOWN(57601),
        LEFT(57602),
        RIGHT(57603),
        RED_KEY(57856),
        BE_TV(57359),
        OK(57345);
```

Le second est le code qui s'exécute quand on appuie sur l'un ou l'autre bouton de la télécommande dans l'application.
```java
        public void onClick(View view) {
            if (RemoteFragment.this.mDevice != null && Buttons.getButtonByName(view.getTag().toString()) != null) {
                RemoteFragment.this.mKey = Buttons.getButtonByName(view.getTag().toString()).getKey();
                final RFBConnection rFBConnection = new RFBConnection(RemoteFragment.this.mDevice.getSSDPPacket().getRemoteAddress(), 5900, new RFBSecurityVNC(null));
                new Thread(new Runnable() {
                    public void run() {
                        try {
                            rFBConnection.connect();
                            rFBConnection.sendKey(RemoteFragment.this.mKey);
                        } catch (Throwable e) {
                            ThrowableExtension.printStackTrace(e);
                        } catch (Throwable e2) {
                            ThrowableExtension.printStackTrace(e2);
                        }
                    }
                }).start();
            }
        }
```

Passons la connexion, ce qui nous intéresse c’est l’envoi de commande. Dans ces fonctions "i" représente le code de la touche repris dans l'interface ci-dessus.
```java
    public void sendKey(int i) throws IOException {
        sendKeyDown(i);
        sendKeyUp(i);
    }

    private void sendKeyDown(int i) throws IOException {
        write(new byte[]{(byte) 4, (byte) 1, (byte) 0, (byte) 0, (byte) ((i >> 24) & 255), (byte) ((i >> 16) & 255), (byte) ((i >> 8) & 255), (byte) (i & 255)});
    }

    private void sendKeyUp(int i) throws IOException {
        write(new byte[]{(byte) 4, (byte) 0, (byte) 0, (byte) 0, (byte) ((i >> 24) & 255), (byte) ((i >> 16) & 255), (byte) ((i >> 8) & 255), (byte) (i & 255)});
    }
```

Dans les prochains jours, je rendrais disponible mon code le temps le nettoyer un maximum.
J’espère que j’ai été un maximum compréhensible, je ne suis pas pédagogue:/
Si vous avez des questions sur l’implémentation, n’hésitez pas !

PS Le forum VOO a découpé mon post en plusieurs morceaux donc si vous remarquez qu’il manque un morceau d’explication dites-le-moi.
Lien vers le forum https://forum.voo.be/ma-box-evasion-10/api-de-la-box-evasion-7227 
