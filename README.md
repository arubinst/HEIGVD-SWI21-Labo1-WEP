[Livrables](#livrables)

[Échéance](#échéance)

[Travail à réaliser](#travail-à-réaliser)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 Sécurité WEP

__A faire en équipes de deux personnes__

### Pour cette partie pratique, vous devez être capable de :

* Déchiffrer manuellement des trames WEP utilisant Python et Scapy
* Chiffrer manuellement des trames WEP utilisant Python et Scapy
* Forger des fragments protégés avec WEP afin d’obtenir une keystream de longueur plus grande que 8 octets
w
Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). 


## Travail à réaliser

### 1. Déchiffrement manuel de WEP

Dans cette partie, vous allez récupérer le script Python [manual-decryption.py](files/manual-decryption.py). Il vous faudra également le fichier de capture [arp.cap](files/arp.cap) contenant un message arp chiffré avec WEP et la librairie [rc4.py](files/rc4.py) pour générer les keystreams indispensables pour chiffrer/déchiffrer WEP. Tous les fichiers doivent être copiés dans le même répertoire local sur vos machines.

- Ouvrir le fichier de capture [arp.cap](files/arp.cap) avec Wireshark
  
- Utiliser Wireshark pour déchiffrer la capture. Pour cela, il faut configurer dans Wireshark la clé de chiffrement/déchiffrement WEP (Dans Wireshark : Preferences&rarr;Protocols&rarr;IEEE 802.11&rarr;Decryption Keys). Il faut également activer le déchiffrement dans la fenêtre IEEE 802.11 (« Enable decryption »). Vous trouverez la clé dans le script Python [manual-decryption.py](files/manual-decryption.py).

Nous avons procéder au déchiffrement de la capture comme demandé et identifié la trame d'exemple comme une trame ARP classique.

![](img/wireshark.png)

- Exécuter le script avec `python manual-decryption.py`

Nous avons executer le script comme affiché ci-dessous

![](img/script1.png)

- Comparer la sortie du script avec la capture text déchiffrée par Wireshark

La sortie du script (champ `text`) est identique à celle que nous voyons dans WireShark (capture ci-dessous) sous l'onglet "Decrypted WEP data".

![](img/wireshark2.png)

Nous n'avons pas trouvé comment vérifier l'ICV en clair depuis WireShark, cependant nous avons décidé de modifier le script en ajoutant une instruction pour afficher la valeur de `icv_encrypted` et nous avons pu constater qu'elle correspond à ce que nous indique WireShark (capture ci-dessous).

![](img/wireshark3.png)

- Analyser le fonctionnement du script

Le fonctionnement du script est relativement straightforward, dans un premier temps ce dernier va lire la capture indiquée (`arp.cap` dans notre cas) et en extraire les trames, nous choissisons ici de nous contenter de la première.

Ensuite ce dernier va récupérer la seed pour RC4 à l'aide de l'IV et de la clé ainsi que récupérer le ICV, restorer le message chiffré en concatenant les données de la trame (champ `wepdata` avec le ICV (contrôle d'intégrité)). Puis le script va procéder au déchiffrement RC4.

Finalement le script va récupérer l'ICV en clair ainsi que le texte en clair dans deux variable différente ainsi que calculer l'ICV numérique afin d'afficher ces valeurs en sorties.

### 2. Chiffrement manuel de WEP

Utilisant le script [manual-decryption.py](files/manual-decryption.py) comme guide, créer un nouveau script `manual-encryption.py` capable de chiffrer un message, l’enregistrer dans un fichier pcap et l’envoyer.
Vous devrez donc créer votre message, calculer le contrôle d’intégrité (ICV), et les chiffrer (voir slides du cours pour les détails).


### Quelques éléments à considérer :

- Vous pouvez utiliser la même trame fournie comme « template » pour votre trame forgée (conseillé). Il faudra mettre à jour le champ de données qui transporte le message (`wepdata`) et le contrôle d’intégrite (`icv`).
- Le champ `wepdata` peut accepter des données en format text mais il est fortement conseillé de passer des bytes afin d'éviter les soucis de conversions.
- Le champ `icv` accepte des données en format « long ».
- Vous pouvez vous guider à partir du script fourni pour les différentes conversions de formats qui pourraient être nécessaires.
- Vous pouvez exporter votre nouvelle trame en format pcap utilisant Scapy et ensuite, l’importer dans Wireshark. Si Wireshark est capable de déchiffrer votre trame forgée, elle est correcte !


En utilisant notre script en annexe, nous avons pu créer une nouvelle trame sur la base de l'existante et l'extraire dans un fichier `arp2.cap` présent dans `files`. Ci-dessous notre capture ouverte dans WireShark.

![](img/wireshark4.png)


### 3. Fragmentation

Dans cette partie, vous allez enrichir votre script développé dans la partie précédente pour chiffrer 3 fragments.

### Quelques éléments à considérer :

- Chaque fragment est numéroté. La première trame d’une suite de fragments a toujours le numéro de fragment à 0. Une trame entière (sans fragmentation) comporte aussi le numéro de fragment égal à 0
- Pour incrémenter le compteur de fragments, vous pouvez utiliser le champ « SC » de la trame. Par exemple : `trame.SC += 1`
- Tous les fragments sauf le dernier ont le bit `more fragments` à 1, pour indiquer qu’un nouveau fragment va être reçu
- Le champ qui contient le bit « more fragments » est disponible en Scapy dans le champ `FCfield`. Il faudra donc manipuler ce champ pour vos fragments. Ce même champ est visible dans Wireshark dans IEEE 802.11 Data &rarr; Frame Control Field &rarr; Flags
- Pour vérifier que cette partie fonctionne, vous pouvez importer vos fragments dans Wireshark, qui doit être capable de les recomposer
- Pour un test encore plus intéressant (optionnel), vous pouvez utiliser un AP (disponible sur demande) et envoyer vos fragments. Pour que l’AP accepte vous données injectées, il faudra faire une « fake authentication » que vous pouvez faire avec `aireplay-ng`
- Si l’AP accepte vos fragments, il les recomposera et les retransmettra en une seule trame non-fragmentée !

Pour cette partie nous avons repris une part importante de notre script de l'étape d'envoi, simplement en ajoutant les détails nécessaires à la fragmentation. Nous avons suivi les instructions de la données et ajouter le champ "SC" à notre script mais également utiliser le champ FCfield, plus précisément nous avons modifié "FCfield.MF" qui correspond au flag *"More Fragments"* (voir illustration ci-dessous).

![](img/framecontrol.png)

Nous avions des problèmes de lecture des fragments que nous avons pu corriger en ajoutant l'instruction `template[RadioTap].len = None` après avoir demandé de l'aide à un autre groupe, cette dernière permet de provoquer le recalcul de la taille du paquet et que celui-ci soit interprété correctement. 

Finalement, ci-dessous la capture d'écran du résultat de l'important de notre fichier `arp3.cap` dans WireShark.

![](img/wireshark5.png)

## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

-	Script de chiffrement WEP **abondamment commenté/documenté**
  - Fichier pcap généré par votre script contenant la trame chiffrée
  - Capture d’écran de votre trame importée et déchiffré par Wireshark
-	Script de fragmentation **abondamment commenté/documenté**
  - Fichier pcap généré par votre script contenant les fragments
  - Capture d’écran de vos trames importées et déchiffrés par Wireshark 

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 25 mars 2021 à 23h59
