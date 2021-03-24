[Livrables](#livrables)

[Échéance](#échéance)

[Travail à réaliser](#travail-à-réaliser)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 Sécurité WEP

> Etudiants : Gabriel Roch (g-roch) et Cassandre Wojciechowski (CassandreWoj)
>
> Date : 18.03.2021

### Pour cette partie pratique, vous devez être capable de :

* Déchiffrer manuellement des trames WEP utilisant Python et Scapy
* Chiffrer manuellement des trames WEP utilisant Python et Scapy
* Forger des fragments protégés avec WEP afin d’obtenir une keystream de longueur plus grande que 8 octets


Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). 


## Travail à réaliser

### 1. Déchiffrement manuel de WEP

**Dans cette partie, vous allez récupérer le script Python [manual-decryption.py](files/manual-decryption.py). Il vous faudra également le fichier de capture [arp.cap](files/arp.cap) contenant un message arp chiffré avec WEP et la librairie [rc4.py](files/rc4.py) pour générer les keystreams indispensables pour chiffrer/déchiffrer WEP. Tous les fichiers doivent être copiés dans le même répertoire local sur vos machines.**

- **Ouvrir le fichier de capture [arp.cap](files/arp.cap) avec Wireshark**
- **Utiliser Wireshark pour déchiffrer la capture. Pour cela, il faut configurer dans Wireshark la clé de chiffrement/déchiffrement WEP (Dans Wireshark : Preferences&rarr;Protocols&rarr;IEEE 802.11&rarr;Decryption Keys). Il faut également activer le déchiffrement dans la fenêtre IEEE 802.11 (« Enable decryption »). Vous trouverez la clé dans le script Python [manual-decryption.py](files/manual-decryption.py).**
- **Exécuter le script avec `python manual-decryption.py`**
- **Comparer la sortie du script avec la capture text déchiffrée par Wireshark**
- **Analyser le fonctionnement du script**

> Résultat donné par le script : 

```bash
$ python3 manual-decryption.py 

Text: aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8
icv:  cc88cbb2
icv(num): (3431517106,)
```

> Résultat donné par Wireshark : 

![](images/SWI_ex1_right.png)

Le corps du message est identique entre celui déchiffré par la commande et celui déchiffré directement dans `wireshark`. L'ICV affiché par la commande est déchiffré et celui que `wireshark` affiche est chiffré, d'où la différence. 

> Fonctionnement du script : 

Le script lit le fichier .cap et récupérer le premier paquet de la capture. On calcule la graine RC4 (`seed`) avec le vecteur d'initialisation et la clé. Il récupère ensuite l'ICV chiffré puis le message complet chiffré en séparant les deux champs qui ont été concaténés. 
On déchiffre le message complet chiffré avec RC4 avec la `seed` comme clé. Les 4 derniers bytes du message en clair correspondent à l'ICV déchiffré, elles sont donc stockées dans une variable et on les supprime du message en clair. 

### 2. Chiffrement manuel de WEP

**Utilisant le script [manual-decryption.py](files/manual-decryption.py) comme guide, créer un nouveau script `manual-encryption.py` capable de chiffrer un message, l’enregistrer dans un fichier pcap et l’envoyer.
Vous devrez donc créer votre message, calculer le contrôle d’intégrité (ICV), et les chiffrer (voir slides du cours pour les détails).**


### Quelques éléments à considérer :

- **Vous pouvez utiliser la même trame fournie comme « template » pour votre trame forgée (conseillé). Il faudra mettre à jour le champ de données qui transporte le message (`wepdata`) et le contrôle d’intégrite (`icv`).**
- **Le champ `wepdata` peut accepter des données en format text mais il est fortement conseillé de passer des bytes afin d'éviter les soucis de conversions.**
- **Le champ `icv` accepte des données en format « long ».**
- **Vous pouvez vous guider à partir du script fourni pour les différentes conversions de formats qui pourraient être nécessaires.**
- **Vous pouvez exporter votre nouvelle trame en format pcap utilisant Scapy et ensuite, l’importer dans Wireshark. Si Wireshark est capable de déchiffrer votre trame forgée, elle est correcte !**

Sur la capture d'écran ci-dessous, on peut constater que le fichier `test.cap` est ouvert et déchiffré dans `wireshark`. La trame est légèrement différente de celle fournie en exemple au début du laboratoire, car nous avons modifié l'adresse MAC de l'envoyeur : celle-ci était avant "90:27:..." et est maintenant "92:27:...".

La trame créée dans notre script `manual-encryption.py` est donc bien reconnue par `wireshark` comme une trame `arp` et est correctement déchiffrée avec la clé. 

![](images/SWI_ex2.png)


### 3. Fragmentation

**Dans cette partie, vous allez enrichir votre script développé dans la partie précédente pour chiffrer 3 fragments.**

### Quelques éléments à considérer :

- **Chaque fragment est numéroté. La première trame d’une suite de fragments a toujours le numéro de fragment à 0. Une trame entière (sans fragmentation) comporte aussi le numéro de fragment égal à 0**
- **Pour incrémenter le compteur de fragments, vous pouvez utiliser le champ « SC » de la trame. Par exemple : `trame.SC += 1`**
- **Tous les fragments sauf le dernier ont le bit `more fragments` à 1, pour indiquer qu’un nouveau fragment va être reçu**
- **Le champ qui contient le bit « more fragments » est disponible en Scapy dans le champ `FCfield`. Il faudra donc manipuler ce champ pour vos fragments. Ce même champ est visible dans Wireshark dans IEEE 802.11 Data &rarr; Frame Control Field &rarr; Flags**
- **Pour vérifier que cette partie fonctionne, vous pouvez importer vos fragments dans Wireshark, qui doit être capable de les recomposer**
- **Pour un test encore plus intéressant (optionnel), vous pouvez utiliser un AP (disponible sur demande) et envoyer vos fragments. Pour que l’AP accepte vos données injectées, il faudra faire une « fake authentication » que vous pouvez faire avec `aireplay-ng`**
- **Si l’AP accepte vos fragments, il les recomposera et les retransmettra en une seule trame non-fragmentée !**

![](images/SWI_ex3.png)

Sur la capture d'écran ci-dessus, nous constatons que la trame a été découpé en trois fragments, et le 3ème fragment est bien la trame complète recomposée : `wireshark` reconnait la trame ARP en tant que telle. 

## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

-	Script de chiffrement WEP **abondamment commenté/documenté**
  - Fichier pcap généré par votre script contenant la trame chiffrée
  - Capture d’écran de votre trame importée et déchiffrée par Wireshark
-	Script de fragmentation **abondamment commenté/documenté**
  - Fichier pcap généré par votre script contenant les fragments
  - Capture d’écran de vos trames importées et déchiffrés par Wireshark 

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 25 mars 2021 à 23h59
