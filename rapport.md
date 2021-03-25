# Sécurité des réseaux sans fil

## Laboratoire 802.11 Sécurité WEP

**Auteurs: Michaël da Silva, Nenad Rajic**

### 1. Déchiffrement manuel de WEP

![](images/1_wireshark_decode.PNG)

![](images/1_decoder.PNG)

### 2. Chiffrement manuel de WEP

![](images/2_encoder.PNG)

Le message est bien celui que nous avons défini et l'ICV est correct. Pour que le message fonctionne, il faut qu'il contienne 36 caractères/octets.


### 3. Fragmentation

![](images/3_fragmented.PNG)

On a bien un paquet divisé en 3.

![](images/3_fragmented_reassembled.PNG)

On peut alors avec le dernier paquet réassembler le tout et lire le contenu.