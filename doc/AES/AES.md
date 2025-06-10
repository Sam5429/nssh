# AES (Advanced Encryption Standard)

## Principe

AES est un algorithme de chiffrement symétrique, c'est-à-dire que la même clé est utilisée pour chiffrer et déchiffrer. AES signifie Advanced Encryption Standard. Il a été standardisé par le NIST en 2001 après un processus de sélection de 5 ans.

Son objectif est de respecter au mieux les principes de Claude Shannon :
- **Confusion** : La confusion c'est rendre compliqué l'analyse du rôle de la clé dans le texte chiffré. Exemple, si nous avons une clé de 128 bits et que nous changeons un seul bit, la confusion veux que de nombreux bits du texte chiffré soit modifiés, rendant difficile la corrélation entre la clé et le texte chiffré.
- **Diffusion** : La diffusion c'est mélangé l'information de sorte que même deux message similaire ne se ressemble pas. Exemple, si nous avons le message "Bonjour" et que nous changeons le 'B' en 'b', la diffusion veux que le texte chiffré final soit complètement différent, pas seulement au début.


## L'algorithme

AES est un algorithme de chiffrement par bloc. Il découpe le message en blocs de même taille (128 bits) et les chiffre successivement.
Le principe est simple, pour chaque bloc, on effectue une série d'opérations sur le bloc, plus précisément pour une clé de 128 bits, on effectue 10 tours de chiffrement. Chaque tour consiste en plusieurs étapes qui transforment le bloc de données.

### Préprocessing
La première étape de AES est de découper le message en blocs de 128 bits. Pour le dernier bloc, s'il ne fait pas 128 bits, on ajoute du padding avec des 0 dans les bits de poids faible.

Pour AES avec une clé de 128 bits, il faut faire 11 tours de chiffrement. À chaque tour, une nouvelle clé est utilisée, créée à partir de la clé de base. On fait ceci dans le but d'augmenté la confusion car comme chaque clé dépend de la première l'information est bien mélangé au fur et a mesure des tour de chiffrement |

Bien sur si AES consiste uniquement à ajouté 11 clé de chiffrement à un message ce n'est pas plus sécurisé que d'ajouté une clé qui est la somme de toutes les clés. C'est pourquoi en plus de l'ajout de la clé, on effectue plusieurs opérations sur le bloc de données.

### Les fonctions

| Fonction | Description | Exemple |
|----------|-------------|---------|
| **Ajout de la clé (Add Round Key)** | On fait un XOR (ou exclusif) entre la clé et le message. Mais comme dit précédement seul c'est pas efficaces. | Message : 00101100, Clé : 10101010, Résultat : 10000110 |
| **Substitution (SubBytes)** | On remplace chaque byte du message par un autre byte selon une table de substitution (S-box). Cette étape n'est pas sécurisé en elle même car la table est facilement inversible mais combiné avec l'ajout de la clé c'est sécurisé. | Byte d'entrée : 53, Byte de sortie : ED |
| **Déplacement des lignes (ShiftRows)** | On décale les lignes du bloc : Première ligne : pas de décalage, Deuxième ligne : décalage de 1 byte, Troisième ligne : décalage de 2 bytes, Quatrième ligne : décalage de 3 bytes. | Voir tableau ci-dessous |
| **Mélange des colonnes (MixColumns)** | On effectue des opérations mathématiques sur les colonnes pour mélanger les bytes. | Voir tableau ci-dessous |

Les deux dernières étapes (ShiftRows et MixColumns) sont effectuées à fin d'augmenté la diffusion. Elles permettent de mélanger les bytes entre eux pour que même si deux blocs sont similaires, le texte chiffré final soit très différent.

**Exemple ShiftRows** :

Avant ShiftRows :
|00|04|08|12|
|01|05|09|13|
|02|06|10|14|
|03|07|11|15|

Après ShiftRows :
|00|04|08|12|
|05|09|13|01|
|10|14|02|06|
|11|15|03|07|

**Exemple MixColumns** :

Avant MixColumns :
|00|05|10|11|
|04|09|14|15|
|08|13|02|03|
|12|01|06|07|

Après MixColumns :
|00|04|08|12|
|01|05|09|13|
|02|06|10|14|
|03|07|11|15|

## Limitation

Avec l'implémentation que j'ai faite, si deux bloc sont identique, le texte chiffré sera également identique. On peux remédier à cela en créant un salt déterminé à partir du bloc précédent, ou de plein d'autres méthodes. Mais pour l'instant, je n'ai pas implémenté cela.


## Resources

- Un doc qui aide pour l'implémentation technique : [FIPS AES](/AES/nist.fips.197.pdf)
- Des vidéos qui m'on aidé a comprendre l'algorithme :
	- [AES: How to Design Secure Encryption](https://www.youtube.com/watch?v=C4ATDMIz5wc)
	- [AES: How to Design Secure Encryption](https://www.youtube.com/watch?v=FAaki7d5vvY&t=806s)
