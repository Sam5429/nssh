# SHA256

## C'est quoi SHA256 ?

SHA256 est un algorithme de hachage cryptographique qui produit un condensé de 256 bits (32 octets) à partir d'une entrée de n'importe quelle taille.
Il est utilisé car même une modification minime de l'entrée entraîne un condensé complètement différent, ce qui le rend idéal pour garantir l'intégrité des données.
Il est notamment utiliser pour sauvegarder les mots de passe de manière sécurisée, pour vérifier l'intégrité des fichiers et pour les signatures numériques.

## Comment ça marche ?

SHA256 fonctionne en prenant un message d'entrée et en le divisant en blocs de 512 bits. Chaque bloc est ensuite traité à travers une série d'opérations mathématiques pour produire un condensé final (une sorte de bouillit d'octet qui a perdu toute structure) de 256 bits. Voici les étapes principales :

1. **Prétraitement** : Le message est complété pour que sa longueur soit un multiple de 512 bits. Cela inclut l'ajout d'un bit '1', suivi de zéros, et la longueur du message original en bits.

2. **Initialisation** : Huit variables de hachage sont initialisées avec des valeurs spécifiques.

3. **Traitement des blocs** : Chaque bloc de 512 bits est divisé en 16 mots de 32 bits. Ces mots sont étendus pour créer 64 mots de 32 bits.

4. **Fonctions de compression** : Pour chaque mot, une série de fonctions mathématiques est appliquée, y compris des opérations de rotation, de décalage et de mélange. Ces opérations sont répétées pour 64 tours, pour vraiment faire perdre toute structure.

5. **Mise à jour des variables de hachage** : Après avoir traité tous les blocs, les variables de hachage sont mises à jour pour produire le condensé final.

## Pourquoi est-ce important ?

SHA256 est crucial pour la sécurité des données car il garantit que même un petit changement dans l'entrée produira un condensé complètement différent. Cela rend difficile pour un attaquant de falsifier des données sans être détecté. De plus, SHA256 est résistant aux collisions, ce qui signifie qu'il est extrêmement improbable que deux entrées différentes produisent le même condensé.

## Ressources

- Un doc qui aide pour l'implémentation : [FIPS SHA256](./fips180-2.pdf)
- Un doc qui aide pour le débugage : [SHA256 Debug](./SHA256.pdf)
