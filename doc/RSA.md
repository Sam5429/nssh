# RSA

## Principe

RSA est un algorithme de chiffrement asymétrique. Cela signifie que le processus de chiffrement et de déchiffrement n'est pas symétrique (on ne fait pas la même chose dans les deux sens). Le grand avantage de RSA est qu'il n'est pas nécessaire de s'accorder sur un secret commun pour chiffrer un message, contrairement à des algorithmes comme AES. Cela permet d'envoyer un premier message pour s'accorder sur une clé secrète et commencer à utiliser AES, qui est beaucoup plus rapide.

## Attention

Le but ici est de vulgariser le concept. Il manque donc de nombreux détails arithmétiques, mais cela reste une bonne base pour comprendre les principes fondamentaux de l'implémentation.

## Exemple avec Léo et Léa

Imaginons deux personnages : Léo et Léa. Léo et Léa sont amoureux et souhaitent s'envoyer des messages d'amour. Ils ne veulent évidemment pas que leurs messages tombent entre de mauvaises mains.
Léo et Léa ont un autre problème : ils sont loin l'un de l'autre et n'ont pas convenu d'un secret commun avant de se séparer. Maintenant qu'ils sont loin, il est impossible de s'accorder sur un secret sans qu'un potentiel espion ne les écoute !

Mais par chance, Léa propose une solution :

1. **Choix des nombres premiers** : Léa choisit un entier $n$ qui est décomposable en deux nombres premiers distincts $p$ et $q$.
2. **Calcul des clés** : À partir de ces deux nombres, elle calcule $e$ qui est premier avec $(p-1)(q-1)$ et $d$, l'inverse modulaire de $e$.
3. **Envoi des clés publiques** : Léa envoie $n$ et $e$ à Léo.
4. **Chiffrement du message** : Léo chiffre son message $m$ en calculant $m^e \mod n$ et envoie le résultat $c$ à Léa.
5. **Déchiffrement du message** : Léa déchiffre le message en calculant $c^d \mod n$ pour obtenir $m$.

Léo et Léa ont ainsi réussi à s'envoyer des messages sans que personne ne puisse lire leur contenu !

## Détails mathématiques

### Trouver des nombres premiers pour p et q

Un nombre premier est un nombre qui est divisible uniquement par 1 et par lui-même. Pour les trouver, il existe différentes méthodes :

- **Crible d'Ératosthène** :
  - Principe : Parcourir une liste de nombres de 2 à $n$ et supprimer les multiples de chaque nombre premier trouvé.
  - Exemple :
    ```
    Liste initiale : [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    Après suppression des multiples de 2 : [1, 2, 3, 5, 7, 9]
    Après suppression des multiples de 3 : [1, 2, 3, 5, 7]
    ```
    Et MAGIE 1, 2, 3, 5 et 7 sont bien premier

- **Test de Miller-Rabin** :
  - Principe : Utiliser des témoins pour vérifier si un nombre est premier.
  - Formule : Si $a^m \equiv 1 \mod n$ ou $a^{2^j \cdot m} \equiv -1 \mod n$, alors $n$ est probablement premier.

En pratique le crible n'est pas utilisable pour RSA. En effet les entiers p et q sont trop grand et la liste qu'il faudrait faire est trop grande et trop longue à créer.
De plus il suffit de peu de test pour être presque sur que un nombre est premier et c'est très rapide de prouver qu'il n'est pas premier. C'est donc bien plus efficace en pratique.

### Calcul des exposants de chiffrement e et de déchiffrement b

1. **Indicatrice d'Euler** : $\phi(n) = (p-1)(q-1)$.
2. **Choix de $e$** : $e$ doit être premier avec $\phi(n)$.
3. **Algorithme d'Euclide** pour trouver le PGCD :
    ```
    a = b * q + r
    a' = b, b' = r
    a' = b' * q' + r'
    ```
    L'algorithme s'arrête quand le reste est nul, et le PGCD est le dernier reste non nul.
4. **Algorithme d'Euclide étendu** pour trouver $d$ :
    - Trouver $d$ tel que $e \cdot d \equiv 1 \mod \phi(n)$.

Top maintenant on sait comment faire pour trouver nos module mais il reste une question. C'est quoi cette indicatrice d'euler et pourquoi on s'en sert ?

### Théorème d'Euler

Le théorème d'Euler nous dit que pour $n$ premier et $a$ premier avec $n$, alors $a^{\phi(n)} \equiv 1 \mod n$.

- **Application à RSA** :
	$$
  e \cdot d \equiv 1 \mod \phi(n)
  m^{e \cdot d} = m^{\phi(n) \cdot k} \cdot m

  En appliquant le théorème d'Euler :

  m^{e \cdot d} \equiv 1^k \cdot m \mod n
  m^{e \cdot d} \equiv m \mod n
  $$

Et c'est donc grâce à ce théorème que nous pouvons prouver que, après avoir élevé le message à la puissance $e$ puis $d$, nous retrouvons bien le message d'origine !
