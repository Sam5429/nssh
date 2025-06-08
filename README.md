# NSSH

NSSH : Not Secure SHell :ninja:

Ce projet à pour but de faire une implémentation simplifié du protocole ssh.
Pour se faire je me suis amusé a recoder **RSA**, **AES** et **SHA256**. On va donc voir comment fonctionne ssh (très simplifié) et comment fonctionne chacun de c'est algo.

Le code est commenté et documenté, merci de me dire si vous avez des remarques ou des conseils (c'est mon premier projet en rust).
Vous trouverez ici des explication sur : [RSA](doc/RSA.md), [AES](doc/AES.md) et [SHA256](doc/SHA256.md).

## Objectif :nerd_face:

1. **Vulgarisation** : Le but c'est d'apprendre à vulgariser des concepts mathématiques et informatiques.
2. **Apprendre le rust** : Faire un projet pour mettre en pratique un peu de rust.

## SSH c'est quoi ?

SSH (Secure SHell), c'est un protocole de communication super sécurisé, créé en 1995. Avant SSH, les données voyageaient en clair sur le réseau. Genre, si quelqu'un interceptait tes paquets, il pouvait tout lire tranquillement. Bref, c'était pas l'idéal pour garder tes infos privées.

L'objectif de SSH, c'est justement de mettre une couche de protection sur tes données. Comme ça, seul ton pote peut voir ce que t'envoies. Mais c'est encore plus balèze que ça ! Avec SSH, t'as trois garanties :

- T'es sûr que tu parles bien à ton pote (authentification)
- Personne peut lire ce que t'envoies (confidentialité)
- T'es sûr que le message a pas été modifié en route (intégrité)

En langage technique, on dit que SSH assure l'authentification, la confidentialité et l'intégrité. Ouais, c'est pas mal comme promesse !

Pour faire ça, y a plusieurs étapes :
1. On crée un canal bien chiffré
2. On authentifie le serveur et le client

La première étape, c'est la plus compliquée parce que c'est là qu'il y a toutes les maths. Pour sécuriser l'échange, faut faire un peu de cryptographie.


## La cryptographie, c'est quoi ?

La cryptographie, c'est l'art de sécuriser les communications. Et pour faire ça tout repose sur le secret.

Que ce soit avec :
- Un vieux code comme celui de César
- Ou un algorithme moderne comme AES

Toutes ces méthodes reposent sur un secret partagé entre les deux parties. Mais voilà le problème : comment se mettre d'accord sur ce secret quand on communique sur un réseau où tout le monde peut lire vos messages ?

### La solution : la crypto asymétrique

Des chercheurs du MIT ont trouvé la solution avec la cryptographie asymétrique. Le principe ?
- La clé pour chiffrer ≠ la clé pour déchiffrer
- Tu peux envoyer ta clé publique à tout le monde
- Seul celui qui a la clé privée correspondante peut déchiffrer

C'est le principe de [RSA](doc/RSA.md), et c'est super pratique !

## Comment on s'en sert ?

Cette partie est propre a mon implémentation de SSH et peu changer d'une implémentation à l'autre. Par exemple on peu se servir d'autre algorithme de chiffrement asymétrique comme Rabin.

Mais voici les étapes pour s'échanger la clé qui va chiffré tout le reste des échanges.
1. **Génération de clé RSA**: On génére une clé RSA qui va nous servir à échanger la clé AES
2. **Echange de clé public**: le client et le serveur s'envoie leur clé public.
3. **Echange de clé AES**: Le serveur génére une clé AES et l'envoie au client, le client lui renvoie la clé AES qu'il a reçut. De cette manière on est sur que la clé que le client a reçu est celle qu'on a envoyer et que personne n'a intercepté le message pour le changer. 
2. **Chiffrement des données** : Une fois la clé échangée, on utilise AES pour tout chiffrer. On se sert plutôt de AES car RSA est beaucoup plus lent surtout sur des grands volume de données.

## L'intégrité : la dernière brique de SSH

Pour garantir l'intégrité des messages, rien de plus simple :
1. On envoie le message dans un paquet
2. Dans un second paquet, on envoie un hash spécial :
   - Ce hash est calculé à partir du message original
   - Il est combiné avec la clé de session
3. Résultat : impossible pour un intrus de modifier le message sans être détecté
   - Si quelqu'un modifie le message, le hash ne correspondra plus
   - On détecte immédiatement la modification
   - Et on peut réagir en conséquence (en ignorant le message par exemple)

## L'authentification : être sûr de parler à la bonne personne

Dernière étape cruciale : vérifier l'identité de ton interlocuteur. Pour ça, SSH utilise :
- Des certificats numériques
- Ou des empreintes de clés publiques

Comme ça, t'es sûr à 100% que tu parles bien à ton pote, et pas à un imposteur !

