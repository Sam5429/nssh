# RSA

## Principe

RSA est un algorithme de chiffrage asymétrique. C'est à dire que le chiffrement et le déchiffrement ne sont symétrique (on fait pas le même truc). Le gros avantage de RSA c'est qu'il n'y a pas desoin de se mettre d'accord sur un secret pour chiffré un message comme dans AES par exemple. Ce que permet donc d'envoyer un premier message pour se mettre d'accord sur une clé secret et pouvoir commencer a utiliser AES qui est beaucoup plus rapide.\*

## Outils utiliser

**Indicatrice d'Euler** :

- φ(n) est concrètement le nombre d’entiers m, tels que 0 < m < n, et
  pgcd(m, n) = 1.
- Pour un nombre premier p, φ(p) = p − 1.
- Si p et q sont des nombres premiers distincts, et n = pq, alors φ(n) = (p − 1)(q − 1)
- Mais le comportement (et le calcul) général de φ(n) n’est ni simple, ni régulier : il dépend
  de la décomposition en facteurs premiers de n.

## Algorithme

Comme je l'ai déjà dit RSA est un algorithme asymétrique, mais quesque ça veut dire.

Ca veut dire que l'un va chiffré le message avec un truc et l'autre le déchiffré avec un autre truc.
Mais c'est quoi c'est truc allez vous me demander ?
Et bien c'est tout simplement des nombres. Mais comme vous vous en doutez c'est nombre sont particulier.
Allons voir de plus prêt se qu'ils ont de particulier.

1. Création des clé

- n = p \* q avec p et q premier et distinct
- on calcule φ(n) = (p-1)(q-1) et on choisi un nombre e premier et inférieur à φ(n)
- on calcule d son inverse modulaire (en gros e\*d est congru à 1 modulo φ(n))

on a donc nos deux clé

- la clé public (n, e)
- la clé pricé (p, q, d)
