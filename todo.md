- [ ] client / serveur crypter
  - [ ] chiffrer les donné
  - [ ] co et se déco


Objectif :nerd_face: :
	Créer une clé AES -> Envoie via RSA
	Taper des commandes en ligne de commande et les chiffrer avec AES pour les envoyer.
generate rsa session key
create a aes session key and exchange
auth : client (username + password / rsa key) server (fingerprint)

oommunication with Message Auth Code (hash of aes session key + message)


for security: rsa session key -> exchange aes session key
for auth: user -> login / password, server -> fingerprint
for ...: MAC

generate a rsa key + 8 bytes random
send to each other the 8 bytes and add them (server first)
start auth => server send it fingerprint if client ok send it login / password
start communication


algo :

M bloc de taille fix et on met du padding si besoin
H0 = constante

fonction de compressions prend bloc de 512 -> 64 bloc de 32 bits et haché intermédiaire de 256 bits

fonction de tour :
32 bit (un des bloc du message) puis on découpe le haché de 256 en 8 bloc de 32 bits
[1..3] ch(e,f,g) = (e&f)+(-e&g)
+ h
3 sigma1(e) = (e>>6)^(e>>11)^(e>>25)
+ h
+ bloc message
+ K qui dépend du tour
+ 4
[5..7] maj(e,f,g) = (e&f)+(e&g)+(f&g)
+ h
7 sigma0(a) = (a>>2)^(a>>13)^(a>>22)
shift left de 1 bloc (le premier deviens dernier)
