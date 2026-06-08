# Level06 — Walkthrough

**Objectif :** reconstruire l'algorithme de hachage du login pour calculer le serial exact attendu par `auth()` — pas de faille mémoire, on reverse l'algo et on entre le bon serial pour déclencher le shell.

## Analyse du binaire

Le programme demande un **login** (chaîne) et un **serial** (entier non signé).  
La fonction `auth()` calcule un hash à partir du login et le compare au serial saisi.  
Si les deux correspondent, un shell `/bin/sh` est lancé avec les droits de level07 (setuid).

### Algorithme de hachage

```c
hash = (login[3] ^ 0x1337) + 0x5eeded;

for each char c in login:
    hash += (c ^ hash) % 0x539;   // 0x539 = 1337
```

### Contraintes

- Login minimum 6 caractères (max 32).
- Aucun caractère de contrôle (< 0x20) accepté.
- Anti-debug : `ptrace(PTRACE_TRACEME)` — bloque gdb/strace.  
  Sans traceur le programme continue normalement, ça ne pose aucun problème.

## Vulnérabilité

Il n'y a pas de buffer overflow. L'algorithme de hachage est **déterministe et lisible** dans le source : on peut calculer le serial attendu pour n'importe quel login sans jamais avoir besoin de débugger le binaire.

## Exploit

On simule l'algorithme en Python pour un login choisi, puis on entre le login et le serial calculé dans le binaire.

Le script `serial.py` dans `Ressources/` contient l'algorithme. Pour l'utiliser, changer la variable `login` si besoin puis le lancer :

```bash
python3 Ressources/serial.py
# Login:  qordoux
# Serial: 6233773
```

## Session

```
level06@OverRide:~$ ./level06
-> Enter Login: qordoux
-> Enter Serial: 6233773
Authenticated!
$ whoami
level07
```
