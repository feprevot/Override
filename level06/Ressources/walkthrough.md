# Level06 — Walkthrough

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

```python
login = "qordoux"
h = (ord(login[3]) ^ 0x1337) + 0x5eeded
for c in login:
    h += (ord(c) ^ h) % 0x539
print(h & 0xFFFFFFFF)   # unsigned 32 bits comme en C
# → 6233773
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
