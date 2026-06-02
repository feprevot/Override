# CLAUDE.md — Projet OverRide

Contexte de travail pour Claude Code sur le dépôt de rendu du projet **OverRide** (sécurité / exploitation de binaires, cursus 42).

## Vue d'ensemble

OverRide est une série de challenges d'exploitation de binaires à résoudre dans une **machine virtuelle dédiée** (64 bits) fournie avec le sujet. Chaque niveau consiste à exploiter un binaire vulnérable pour lire le fichier `.pass` du niveau suivant, puis à passer à l'utilisateur suivant via `su`.

Progression : `level00` → `level01` → … → `level08` → (`level09`) → `end`.

**Partie obligatoire à valider : level00 à level08.**

## Environnement (rappel, ne pas reproduire dans le dépôt)

- VM 64 bits lancée depuis l'ISO du sujet.
- Accès initial : `level00:level00`.
- Connexion conseillée en SSH sur le port **4242** :
  ```
  ssh level00@<IP_VM> -p 4242
  ```
- L'IP est indiquée au démarrage. ⚠️ Le sujet mentionne deux adresses (`192.168.1.3` et `192.168.1.13`) : **vérifier l'IP réelle avec `ifconfig`** une fois connecté.
- Le `.pass` se trouve à la racine du home de chaque utilisateur (sauf `level00`).

Exemple de session attendue :
```
level0@OverRide:~$ ./level00 $(exploit)
$ cat /home/user/level01/.pass
?????????????????????
$ exit
level0@OverRide:~$ su level01
Password:
level01@OverRide:~$
```

## Structure du dépôt de rendu

Un dossier par niveau, à la racine :

```
.
├── level00/
├── level01/
├── level02/
├── ...
└── level08/
```

Contenu de chaque dossier `levelXX/` :

```
levelXX/
├── flag          # le .pass récupéré (peut être vide → justification orale requise)
├── source        # le binaire exploité sous forme lisible par un dev (code source)
└── Ressources/   # tout ce qui sert à prouver la résolution en soutenance
```

- `flag` : contenu du `.pass` du niveau. S'il est vide, une justification sera demandée en soutenance.
- `source` : version compréhensible (code source) du binaire exploité. **Le langage n'est pas imposé.**
- `Ressources/` : notes, schémas, scripts d'aide, explications de l'exploit, etc.

## Règles strictes (à respecter absolument)

1. **Aucun binaire** ne doit être présent dans le dépôt — surtout pas dans `Ressources/`.
2. **Ne jamais committer un fichier issu de l'ISO** du projet. S'il en faut un, il sera **téléchargé en soutenance**.
3. **Pas d'outil d'automatisation** pour résoudre les niveaux : c'est considéré comme de la triche → **-42**.
4. **Pas de bruteforce** des flags / mots de passe SSH (inutile, et il faut justifier en soutenance de toute façon).
5. Le dépôt ne doit contenir **que ce qui a servi** à résoudre chaque épreuve validée — rien de superflu.
6. **Tout** ce qui est dans le dépôt doit pouvoir être **expliqué sans hésitation** en soutenance, par **chaque** membre du groupe.
7. Si un logiciel externe spécifique est utilisé, prévoir un **environnement reproductible** (VM, Docker, Vagrant).
8. La correction est **humaine uniquement**.

## Ce que Claude Code peut faire ici

- Aider à **rédiger et structurer** les explications, notes et fichiers `source` (commentés, lisibles).
- Vérifier la **cohérence de l'arborescence** du rendu (un dossier par niveau, présence de `flag` / `source` / `Ressources/`).
- Relire / clarifier la documentation des résolutions pour qu'elle soit défendable en soutenance.
- Aider à écrire des **scripts d'aide** (encouragés par le sujet), à condition qu'ils restent explicables en détail et ne soient pas des outils d'automatisation de résolution.

## Ce que Claude Code ne doit PAS faire ici

- Ajouter ou générer des **binaires** dans le dépôt.
- Copier des fichiers provenant de l'**ISO** dans le dépôt.
- Produire un rendu que le groupe ne saurait pas expliquer ligne par ligne.

## Avant de committer — checklist

- [ ] Un dossier par niveau validé (`level00` … `level08`).
- [ ] Chaque dossier contient `flag`, `source`, `Ressources/`.
- [ ] Aucun binaire dans le dépôt.
- [ ] Aucun fichier issu de l'ISO.
- [ ] Chaque membre sait expliquer chaque fichier.