# PSManager

Interface web de gestion de parc informatique Windows via PowerShell WinRM.

![PSManager Login](screenshot.png)

## Présentation

PSManager est une application Node.js permettant d'administrer à distance un parc de postes Windows depuis un navigateur. Elle s'appuie sur WinRM (port 5985) et PowerShell pour exécuter des actions sur les machines distantes.

## Fonctionnalités

- **Exécution de scripts PowerShell** en masse avec parallélisme configurable
- **Extinction / Redémarrage** individuel ou par groupe (parallélisme configurable)
- **Wake-on-LAN** — envoi de magic packet UDP
- **Planification** — tâches différées (script, reboot, shutdown, WOL)
- **Copie de fichiers** vers les postes distants
- **Explorateur de fichiers** distant
- **Éditeur de registre** distant
- **Terminal PowerShell** interactif (xterm.js)
- **Scan réseau** — découverte automatique des postes
- **Inventaire** — collecte automatique (CPU, RAM, disque, logiciels, garantie...)
- **Sessions utilisateurs** — visualisation des sessions actives par groupe
- **Rapport CSV** exportable
- **LLDP** — identification du port switch d'un poste
- **Aspiration / déploiement de drivers**
- **Historique des logins**
- Thème clair / sombre

## Prérequis

- Node.js 18+
- PowerShell 5.1+ sur le serveur
- WinRM activé sur les postes cibles (`winrm quickconfig`)
- Fichier d'inventaire `parc.txt` au format pipe `|`

## Installation

```bash
git clone https://github.com/supergonzales-byte/psmanager.git
cd psmanager
npm install
node server.js
```

L'interface est accessible sur `http://localhost:3000`.

## Configuration

Le fichier de parc est attendu par défaut à `C:\ps-manager\inventaire\parc.txt`.  
Les scripts PowerShell doivent être placés dans `C:\ps-manager\scripts\`.  
Les utilisateurs autorisés sont définis dans `users.json` (généré au premier lancement).

## Stack

- **Backend** : Node.js, Express, node-schedule, ws, node-pty, ldapjs
- **Frontend** : HTML/CSS/JS vanilla, xterm.js
- **Remoting** : PowerShell WinRM (`Invoke-Command`, `Copy-Item -ToSession`)
