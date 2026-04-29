# PSManager

Interface web de gestion de parc informatique Windows via PowerShell, WinRM et outils d'administration poste par poste.

![PSManager Login](screenshot.png)

## Présentation

PSManager permet d'administrer un parc de postes Windows depuis un navigateur. L'application s'appuie principalement sur WinRM/PowerShell pour exécuter des actions à distance, collecter l'inventaire, déployer des logiciels, gérer les fichiers, lancer des sessions RDP et centraliser les opérations courantes d'un parc.

Le projet est conçu pour un usage réseau interne, avec une interface responsive utilisable sur desktop comme sur smartphone.

## Fonctionnalités

- **Tableau de parc** avec groupes, recherche, état WinRM, IP/MAC, détails matériels et logiciels.
- **Scan réseau** avec résolution DNS, détection du port `5985`, annulation côté serveur et scan LLDP optionnel.
- **Inventaire WinRM** : version Windows, fabricant, modèle, numéro de série, RAM, disque, GPU, BIOS, MAC, CPU, date d'installation Windows et logiciels installés.
- **Rapports** HTML/CSV avec sélection des colonnes, export Veyon Master et historique des actions.
- **Exécution PowerShell** en masse, depuis un fichier ou un script saisi manuellement, avec parallélisme configurable.
- **Terminal PowerShell interactif** dans le navigateur via WebSocket/xterm.js.
- **Actions d'alimentation** : extinction, redémarrage et Wake-on-LAN individuel, par groupe ou planifié.
- **Planification** : script, Wake-on-LAN, redémarrage et extinction en exécution unique ou récurrente.
- **Explorateur de fichiers distant** : liste, téléchargement, upload, suppression et création de dossiers.
- **Éditeur de registre distant** pour consulter et modifier les ruches principales.
- **Installation de logiciels** `.exe` / `.msi` avec arguments silencieux mémorisés.
- **Intégration Winget** : ajout d'un package par identifiant Winget, vérification de version et mise à jour automatique des installeurs depuis les manifests `winget-pkgs`.
- **Déploiement Veyon** : gestion des fichiers requis, génération de configuration et de clés, récupération de l'installeur, déploiement distant avec suivi SSE et annulation.
- **Drivers** : aspiration de drivers depuis un poste modèle et déploiement vers des postes cibles via `pnputil`.
- **RDP** : lancement MSTSC local ou génération de fichier `.rdp` selon le contexte.
- **LLDP** : capture à la demande et intégration au scan réseau pour identifier le port switch.
- **Diagnostics poste** : DNS, espace disque, sessions utilisateurs actives et garantie Lenovo.
- **Administration** : comptes locaux, historique des logins, HTTPS, LDAP/Active Directory et token GitHub pour Winget.
- **Thèmes** : Jour, Nuit, Aurore et Couchant.

## Prérequis

- Node.js 18+
- Windows sur le serveur PSManager
- PowerShell 5.1+
- WinRM activé sur les postes cibles (`winrm quickconfig`)
- Droits administrateur sur les postes cibles pour les opérations système
- Accès réseau aux postes cibles sur le port WinRM `5985`
- Fichier de parc au format pipe `|`

Pour certaines fonctions :

- **Wake-on-LAN** : MAC renseignée dans le fichier de parc et routage/broadcast adapté au réseau.
- **Winget** : accès GitHub aux manifests `microsoft/winget-pkgs`; un `GITHUB_TOKEN` est recommandé pour éviter les limites de taux.
- **Veyon** : fichiers Veyon disponibles dans `C:\ps-manager\veyon` ou générés depuis l'interface.
- **LDAP/AD** : configuration LDAP activée depuis les paramètres si l'authentification AD ou l'import Veyon par OU est utilisé.

## Installation

```bash
git clone https://github.com/supergonzales-byte/psmanager.git
cd psmanager
npm install
npm start
```

Par défaut, l'interface est accessible sur :

- HTTP : `http://localhost:4000`
- HTTPS : `https://localhost` lorsque HTTPS est activé dans les paramètres

## Configuration

| Chemin | Rôle |
|---|---|
| `C:\ps-manager\inventaire\parc.txt` | Fichier de parc principal |
| `C:\ps-manager\inventaire\Logiciels\` | Logs et données d'inventaire |
| `C:\ps-manager\scripts\` | Scripts PowerShell disponibles dans l'interface |
| `C:\ps-manager\installers\` | Installeurs `.exe` / `.msi` déployables |
| `C:\ps-manager\Drivers\` | Dossiers de drivers par modèle |
| `C:\ps-manager\veyon\` | Installeur, configuration et clés Veyon |
| `users.json` | Utilisateurs locaux |
| `config.json` | Paramètres applicatifs |
| `installer-args.json` | Arguments silencieux des installeurs |
| `installer-meta.json` | Métadonnées d'installeurs, dont les IDs Winget |
| `schedules.json` | Tâches planifiées |
| `ssl/key.pem` et `ssl/cert.pem` | Certificats HTTPS |

Le fichier de parc utilise des champs séparés par `|`. Les données enrichies par l'inventaire sont réécrites par PSManager.

## Winget

Depuis la fenêtre d'installation de logiciels, il est possible :

- d'uploader manuellement un installeur `.exe` ou `.msi`;
- d'ajouter un package via son ID Winget, par exemple `Google.Chrome`, `Mozilla.Firefox` ou `VideoLAN.VLC`;
- d'associer un ID Winget à un installeur existant;
- de vérifier la dernière version disponible;
- de télécharger automatiquement la mise à jour et de conserver les arguments d'installation.

Le module lit les manifests du dépôt `microsoft/winget-pkgs`, choisit un installeur compatible et vérifie le SHA256 lorsqu'il est fourni. En cas de limite GitHub, définissez la variable d'environnement :

```powershell
$env:GITHUB_TOKEN="votre_token_github"
npm start
```

## Veyon

Le déploiement Veyon se pilote depuis l'action **Déployer Veyon**. PSManager attend ou génère les fichiers suivants dans `C:\ps-manager\veyon` :

- `veyon-x.x.x-win64-setup.exe`
- `veyon_configuration.json`
- `key`
- `publickey`

L'interface permet de déposer les fichiers, récupérer l'installeur Veyon, générer une configuration par défaut et générer une paire de clés. Le déploiement copie les fichiers depuis le serveur vers les postes, désinstalle une ancienne version si nécessaire, installe Veyon silencieusement, importe la configuration et redémarre le service.

Les postes professeurs peuvent recevoir la clé privée et une liste de machines issue de l'OU Active Directory lorsque LDAP est configuré.

## HTTPS et LDAP

HTTPS s'active depuis les paramètres. Le serveur écoute alors sur le port `443` et utilise `ssl/key.pem` / `ssl/cert.pem`. Si les certificats n'existent pas, un certificat auto-signé est généré automatiquement au démarrage.

L'authentification peut fonctionner avec des comptes locaux ou avec LDAP/Active Directory. Les routes API, hors login/logout, sont protégées par session.

## Stack technique

- **Backend** : Node.js, Express, ws, node-pty, node-schedule, ldapts, multer, archiver
- **Frontend** : HTML/CSS/JavaScript vanilla, xterm.js
- **Remoting** : PowerShell WinRM, `Invoke-Command`, `Copy-Item -ToSession`
- **Téléchargements** : PowerShell `Invoke-WebRequest` pour respecter les proxies Windows
- **Opérations longues** : suivi de progression et annulation côté serveur pour les scans, scripts, copies, drivers, installations et déploiements Veyon

## Licence

Ce projet est distribué sous licence MIT. Voir [LICENSE](LICENSE).
