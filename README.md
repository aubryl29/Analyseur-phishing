# 🎣 Analyseur de Phishing

Un outil puissant et interactif en Python pour analyser les emails (fichiers `.eml`) et détecter les tentatives d'hameçonnage (phishing). Il évalue le risque d'un email en se basant sur plusieurs facteurs et attribue un score de menace sur 100.

L'outil propose deux interfaces :
1. **Un script en ligne de commande (CLI)** (`analyseur.py`)
2. **Un Dashboard interactif avec Streamlit** (`app.py`)

## ✨ Fonctionnalités

- **Extraction automatique** des informations clés de l'email : Expéditeur, Date, IP d'origine, et liens (URLs).
- **Analyse sémantique** : Détection de mots-clés d'urgence ou de pression (ex: "mot de passe", "urgent", "bloqué").
- **Analyse des liens (URLs)** :
  - Détection des liens non sécurisés (HTTP).
  - Identification de domaines inconnus ou suspects.
  - Évaluation d'un risque exponentiel basé sur la présence massive de liens suspects.
- **Intégration de l'API VirusTotal** (Optionnel) pour vérifier la réputation et la dangerosité des liens extraits.
- **Analyse de l'expéditeur** : Détection d'usurpation de grandes marques (ex: Paypal, Microsoft) ou de l'utilisation de domaines gratuits suspects.
- **Visualisations interactives** (Dashboard) : Affichage d'un graphique (Pie chart) de la répartition des mots-clés d'urgence trouvés.

## 🛠️ Prérequis

Assurez-vous d'avoir [Python 3.x](https://www.python.org/downloads/) installé sur votre système.

Les bibliothèques requises sont :
- `streamlit`
- `pandas`
- `plotly`

## 🚀 Installation

1. Clonez ce dépôt sur votre machine locale :
   ```bash
   git clone https://github.com/aubryl29/Analyseur_phishing.git
   cd Analyseur_phishing
   ```

2. Installez les dépendances nécessaires à l'aide de `pip` :
   ```bash
   pip install streamlit pandas plotly
   ```

## 💻 Utilisation

### 1. Via le Dashboard Streamlit (Recommandé)

Lancez l'interface web interactive :
```bash
streamlit run app.py
```
- Une fenêtre s'ouvrira dans votre navigateur.
- Glissez-déposez n'importe quel fichier `.eml` dans l'interface.
- (Optionnel) Entrez votre clé API VirusTotal pour une vérification approfondie des liens.

### 2. Via la ligne de commande (CLI)

Vous pouvez lancer le script d'analyse basique dans votre terminal :
```bash
python analyseur.py "chemin/vers/votre/email.eml"
```
Il vous sera ensuite demandé d'entrer votre clé API VirusTotal si vous souhaitez activer l'analyse en ligne de ces liens (appuyez sur Entrée pour passer cette étape).

## 🔑 Obtenir une clé API VirusTotal
Pour activer l'analyse des URLs par un antivirus en ligne, vous pouvez créer un compte gratuit sur [VirusTotal](https://www.virustotal.com/) et récupérer votre clé API dans les paramètres de votre compte.

## ⚖️ Avertissement
Cet outil est fourni à des fins éducatives et de sensibilisation à la cybersécurité. Ne testez pas ce script sur des emails ou des pièces jointes malveillantes en dehors d'un environnement sécurisé (sandbox).
