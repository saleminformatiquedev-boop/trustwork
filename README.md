# 🛡️ TrustWork — Marketplace de Méthodes & Procédures PDF (How-To Tech) avec Séquestre Garanti

Plateforme spécialisée dans la vente et l'achat de **guides et méthodes pratiques en PDF** expliquant pas à pas **comment accomplir des tâches concrètes de développement** (déploiement AWS/Docker, conception d'APIs sécurisées, pipelines CI/CD, audits de sécurité, clean architecture...).

Le modèle combine **téléchargement immédiat du guide PDF** dès l'achat et **séquestre financier 100% garanti (Escrow USDT & Binance Pay)** pour protéger l'acheteur contre les documents non conformes.

---

## 🌟 Principes Clés

1. **Guides & Méthodes PDF Orientés Tâches ("How-To")** :
   - Chaque produit est un document PDF complet (nombre de pages, niveau requis, étapes pas à pas, snippets de code et commandes prêtes à l'emploi).
   - Accès immédiat au téléchargement dès la commande.

2. **Système de Séquestre Garanti (Escrow)** :
   - **Verrouillage initial (`ESCROWED` / `DELIVERED`)** : Dès que l'acheteur commande, les USDT sont prélevés de son solde disponible et **bloqués sous séquestre** par la plateforme. Le PDF est immédiatement accessible en téléchargement.
   - **Validation de la Tâche (`COMPLETED`)** : L'acheteur teste la méthode sur son projet. Dès qu'il valide que la tâche est accomplie, les USDT sont versés à l'auteur du guide, et l'acheteur peut laisser une note.

3. **Protection Enquête / Litige (`DISPUTED`)** :
   - **Anti-Déception 100%** : Si le fichier PDF est corrompu, illisible ou ne correspond pas au sommaire annoncé, l'acheteur clique sur **"Ouvrir une Enquête / Litige"**.
   - Les fonds restent **intégralement gelés**.
   - L'administrateur peut trancher en un clic :
     - 🛡️ **Rembourser l'Acheteur** (restitution immédiate des USDT).
     - 💰 **Payer l'Auteur** (si le contenu est conforme au descriptif).

4. **Paiements & Retraits Binance** :
   - Support complet des transactions en **USDT**.
   - Enregistrement du **Binance Pay ID** sur le profil pour les retraits directs.
   - Rechargement direct.

5. **Messagerie en Direct & Support de l'Auteur** :
   - Messagerie Socket.io intégrée dans chaque commande pour poser des questions à l'auteur ou recevoir des fichiers d'exemples complémentaires.

---

## 🚀 Démarrage Rapide

### 1. Lancer l'application
Le serveur est déjà configuré. Pour le lancer ou le relancer :

```bash
npm start
```

Rendez-vous ensuite sur : **[http://localhost:3000](http://localhost:3000)**

---

## 🧪 Tester l'application immédiatement (Comptes Démo)

Des comptes prêts à l'emploi sont configurés :
- **Acheteur (Thomas)** : Crédité de **250 USDT** pour passer commande et tester le séquestre.
- **Vendeur (Sarah)** : Dispose déjà de **2 services en ligne** (Landing Page Tailwind, Logo) pour recevoir des commandes et livrer.
- **Médiateur / Support (Admin)** : Accès au centre d'arbitrage pour trancher les enquêtes et rembourser.

Vous pouvez basculer d'un profil à l'autre en un seul clic via le bandeau en haut du site.

---

## 🔑 Configurer Google OAuth 2.0 (Optionnel)

Si vous souhaitez activer la véritable connexion avec Google :
1. Créez un projet sur [Google Cloud Console](https://console.cloud.google.com/).
2. Activez l'API **Google+ / Identity**.
3. Dans la section *Identifiants OAuth 2.0*, ajoutez l'URI de redirection autorisée :
   `http://localhost:3000/auth/google/callback`
4. Remplissez les clés dans votre fichier `.env` :
   ```env
   GOOGLE_CLIENT_ID="votre-client-id.apps.googleusercontent.com"
   GOOGLE_CLIENT_SECRET="votre-client-secret"
   ```

---

## 📁 Architecture du Projet

```
├── .env                  # Configuration (Port, Session, Clés Google)
├── package.json          # Dépendances Node.js
├── dev.db                # Base de données SQLite locale avec WAL
├── src/
│   ├── server.js         # Serveur Express & Routes
│   ├── db.js             # Initialisation SQLite (Users, Services, Orders, Disputes)
│   ├── auth.js           # Google OAuth 2.0 & Fast Login
│   ├── escrow.js         # Moteur de Séquestre atomique (Transactions ACID)
│   └── views/            # Vues Tailwind CSS
│       ├── index.ejs            # Catalogue des services & Hero
│       ├── service-detail.ejs   # Fiche service & commande séquestre
│       ├── new-service.ejs      # Formulaire de publication travailleur
│       ├── order-detail.ejs     # Stepper Escrow, Enquêtes & Messagerie
│       ├── dashboard.ejs        # Portefeuille USDT, Binance ID & commandes
│       ├── disputes.ejs         # Centre d'arbitrage Admin
│       ├── login.ejs            # Connexion Google & Démo
│       └── partials/            # Header avec solde en direct & Footer
```
