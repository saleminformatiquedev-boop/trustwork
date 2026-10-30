# 🛡️ TrustWork — Plateforme de Services Freelance avec Séquestre (Escrow) & Binance Pay

Plateforme de mise en relation de services forfaitaires entre travailleurs (inspirée de G2G / Upwork / ComeUp), simplifiée, **sans contrat à l'heure**, avec **séquestre financier 100% garanti** et intégration **Binance Pay / USDT**.

---

## 🌟 Principes Clés

1. **Tarif Forfaitaire Fixe (Fixed-Price uniquement)** :
   - Aucun suivi au temps passé ni tarif à l'heure.
   - Les commandes ont un prix clair et un délai de livraison défini (en jours).

2. **Système de Séquestre Garanti (Escrow)** :
   - **Verrouillage initial (`ESCROWED`)** : Dès que l'acheteur commande, les USDT sont prélevés de son solde disponible et **bloqués sous séquestre** par la plateforme. Le travailleur sait que les fonds sont garantis.
   - **Livraison (`DELIVERED`)** : Le travailleur réalise la mission et soumet ses livrables (liens, fichiers, rapports).
   - **Validation & Paiement (`COMPLETED`)** : L'acheteur vérifie le travail. Dès qu'il valide, les USDT bloqués sont immédiatement versés sur le compte du travailleur.

3. **Protection Enquête / Litige (`DISPUTED`)** :
   - **L'acheteur ne peut pas perdre son argent** : S'il y a le moindre problème (travail non conforme, retard, absence de réponse), l'acheteur clique sur **"Ouvrir une Enquête / Litige"**.
   - Les fonds restent **intégralement gelés**.
   - Un arbitre/administrateur examine le dossier et le fil de messagerie, puis peut décider en un clic :
     - 🛡️ **Rembourser l'Acheteur** (les USDT retournent immédiatement sur son portefeuille).
     - 💰 **Payer le Vendeur** (si les preuves de livraison sont conformes).

4. **Paiements & Retraits Binance** :
   - Support des transactions en **USDT**.
   - Enregistrement du **Binance Pay ID** sur le profil pour les retraits directs.
   - Rechargement rapide.

5. **Authentification Simple** :
   - Connexion **Google OAuth 2.0** en un clic.
   - Mode démo instantané inclus pour tester les rôles Acheteur, Vendeur et Modérateur sans configuration préalable.

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
