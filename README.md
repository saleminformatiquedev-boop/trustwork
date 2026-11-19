# 🛡️ TrustWork — Practical Tech Procedures & PDF Guides Marketplace with Guaranteed Escrow

Specialized platform for buying and selling **practical PDF guides and technical methods** explaining step-by-step **how to accomplish real-world software engineering and DevOps tasks** (AWS/Docker deployments, secure API design, CI/CD pipelines, security audits, clean architecture, and more).

The marketplace combines **instant download access** upon purchase with a **100% Guaranteed Financial Escrow (USDT & Binance Pay)** to protect buyers against non-compliant or deceptive documents.

---

## 🌟 Key Principles

1. **Task-Oriented "How-To" PDF Methods & Code Packs**:
   - Every product is a comprehensive technical guide (page count, difficulty level, step-by-step instructions, ready-to-use code snippets and command lines).
   - Instant file download available immediately after order placement.

2. **Guaranteed Escrow Protection System**:
   - **Initial Lock (`ESCROWED` / `DELIVERED`)**: When the buyer places an order, the USDT is deducted from their available balance and **held securely in platform escrow**. The guide and attachments become available for immediate download.
   - **Task Validation (`COMPLETED`)**: The buyer tests the instructions on their own environment. Once they verify that the task succeeds, funds are released to the author's available balance, and the buyer can leave a review.

3. **Dispute & Investigation Protection (`DISPUTED`)**:
   - **100% Satisfaction Guarantee**: If the document is corrupt, incomplete, or does not match the advertised table of contents, the buyer can click **"Open Dispute / Investigation"**.
   - Escrow funds are **frozen immediately**.
   - Platform administrators can arbitrate with a single click:
     - 🛡️ **Refund Buyer** (instant restitution of USDT to buyer's balance).
     - 💰 **Pay Author** (if content complies with the description).

4. **Binance Pay & Crypto Transactions**:
   - Full support for **USDT** transactions.
   - Save your **Binance Pay ID** in your profile for direct withdrawals.
   - Instant top-up / deposit flow with QR code generation.

5. **Multi-User Real-Time Chat (Buyer, Author, Administrator)**:
   - **Dedicated `/chat` view** with dual-pane layout (conversations list + active conversation).
   - **Socket.io Real-Time Engine**: instant delivery, live typing indicator ("typing..."), toast notifications, and unread badges.
   - **Attachment & Deliverable Sharing**: upload up to 25 MB (PDF, ZIP, images, scripts) with live previews.
   - **Targeted Communications**:
     - **Buyer ↔ Author**: "Ask a question to author" button from every guide or author profile.
     - **User ↔ Support Admin**: 1-click direct link to "Contact Support".
     - **Admin ↔ Users**: direct arbitration from the moderation center with global oversight.

---

## 🚀 Quick Start

### 1. Run the application
The server is preconfigured. To run it:

```bash
npm start
```

Then visit: **[http://localhost:3000](http://localhost:3000)**

---

## 🧪 Test Instantly (Demo Profiles)

Ready-to-use demo accounts are configured:
- **Buyer (Thomas)**: Pre-funded with **250 USDT** to test purchasing and escrow locking.
- **Author (Sarah)**: Features published technical guides to test receiving orders and fund release.
- **Mediator / Support (Admin)**: Full access to the disputes center to arbitrate cases and refund/release funds.

You can switch between demo profiles in one click from the persistent navigation header.

---

## 🔑 Configure Google OAuth 2.0 (Optional)

If you want to enable live Google authentication:
1. Create a project in [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the **Google+ / Identity API**.
3. Under *OAuth 2.0 Credentials*, add the authorized redirect URI:
   `http://localhost:3000/auth/google/callback`
4. Set the keys in your `.env` file:
   ```env
   GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
   GOOGLE_CLIENT_SECRET="your-client-secret"
   ```

---

## 📁 Project Architecture

```
├── .env                  # Configuration (Port, Session, Database, Google keys)
├── package.json          # Node.js dependencies & scripts
├── prisma/               # Prisma ORM schema
├── src/
│   ├── server.js         # Express server, Socket.io, REST APIs & SSR routes
│   ├── db.js             # PostgreSQL client pool & schema initialization
│   ├── auth.js           # Google OAuth 2.0 & demo fast-login profiles
│   ├── escrow.js         # Atomic Escrow engine (ACID transactions)
│   ├── services/
│   │   └── email.js      # Responsive HTML email notification templates
│   └── views/            # Tailwind CSS / EJS templates
│       ├── index.ejs            # Marketplace catalog & search filters
│       ├── service-detail.ejs   # Guide details, curriculum & order checkout
│       ├── new-service.ejs      # Technical guide authoring form
│       ├── order-detail.ejs     # 4-step escrow stepper, downloads & order chat
│       ├── dashboard.ejs        # USDT wallet, Binance Pay deposit/withdraw & orders
│       ├── chat.ejs             # Multi-user real-time messaging
│       ├── disputes.ejs         # Admin arbitration & dispute resolution center
│       ├── history.ejs          # Global transaction ledger & order history
│       ├── profile.ejs          # Public author profile & verified reviews
│       ├── login.ejs            # Google & demo login
│       └── partials/            # Header with live balance & Footer
```
