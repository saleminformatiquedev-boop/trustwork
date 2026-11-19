# 🛡️ TrustWork — Practical Tech Procedures & PDF Guides Marketplace with Guaranteed Escrow

Specialized platform for buying and selling **practical PDF guides and technical methods** explaining step-by-step **how to accomplish real-world software engineering and DevOps tasks** (AWS/Docker deployments, secure API design, CI/CD pipelines, security audits, clean architecture, and more).

The marketplace combines **instant download access** upon purchase with a **100% Guaranteed Financial Escrow** to protect buyers against non-compliant or deceptive documents. Checkout is powered by **Telegram Stars (XTR)**, Telegram's official currency for digital goods.

---

## 🌟 Key Principles

1. **Task-Oriented "How-To" PDF Methods & Code Packs**:
   - Every product is a comprehensive technical guide (page count, difficulty level, step-by-step instructions, ready-to-use code snippets and command lines).
   - Instant file download available immediately after order placement.

2. **Guaranteed Escrow Protection System**:
   - **Initial Lock (`ESCROWED` / `DELIVERED`)**: When the buyer places an order, the USD ledger amount is deducted from their available balance and **held securely in platform escrow**. The guide and attachments become available for immediate download.
   - **Task Validation (`COMPLETED`)**: The buyer tests the instructions on their own environment. Once they verify that the task succeeds, funds are released to the author's available balance, and the buyer can leave a review.

3. **Dispute & Investigation Protection (`DISPUTED`)**:
   - **100% Satisfaction Guarantee**: If the document is corrupt, incomplete, or does not match the advertised table of contents, the buyer can click **"Open Dispute / Investigation"**.
   - Escrow funds are **frozen immediately**.
   - Platform administrators can arbitrate with a single click:
     - 🛡️ **Refund Buyer** (instant restitution in USD to the buyer's ledger balance).
      - 💰 **Pay Author** (if content complies with the description).

4. **Telegram Stars Payments (XTR)**:
   - Store checkout and wallet top-ups create an official Telegram Stars invoice (`createInvoiceLink`).
   - Payment is confirmed server-side by Telegram's `successful_payment` update — no TxID to copy, no manual verification.
   - Internal balances remain denominated in **USD** for escrow and accounting; Stars are the funding rail.
   - Conversion is configurable with `TG_STARS_PER_USD` (default `77 Stars = $1`).
   - Sellers save **payout details** (IBAN, PayPal, Fragment, etc.) and request a payout; the admin sends funds manually because Telegram does not allow transferring arbitrary Stars between users.
   - Admins can view the live bot Stars balance, recent Stars transactions, and refund a paid order directly to the buyer's Telegram Stars balance.

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
- **Buyer (Thomas)**: Pre-funded with **$250** to test purchasing and escrow locking.
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

## ⭐ Configure Telegram Stars

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its token.
2. Expose the app over **public HTTPS** (a domain, or a tunnel such as Cloudflare Tunnel / ngrok in development).
3. Add the following variables to `.env`:

   ```env
   TELEGRAM_BOT_TOKEN="123456789:AA...your-bot-token..."
   TELEGRAM_BOT_USERNAME="your_bot_username"
   TELEGRAM_WEBHOOK_URL="https://your-domain.com"
   TELEGRAM_WEBHOOK_SECRET="replace-with-a-random-secret"
   TG_STARS_PER_USD="77"
   ```

4. Start the server. On boot it registers the webhook at
   `{TELEGRAM_WEBHOOK_URL}/telegram/webhook/{TELEGRAM_WEBHOOK_SECRET}`
   with the `X-Telegram-Bot-Api-Secret-Token` header check enabled.
   If no webhook URL is set, the server falls back to long polling for local development.
5. Set `TELEGRAM_POLLING="false"` to disable the long-polling fallback in production.

**How payments work**

- Store checkout and wallet top-ups call `createInvoiceLink` with `currency: "XTR"`.
- Telegram sends `pre_checkout_query` (validated and answered) and then `successful_payment`.
- The webhook marks the order/invoice `PAID`, credits the wallet exactly once (idempotent by payload + charge ID), and notifies the admin.
- Refunds use `refundStarPayment` and are only available inside Telegram's refund window.
- Telegram does not allow transferring arbitrary Stars to other users: seller payouts are therefore recorded as manual payout requests and processed by the admin via the seller's saved payout method.

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
│   │   ├── telegramStars.js # Telegram Stars invoices, refunds & webhook updates
│   │   └── email.js      # Responsive HTML email notification templates
│   └── views/            # Tailwind CSS / EJS templates
│       ├── index.ejs            # Marketplace catalog & search filters
│       ├── service-detail.ejs   # Guide details, curriculum & order checkout
│       ├── new-service.ejs      # Technical guide authoring form
│       ├── order-detail.ejs     # 4-step escrow stepper, downloads & order chat
│       ├── dashboard.ejs        # USD wallet, Telegram Stars top-up & payout requests
│       ├── chat.ejs             # Multi-user real-time messaging
│       ├── disputes.ejs         # Admin arbitration & dispute resolution center
│       ├── history.ejs          # Global transaction ledger & order history
│       ├── profile.ejs          # Public author profile & verified reviews
│       ├── login.ejs            # Google & demo login
│       └── partials/            # Header with live balance & Footer
```
