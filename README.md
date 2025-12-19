# AssetVerse | Backend API Service

This is the robust Node.js and Express backend for AssetVerse, handling data persistence, authentication logic, and administrative operations using MongoDB.

- **API Base URL:** [https://asset-verse.netlify.app](https://asset-verse.netlify.app)

## 🚀 Key Features
* **Secure API Endpoints:** Protected routes using JWT (JSON Web Token) authentication.
* **MongoDB Integration:** Optimized schema design for assets, users, and requests.
* **Pagination & Search:** Server-side filtering and pagination for large asset datasets.
* **Status Management:** Automated logic for updating asset quantities upon return or approval.
* **Middleware:** Custom error handling and authentication verification.

## 🛠️ Tech Stack & Packages
* **Runtime:** Node.js
* **Framework:** Express.js
* **Database:** MongoDB (via MongoDB Atlas)
* **Security:** JSON Web Token (JWT), Cookie Parser, CORS, Dotenv
* **Utilities:** Morgan (logging)

## 💻 Setup Instructions
1. Navigate to the server folder:
   ```bash
   cd assetverse/server

2. Install dependencies:
   ```bash
    npm install

3. Create the configuration file (see Environment Variables).

4. Start the server:
  ```bash
  npm start