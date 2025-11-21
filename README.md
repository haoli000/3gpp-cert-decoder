# SSL Cert Decoder

A modern, web-based tool for decoding and visualizing X.509 certificates. This application provides a clean, technical interface for inspecting certificate details, with specialized support for 3GPP extensions.

![SSL Cert Decoder](https://via.placeholder.com/800x400?text=SSL+Cert+Decoder+Screenshot)

## Features

* **Comprehensive Decoding**: Parses standard X.509 certificate fields including Subject, Issuer, Validity, and Serial Number.
* **Extension Support**: Detailed parsing of common extensions:
  * Subject Alternative Name (DNS, IP, Email, URI)
  * Key Usage (BitString decoding)
  * Extended Key Usage
  * Basic Constraints
  * Subject/Authority Key Identifiers
* **3GPP Specifics**: Special handling for 3GPP "NF Types" extension (OID `1.3.6.1.5.5.7.1.34`).
* **Flexible Input**: Accepts both standard PEM format and Base64-encoded certificate data. Automatically detects and converts Base64 input.
* **Raw Output**: Generates an OpenSSL-style text view (`openssl x509 -text`) for deep inspection.
* **Modern UI**:
  * Clean, light-themed "technical" design.
  * Glassmorphism effects.
  * Responsive layout that adapts from a centered input view to a split-screen results view.
  * Visual indicators for Critical extensions and 3GPP specific fields.

## Tech Stack

* **Frontend**: React 18, TypeScript, Vite
* **UI Framework**: Bootstrap 5, React-Bootstrap
* **Crypto/Parsing**: `pkijs`, `asn1js`
* **Backend**: Node.js, Express (for serving the static build)

## Getting Started

### Prerequisites

* Node.js (v16 or higher recommended)
* npm

### Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd 3gpp-cert-decoder
   ```

2. Install dependencies for the root (server) and the client:

   ```bash
   npm install
   cd client
   npm install
   cd ..
   ```

### Running Development Server

To run both the backend server and the React development server concurrently:

```bash
npm run dev
```

* The application will be available at `http://localhost:5173` (Vite default).
* The Express server runs on port 3000.

### Building for Production

1. Build the React client:

   ```bash
   cd client
   npm run build
   cd ..
   ```

2. Start the production server:

   ```bash
   npm start
   ```

   The application will be served at `http://localhost:3000`.

### Deploying to Vercel

This project is configured for easy deployment on Vercel.

1. Push your code to a Git repository (GitHub, GitLab, Bitbucket).
2. Import the project into Vercel.
3. Vercel will automatically detect the configuration from `vercel.json` and deploy the client as a static site.

## Project Structure

```text
├── client/                 # React Frontend
│   ├── src/
│   │   ├── components/     # UI Components (CertificateInput, CertificateDetails)
│   │   ├── utils/          # Parsing logic (parser.ts)
│   │   ├── App.tsx         # Main Application Component
│   │   └── App.css         # Global Styles & Theming
│   ├── index.html
│   └── vite.config.ts
├── server.js               # Express server for production serving
└── package.json            # Root configuration
```

## License

Apache-2.0
