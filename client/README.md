# SSL Cert Decoder

A modern, client-side web application for decoding and visualizing SSL/TLS X.509 Certificates and Certificate Signing Requests (CSRs). Built with React, TypeScript, and Vite.

![SSL Cert Decoder](public/vite.svg)

## Features

- **Dual Parsing Support**:
  - **X.509 Certificates**: Decodes standard SSL certificates.
  - **CSR (Certificate Signing Request)**: Auto-detects and parses CSRs, displaying relevant fields (Subject, Public Key, Requested Extensions).
- **Smart Input Handling**:
  - Accepts PEM formatted data (with headers).
  - Auto-detects and converts raw Base64 input to PEM.
  - Auto-detects between Certificate and CSR types.
- **Detailed Visualization**:
  - **Core Details**: Serial Number, Validity Period (Not Before/After).
  - **Identity**: Subject and Issuer DN parsing.
  - **Extensions**: Decodes standard X.509 extensions (SAN, Key Usage, Basic Constraints, etc.).
  - **3GPP Support**: Special handling for 3GPP specific OIDs (e.g., `1.3.6.1.5.5.7.1.34`).
- **Raw View**: Generates an OpenSSL-style text output for quick verification.
- **Modern UI**: Clean, responsive interface with glassmorphism effects and a technical aesthetic.

## Tech Stack

- **Frontend**: React 19, TypeScript, Vite
- **Styling**: Bootstrap 5, Custom CSS
- **Crypto/Parsing**: `pkijs`, `asn1js`

## Getting Started

### Prerequisites

- Node.js (v18 or higher recommended)
- npm or yarn

### Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd 3gpp-cert-decoder/client
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Start the development server:

   ```bash
   npm run dev
   ```

4. Open your browser and navigate to `http://localhost:5173`.

## Usage

1. **Paste Input**: Copy your Certificate or CSR (PEM or Base64) into the text area.
2. **Decode**: The application automatically detects the format. Click "Decode".
3. **View Details**:
   - **Certificates**: View Subject, Issuer, Validity, and Extensions.
   - **CSRs**: View Subject, Public Key Info, and Requested Extensions.
4. **Raw Output**: Check the "Raw Output" section for a command-line style summary.

## License

Apache-2.0
