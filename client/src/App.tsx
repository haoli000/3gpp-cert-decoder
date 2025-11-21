import { useState, useEffect } from 'react';
import { Spinner, Alert, Navbar, Container } from 'react-bootstrap';
import CertificateInput from './components/CertificateInput';
import CertificateDetails from './components/CertificateDetails';
import { parseCertificate } from './utils/parser';
import './App.css';

// Define the type for the parsed certificate based on the parser's output
export interface ParsedCertificate {
  type: 'certificate' | 'csr';
  subject: Array<{ label: string; value: string }>;
  issuer?: Array<{ label: string; value: string }>;
  serialNumber?: string;
  validity?: {
    notBefore: Date;
    notAfter: Date;
  };
  extensions: Array<{
    oid: string;
    name: string;
    isCritical: boolean;
    value: any;
  }>;
  rawOutput?: string;
  decodedPem?: string;
  error?: string;
}

function App() {
  const [pem, setPem] = useState('');
  const [cert, setCert] = useState<ParsedCertificate | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [hasDecoded, setHasDecoded] = useState(false);

  useEffect(() => {
    if (!pem) {
      setHasDecoded(false);
      setCert(null);
    }
  }, [pem]);

  const handleDecode = () => {
    if (!pem) return;
    setIsLoading(true);
    setHasDecoded(true);
    setCert(null);
    setTimeout(() => {
      const result = parseCertificate(pem);
      setCert(result as ParsedCertificate);
      
      if (result.decodedPem && result.decodedPem !== pem) {
        setPem(result.decodedPem);
      }
      
      setIsLoading(false);
    }, 300);
  };

  const RightPanel = () => {
    if (isLoading) {
      return <div className="d-flex justify-content-center align-items-center h-100"><Spinner animation="border" variant="primary" /></div>;
    }
    if (cert?.error) {
      return <div className="p-4"><Alert variant="danger"><strong>Error:</strong> {cert.error}</Alert></div>;
    }
    if (cert) {
      return <CertificateDetails cert={cert} />;
    }
    return null;
  };

  return (
    <div className="app-container">
      <Navbar className="app-navbar" variant="dark">
        <Container fluid>
          <Navbar.Brand href="#home" className="brand-logo">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="url(#brand-gradient)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="me-2">
              <defs>
                <linearGradient id="brand-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="var(--primary-color)" />
                  <stop offset="100%" stopColor="var(--accent-color)" />
                </linearGradient>
              </defs>
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
            SSL Cert Decoder
          </Navbar.Brand>
          <Navbar.Text className="text-muted small">
            v1.0.0
          </Navbar.Text>
        </Container>
      </Navbar>
      
      <div className={`main-content ${!hasDecoded && !isLoading ? 'center-layout' : ''}`}>
        <div className="left-panel">
          <CertificateInput pem={pem} setPem={setPem} handleDecode={handleDecode} isLoading={isLoading} />
        </div>
        {(hasDecoded || isLoading) && (
          <div className="right-panel">
            <RightPanel />
          </div>
        )}
      </div>
    </div>
  );
}

export default App;