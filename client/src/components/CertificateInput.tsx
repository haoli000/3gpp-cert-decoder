import React, { useState } from 'react';
import { Form, Button, Spinner, Modal } from 'react-bootstrap';

interface CertificateInputProps {
  pem: string;
  setPem: (pem: string) => void;
  handleDecode: () => void;
  isLoading: boolean;
}

const CertificateInput: React.FC<CertificateInputProps> = ({ pem, setPem, handleDecode, isLoading }) => {
  const [showInfo, setShowInfo] = useState(false);

  return (
    <div className="p-4 d-flex flex-column flex-grow-1">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="mb-0">Input Certificate / CSR</h2>
        <Button variant="link" className="text-muted p-0" onClick={() => setShowInfo(true)} aria-label="Info">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="16" x2="12" y2="12"></line>
            <line x1="12" y1="8" x2="12.01" y2="8"></line>
          </svg>
        </Button>
      </div>
      <Form className="d-flex flex-column flex-grow-1">
        <Form.Group controlId="certificateInput" className="flex-grow-1 d-flex flex-column">
          <Form.Label>Data (PEM or Base64)</Form.Label>
          <Form.Control
            as="textarea"
            value={pem}
            onChange={(e) => setPem(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                if (pem && !isLoading) {
                  handleDecode();
                }
              }
            }}
            placeholder="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"
            className="monospace flex-grow-1"
            spellCheck={false}
          />
        </Form.Group>
        <div className="d-grid gap-2 mt-4">
          <Button variant="primary" size="lg" onClick={handleDecode} disabled={isLoading || !pem}>
            {isLoading ? (
              <>
                <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                Decoding...
              </>
            ) : (
              'Decode'
            )}
          </Button>
        </div>
      </Form>

      <Modal show={showInfo} onHide={() => setShowInfo(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>About SSL Cert Decoder</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>This tool allows you to decode and visualize <strong>X.509 Certificates</strong> and <strong>Certificate Signing Requests (CSRs)</strong>.</p>
          
          <h6>Features:</h6>
          <ul>
            <li><strong>Dual Support:</strong> Automatically detects and parses both Certificates and CSRs.</li>
            <li><strong>Flexible Input:</strong> Accepts PEM format (with headers) or raw Base64 strings.</li>
            <li><strong>Deep Parsing:</strong> Decodes standard extensions (SAN, Key Usage, etc.) and specific <strong>3GPP</strong> extensions.</li>
            <li><strong>Privacy Focused:</strong> All processing happens entirely in your browser. No data is sent to any server.</li>
          </ul>
          
          <div className="mt-4 pt-3 border-top">
            <p className="mb-0 text-muted small">
              Version 1.0.0 • by <a href="https://github.com/haoli000/" target="_blank" rel="noopener noreferrer" className="text-decoration-none">browable hobby</a>
            </p>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowInfo(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};

export default CertificateInput;
