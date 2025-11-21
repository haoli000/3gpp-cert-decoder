import React from 'react';
import { Table, Badge } from 'react-bootstrap';
import type { ParsedCertificate } from '../App'; // Import the shared type

interface CertificateDetailsProps {
  cert: ParsedCertificate;
}

const is3gppOid = (oid: string) => oid === '1.3.6.1.5.5.7.1.34';

const DetailRow: React.FC<{ label: string; value: any }> = ({ label, value }) => (
  <tr>
    <td className="detail-label">{label}</td>
    <td className="detail-value monospace">{value}</td>
  </tr>
);

const CertificateDetails: React.FC<CertificateDetailsProps> = ({ cert }) => {
  const isCsr = cert.type === 'csr';

  return (
    <div className="details-container">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h4 className="mb-0">
          {isCsr ? 'Certificate Signing Request' : 'Certificate Details'}
        </h4>
        <Badge bg={isCsr ? 'info' : 'success'}>
          {isCsr ? 'CSR' : 'X.509 Certificate'}
        </Badge>
      </div>

      {!isCsr && cert.validity && (
        <div className="card-custom">
          <div className="card-header-custom">
            <h5>Core</h5>
          </div>
          <Table responsive className="detail-table">
            <tbody>
              {cert.serialNumber && <DetailRow label="Serial Number" value={cert.serialNumber} />}
              <DetailRow label="Valid From" value={cert.validity.notBefore.toUTCString()} />
              <DetailRow label="Valid Until" value={cert.validity.notAfter.toUTCString()} />
            </tbody>
          </Table>
        </div>
      )}

      <div className="card-custom">
        <div className="card-header-custom">
          <h5>Subject</h5>
        </div>
        <Table responsive className="detail-table">
          <tbody>
            {cert.subject.map((part, index) => (
              <DetailRow key={index} label={part.label} value={part.value} />
            ))}
          </tbody>
        </Table>
      </div>

      {!isCsr && cert.issuer && (
        <div className="card-custom">
          <div className="card-header-custom">
            <h5>Issuer</h5>
          </div>
          <Table responsive className="detail-table">
            <tbody>
              {cert.issuer.map((part, index) => (
                <DetailRow key={index} label={part.label} value={part.value} />
              ))}
            </tbody>
          </Table>
        </div>
      )}

      <div className="card-custom">
        <div className="card-header-custom">
          <h5>Extensions</h5>
        </div>
        <Table responsive className="detail-table extensions-table">
          <thead>
            <tr>
              <th>OID / Name</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {cert.extensions.length > 0 ? (
              cert.extensions.map((ext, index) => (
                <tr key={index} className={is3gppOid(ext.oid) ? 'highlight-3gpp' : ''}>
                  <td className="monospace">
                    <div className="d-flex align-items-center flex-wrap">
                      {ext.name}
                      {is3gppOid(ext.oid) && <Badge className="badge-3gpp ms-2">3GPP</Badge>}
                      {ext.isCritical && <Badge bg="warning" text="dark" className="ms-2">Critical</Badge>}
                    </div>
                    {ext.name !== ext.oid && (
                      <div className="text-muted small mt-1" style={{ fontSize: '0.75rem' }}>{ext.oid}</div>
                    )}
                  </td>
                  <td className="monospace" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {ext.value}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={2} className="text-center text-muted">No extensions found</td>
              </tr>
            )}
          </tbody>
        </Table>
      </div>

      {cert.rawOutput && (
        <div className="card-custom">
          <div className="card-header-custom">
            <h5>Raw Output</h5>
          </div>
          <div className="p-3">
            <pre className="monospace mb-0" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '0.85rem' }}>
              {cert.rawOutput}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default CertificateDetails;
