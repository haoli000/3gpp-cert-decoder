import * as asn1js from 'asn1js';
import { Certificate, CertificationRequest, Extension } from 'pkijs';

// OID to Name Mapping
const OID_NAMES: { [key: string]: string } = {
  '2.5.29.14': 'Subject Key Identifier',
  '2.5.29.15': 'Key Usage',
  '2.5.29.17': 'Subject Alternative Name',
  '2.5.29.19': 'Basic Constraints',
  '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies',
  '2.5.29.35': 'Authority Key Identifier',
  '2.5.29.37': 'Extended Key Usage',
  '1.3.6.1.5.5.7.1.1': 'Authority Info Access',
  '1.3.6.1.5.5.7.1.34': 'NF Types',
};

const ALGORITHM_NAMES: { [key: string]: string } = {
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.10045.2.1': 'ecPublicKey',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
};

const DN_LABELS: { [key: string]: string } = {
  '2.5.4.3': 'Common Name',
  '2.5.4.6': 'Country',
  '2.5.4.8': 'State',
  '2.5.4.7': 'City',
  '2.5.4.10': 'Organization',
  '2.5.4.11': 'Organization Unit',
  '2.5.4.9': 'Address',
  '2.5.4.17': 'Postal Code',
  '0.9.2342.19200300.100.1.1': 'User ID',
};

const parseDNToParts = (dn: any) => {
  return dn.typesAndValues.map((tav: any) => {
    const oid = tav.type.toString();
    return {
      label: DN_LABELS[oid] || oid,
      value: tav.value.valueBlock.value
    };
  });
};

const formatHex = (buffer: ArrayBuffer) => {
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join(':');
};

const formatHexMultiline = (buffer: ArrayBuffer, indent: string, bytesPerLine = 15) => {
  const hex = Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0'));
  let output = '';
  for (let i = 0; i < hex.length; i += bytesPerLine) {
    const line = hex.slice(i, i + bytesPerLine).join(':');
    output += indent + line + (i + bytesPerLine < hex.length ? ':\n' : '');
  }
  return output;
};

const generateRawOutput = (cert: Certificate, extensions: any[]) => {
  const indent = '    ';
  const indent2 = indent + indent;
  const indent3 = indent2 + indent;
  const indent4 = indent3 + indent;

  let out = 'Certificate:\n';
  out += indent + 'Data:\n';
  out += indent2 + `Version: ${cert.version + 1} (${'0x' + cert.version.toString(16)})\n`;
  out += indent2 + 'Serial Number:\n';
  out += formatHexMultiline(cert.serialNumber.valueBlock.valueHex, indent3) + '\n';
  
  const sigAlgOid = cert.signatureAlgorithm.algorithmId;
  out += indent + `Signature Algorithm: ${ALGORITHM_NAMES[sigAlgOid] || sigAlgOid}\n`;
  
  const issuerStr = cert.issuer.typesAndValues.map((tav: any) => {
    const oid = tav.type.toString();
    const label = DN_LABELS[oid] || oid;
    return `${label}=${tav.value.valueBlock.value}`;
  }).join(', ');
  out += indent2 + `Issuer: ${issuerStr}\n`;
  
  out += indent2 + 'Validity\n';
  out += indent3 + `Not Before: ${cert.notBefore.value.toUTCString()}\n`;
  out += indent3 + `Not After : ${cert.notAfter.value.toUTCString()}\n`;
  
  const subjectStr = cert.subject.typesAndValues.map((tav: any) => {
    const oid = tav.type.toString();
    const label = DN_LABELS[oid] || oid;
    return `${label}=${tav.value.valueBlock.value}`;
  }).join(', ');
  out += indent2 + `Subject: ${subjectStr}\n`;
  
  out += indent2 + 'Subject Public Key Info:\n';
  const pubKeyAlgOid = cert.subjectPublicKeyInfo.algorithm.algorithmId;
  out += indent3 + `Public Key Algorithm: ${ALGORITHM_NAMES[pubKeyAlgOid] || pubKeyAlgOid}\n`;
  
  if (pubKeyAlgOid === '1.2.840.113549.1.1.1') {
      const parsedKey: any = cert.subjectPublicKeyInfo.parsedKey;
      if (parsedKey) {
          const modulusBits = parsedKey.modulus.valueBlock.valueHex.byteLength * 8;
          out += indent4 + `Public-Key: (${modulusBits} bit)\n`;
          out += indent4 + 'Modulus:\n';
          out += formatHexMultiline(parsedKey.modulus.valueBlock.valueHex, indent4 + '    ') + '\n';
          const exponent = parsedKey.publicExponent.valueBlock.valueHex;
          const expHex = Array.from(new Uint8Array(exponent)).map(b => b.toString(16)).join('');
          const expInt = parseInt(expHex, 16);
          out += indent4 + `Exponent: ${expInt} (0x${expHex})\n`;
      } else {
          out += indent4 + 'Public-Key: (Details not parsed)\n';
      }
  } else {
      out += indent4 + `Public-Key: ${formatHexMultiline(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex, '')}\n`;
  }

  out += indent2 + 'X509v3 extensions:\n';
  extensions.forEach(ext => {
      out += indent3 + `${ext.name}: ${ext.isCritical ? 'critical' : ''}\n`;
      const valueLines = ext.value.toString().split('\n');
      valueLines.forEach((line: string) => {
          out += indent4 + line + '\n';
      });
      out += '\n';
  });

  out += indent + `Signature Algorithm: ${ALGORITHM_NAMES[sigAlgOid] || sigAlgOid}\n`;
  out += formatHexMultiline(cert.signatureValue.valueBlock.valueHex, indent2 + ' ', 18);

  return out;
};

const generateRawOutputForCSR = (csr: CertificationRequest, extensions: any[]) => {
  const indent = '    ';
  const indent2 = indent + indent;
  const indent3 = indent2 + indent;
  const indent4 = indent3 + indent;

  let out = 'Certificate Request:\n';
  out += indent + 'Data:\n';
  out += indent2 + `Version: ${csr.version} (${'0x' + csr.version.toString(16)})\n`;
  
  const subjectStr = csr.subject.typesAndValues.map((tav: any) => {
    const oid = tav.type.toString();
    const label = DN_LABELS[oid] || oid;
    return `${label}=${tav.value.valueBlock.value}`;
  }).join(', ');
  out += indent2 + `Subject: ${subjectStr}\n`;
  
  out += indent2 + 'Subject Public Key Info:\n';
  const pubKeyAlgOid = csr.subjectPublicKeyInfo.algorithm.algorithmId;
  out += indent3 + `Public Key Algorithm: ${ALGORITHM_NAMES[pubKeyAlgOid] || pubKeyAlgOid}\n`;
  
  if (pubKeyAlgOid === '1.2.840.113549.1.1.1') {
      const parsedKey: any = csr.subjectPublicKeyInfo.parsedKey;
      if (parsedKey) {
          const modulusBits = parsedKey.modulus.valueBlock.valueHex.byteLength * 8;
          out += indent4 + `Public-Key: (${modulusBits} bit)\n`;
          out += indent4 + 'Modulus:\n';
          out += formatHexMultiline(parsedKey.modulus.valueBlock.valueHex, indent4 + '    ') + '\n';
          const exponent = parsedKey.publicExponent.valueBlock.valueHex;
          const expHex = Array.from(new Uint8Array(exponent)).map(b => b.toString(16)).join('');
          const expInt = parseInt(expHex, 16);
          out += indent4 + `Exponent: ${expInt} (0x${expHex})\n`;
      } else {
          out += indent4 + 'Public-Key: (Details not parsed)\n';
      }
  } else {
      out += indent4 + `Public-Key: ${formatHexMultiline(csr.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex, '')}\n`;
  }

  out += indent2 + 'Attributes:\n';
  if (extensions.length > 0) {
    out += indent3 + 'Requested Extensions:\n';
    extensions.forEach(ext => {
        out += indent4 + `${ext.name}: ${ext.isCritical ? 'critical' : ''}\n`;
        const valueLines = ext.value.toString().split('\n');
        valueLines.forEach((line: string) => {
            out += indent4 + '    ' + line + '\n';
        });
        out += '\n';
    });
  } else {
      out += indent3 + '(None)\n';
  }

  const sigAlgOid = csr.signatureAlgorithm.algorithmId;
  out += indent + `Signature Algorithm: ${ALGORITHM_NAMES[sigAlgOid] || sigAlgOid}\n`;
  out += formatHexMultiline(csr.signatureValue.valueBlock.valueHex, indent2 + ' ', 18);

  return out;
};

const formatExtensionValue = (oid: string, ext: any) => {
  if (!ext.parsedValue) {
    return `Raw Value (Hex): ${Array.from(new Uint8Array(ext.extnValue.valueBlock.valueHex)).map(b => b.toString(16).padStart(2, '0')).join('')}`;
  }

  switch (oid) {
    case '2.5.29.17': // Subject Alternative Name
      return ext.parsedValue.altNames.map((name: any) => {
        // type 1: rfc822Name, 2: dNSName, 7: iPAddress
        if (name.type === 2) return `DNS:${name.value}`;
        if (name.type === 7) {
           // IP Address handling might vary, but usually value is string or buffer
           if (typeof name.value === 'string') return `IP:${name.value}`;
           // If it's a buffer (IPv4 or IPv6)
           if (name.value.valueBlock && name.value.valueBlock.valueHex) {
             const ipHex = Array.from(new Uint8Array(name.value.valueBlock.valueHex));
             if (ipHex.length === 4) return `IP:${ipHex.join('.')}`;
             // Simple IPv6 formatting (not full compression)
             if (ipHex.length === 16) {
                const parts = [];
                for(let i=0; i<16; i+=2) parts.push(ipHex.slice(i, i+2).map(b => b.toString(16).padStart(2,'0')).join(''));
                return `IP:${parts.join(':')}`;
             }
           }
           return `IP:${JSON.stringify(name.value)}`;
        }
        if (name.type === 1) return `Email:${name.value}`;
        if (name.type === 6) return `URI:${name.value}`;
        return `${name.type}:${name.value}`;
      }).join(', ');

    case '2.5.29.15': // Key Usage
      const usages = [];
      // KeyUsage is a BIT STRING. We need to check the bits in the valueHex.
      // Bit 0 is the MSB of the first byte.
      if (ext.parsedValue && ext.parsedValue.valueBlock && ext.parsedValue.valueBlock.valueHex) {
        const view = new Uint8Array(ext.parsedValue.valueBlock.valueHex);
        const byte0 = view.length > 0 ? view[0] : 0;
        const byte1 = view.length > 1 ? view[1] : 0;

        if (byte0 & 0x80) usages.push('Digital Signature');
        if (byte0 & 0x40) usages.push('Non Repudiation');
        if (byte0 & 0x20) usages.push('Key Encipherment');
        if (byte0 & 0x10) usages.push('Data Encipherment');
        if (byte0 & 0x08) usages.push('Key Agreement');
        if (byte0 & 0x04) usages.push('Certificate Signing');
        if (byte0 & 0x02) usages.push('CRL Signing');
        if (byte0 & 0x01) usages.push('Encipher Only');
        if (byte1 & 0x80) usages.push('Decipher Only');
      }
      
      if (usages.length === 0) {
        return JSON.stringify(ext.parsedValue);
      }
      return usages.join(', ');

    case '2.5.29.19': // Basic Constraints
      const ca = ext.parsedValue.cA ? 'Yes' : 'No';
      const pathLen = ext.parsedValue.pathLenConstraint !== undefined ? `, Path Length: ${ext.parsedValue.pathLenConstraint}` : '';
      return `CA: ${ca}${pathLen}`;

    case '2.5.29.37': // Extended Key Usage
       const EKU_MAP: {[key: string]: string} = {
         '1.3.6.1.5.5.7.3.1': 'Server Auth',
         '1.3.6.1.5.5.7.3.2': 'Client Auth',
         '1.3.6.1.5.5.7.3.3': 'Code Signing',
         '1.3.6.1.5.5.7.3.4': 'Email Protection',
         '1.3.6.1.5.5.7.3.8': 'Time Stamping',
         '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
       };
       return ext.parsedValue.keyPurposes.map((oid: string) => EKU_MAP[oid] || oid).join(', ');
    
    case '2.5.29.14': // Subject Key Identifier
       if (ext.parsedValue.valueBlock && ext.parsedValue.valueBlock.valueHex) {
          return formatHex(ext.parsedValue.valueBlock.valueHex);
       }
       return JSON.stringify(ext.parsedValue);

    case '2.5.29.35': // Authority Key Identifier
       if (ext.parsedValue.keyIdentifier && ext.parsedValue.keyIdentifier.valueBlock) {
          return `KeyID: ${formatHex(ext.parsedValue.keyIdentifier.valueBlock.valueHex)}`;
       }
       return JSON.stringify(ext.parsedValue);

    default:
      return JSON.stringify(ext.parsedValue, null, 2);
  }
};

// Main parsing function
export const parseCertificate = (pem: string) => {
  try {
    let pemToProcess = pem.trim();
    let isCsr = false;

    // Check if input is Base64 encoded PEM (starts with valid Base64 char, no headers)
    if (!pemToProcess.includes('-----BEGIN')) {
      try {
        const decoded = window.atob(pemToProcess);
        if (decoded.includes('-----BEGIN')) {
          pemToProcess = decoded;
        }
      } catch (e) {
        // Not a valid Base64 string or not a Base64 encoded PEM, proceed as is
      }
    }

    if (pemToProcess.includes('REQUEST')) {
      isCsr = true;
    }

    // 1. Clean the PEM string
    const pemCleaned = pemToProcess.replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s/g, '');

    // 2. Convert Base64 to ArrayBuffer
    const binaryString = window.atob(pemCleaned);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const arrayBuffer = bytes.buffer;

    // 3. Decode ASN.1 structure
    const asn1 = asn1js.fromBER(arrayBuffer);
    if (asn1.offset === -1) {
      throw new Error('Cannot parse ASN.1 structure.');
    }

    if (isCsr) {
      // Parse as CSR
      const csr = new CertificationRequest({ schema: asn1.result });
      
      const subject = parseDNToParts(csr.subject);
      
      // Extract extensions from attributes
      let extensions: any[] = [];
      if (csr.attributes) {
        csr.attributes.forEach((attr: any) => {
          if (attr.type === '1.2.840.113549.1.9.14') { // extensionRequest
            attr.values.forEach((val: any) => {
               // val is a SEQUENCE of Extensions
               if (val.valueBlock && val.valueBlock.value) {
                 val.valueBlock.value.forEach((extAsn1: any) => {
                   try {
                     const ext = new Extension({ schema: extAsn1 });
                     const oid = ext.extnID;
                     const isCritical = ext.critical;
                     let value: any = '(Not parsed)';

                     // Special handling for the 3GPP OID
                     if (oid === '1.3.6.1.5.5.7.1.34') {
                        try {
                          const extnValue = asn1js.fromBER(ext.extnValue.valueBlock.valueHex);
                          value = extnValue.result.toString();
                        } catch (e) {
                          value = 'Could not parse 3GPP extension value.';
                        }
                     } else {
                        value = formatExtensionValue(oid, ext);
                     }

                     extensions.push({
                        oid,
                        name: OID_NAMES[oid] || oid,
                        isCritical,
                        value,
                     });
                   } catch (e) {
                     console.error('Error parsing extension in CSR', e);
                   }
                 });
               }
            });
          }
        });
      }

      const rawOutput = generateRawOutputForCSR(csr, extensions);

      return {
        type: 'csr',
        subject,
        extensions,
        rawOutput,
        decodedPem: pemToProcess,
      };
    }

    // 4. Parse the X.509 Certificate
    const certificate = new Certificate({ schema: asn1.result });

    // 5. Extract details
    const subject = parseDNToParts(certificate.subject);
    const issuer = parseDNToParts(certificate.issuer);
    const serialNumber = Array.from(new Uint8Array(certificate.serialNumber.valueBlock.valueHex)).map(b => b.toString(16).padStart(2, '0')).join(':');
    const notBefore = certificate.notBefore.value;
    const notAfter = certificate.notAfter.value;
    
    // 6. Extract extensions, including the custom 3GPP one
    const extensions = certificate.extensions?.map((ext: any) => {
      const oid = ext.extnID;
      const isCritical = ext.critical;
      let value: any = '(Not parsed)';

      // Special handling for the 3GPP OID
      if (oid === '1.3.6.1.5.5.7.1.34') {
        try {
          const extnValue = asn1js.fromBER(ext.extnValue.valueBlock.valueHex);
          // This is a placeholder for actual 3GPP extension parsing.
          // The real structure would need to be known to parse it meaningfully.
          value = extnValue.result.toString();
        } catch (e) {
          value = 'Could not parse 3GPP extension value.';
        }
      } else {
        // For common extensions, pkijs might have parsed them.
        // For others, we just show the raw value.
        value = formatExtensionValue(oid, ext);
      }

      return {
        oid,
        name: OID_NAMES[oid] || oid,
        isCritical,
        value,
      };
    }) || [];

    const rawOutput = generateRawOutput(certificate, extensions);

    return {
      type: 'certificate',
      subject,
      issuer,
      serialNumber,
      validity: {
        notBefore,
        notAfter,
      },
      extensions,
      rawOutput,
      decodedPem: pemToProcess,
    };
  } catch (error: any) {
    console.error('Certificate parsing error:', error);
    return { error: error.message || 'Failed to parse certificate.' };
  }
};

