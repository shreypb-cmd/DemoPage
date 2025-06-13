import axios from 'axios';
import randomstring from 'randomstring';
import { importSPKI, CompactEncrypt } from 'jose';

const fetchPublicKey = async () => {
  try {
    const response = await axios('http://localhost:8080/api/public-key');
    return response.data.publicKey;
  } catch (error) {
    console.error('Error fetching public key:', error);
    throw error;
  }
};

const fetchIPAndUserAgent = async () => {
  try {
    const res = await axios.get('https://api.ipify.org?format=json');
    return {
      customerIP: res.data.ip,
      userAgent: navigator.userAgent,
    };
  } catch (error) {
    console.error('Failed to fetch IP:', error);
    return {
      customerIP: 'unknown',
      userAgent: navigator.userAgent,
    };
  }
};

const encryptWithJWE = async (payloadObject, publicKeyPEM, issuer) => {
  const pubKey = await importSPKI(publicKeyPEM, 'RSA-OAEP-256');
  const payload = new TextEncoder().encode(JSON.stringify(payloadObject));
  const jwe = await new CompactEncrypt(payload)
    .setProtectedHeader({
      alg: 'RSA-OAEP-256',
      enc: 'A128CBC-HS256',
      'issued-by': issuer,
    })
    .encrypt(pubKey);
  return jwe;
};

export const processPayment = async (formData) => {
  try {
    // Fetch public key
    const secretKey = await fetchPublicKey();

    // Fetch IP and user agent
    const { customerIP, userAgent } = await fetchIPAndUserAgent();

    // Generate order ID
    // const orderId = generateOrderId();

    // Prepare payload with updated data
    const payload = {
      ...formData,
      // orderId,
      customerIP,
      userAgent,
    };

    // Encrypt payload
    const encryptedPayload = await encryptWithJWE(payload, secretKey, formData.merchantId);

    // Submit to backend
    const response = await fetch('http://localhost:8080/pay/getPaymentPage', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'key-id': 'KID1739184427260101618445',
      },
      body: JSON.stringify({ payload: encryptedPayload }),
    });

    const data = await response.json();
    
    // Instead of returning the URL, redirect to it
    if (data && data.url) {
      window.location.href = data.url;
    } else {
      throw new Error('No URL found in response');
    }
  } catch (error) {
    console.error('Payment processing failed:', error);
    throw error;
  }
};