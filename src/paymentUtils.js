import axios from 'axios';
import randomstring from 'randomstring';
import { importSPKI, CompactEncrypt } from 'jose';

const fetchPublicKey = async () => {
  try {
    const response = await axios('http://localhost:8080/api/public-key');
    console.log(response.data.publicKey);
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
  try {
    console.log('Encrypting payload:', payloadObject);
    const pubKey = await importSPKI(publicKeyPEM, 'RSA-OAEP-256');
    
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payloadObject)))
      .setProtectedHeader({
        alg: 'RSA-OAEP-256',
        enc: 'A128CBC-HS256',
        'issued-by': issuer,
      })
      .encrypt(pubKey);
    console.log('Encryption successful');
    return jwe;
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error(`Encryption failed: ${error.message}`);
  }
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
    
    const requestBody = { payload: encryptedPayload };
    console.log('Request body:', requestBody);

    // Submit to backend
    console.log('Sending request to server:', requestBody);
    const response = await fetch('http://localhost:8080/pay/getPaymentPage', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'key-id': 'KID1739184427260101618445',
      },
      //credentials:'include',
      body: JSON.stringify(requestBody),
    });

    console.log('Response status:', response.status);
    console.log('Response headers:', Object.fromEntries(response.headers.entries()));
    
    const responseText = await response.text();
    console.log('Raw response:', responseText);

    if (!responseText) {
      throw new Error('Empty response from server');
    }

    let data;
    try {
      data = JSON.parse(responseText);
    } catch (e) {
      console.error('Failed to parse response as JSON:', e);
      throw new Error('Invalid JSON response from server');
    }
    
    // Instead of returning the URL, redirect to it
    if (data && data.url) {
      console.log('Redirecting to URL:', data.url);
      window.location.href = data.url;
    } else {
      console.error('No URL in response:', data);
      throw new Error('No URL found in response');
    }
  } catch (error) {
    console.error('Payment processing failed:', error);
    throw error;
  }
};