# Passkeys in Oracle APEX — No Provider, No Third-Party Crypto
Implement independant passkey directly on the database.  Using PL/SQL, one Java function, and MLE directly in Oracle APEX using only what ships with Oracle Database 23ai — no Auth0, no Okta, no third-party PL/SQL crypto libraries.

## Prerequisites

Before you start:

- **Oracle Database 23ai** with MLE (Multilingual Engine) support enabled
- **Java runtime** enabled in the database (for ECDSA signature verification)
- **Oracle APEX 23.2+**
- **HTTPS** — WebAuthn flat-out refuses to work over HTTP (localhost is the exception for development)
- A modern browser — Chrome 67+, Firefox 60+, Safari 13+, Edge 79+ all support WebAuthn natively
- `GRANT EXECUTE ON SYS.DBMS_CRYPTO TO <your_schema>` — we use this for random bytes, SHA-256, and HMAC

No third-party PL/SQL packages needed. Everything runs on built-in Oracle Database features.
