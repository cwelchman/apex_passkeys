-- MLE wrapper: DER signature to raw 64-byte format
create or replace function fn_pk_der_to_raw (
    p_der_sig_hex in varchar2
) return varchar2 as
    mle module mle_passkey_core env passkey_auth_env signature 'derToRaw(string)';
/

-- MLE wrapper: parse authenticator data
create or replace function fn_pk_parse_auth_data (
    p_auth_data_hex in varchar2
) return varchar2 as
    mle module mle_passkey_core env passkey_auth_env signature 'parseAuthData(string)';
/

-- MLE wrapper: extract public key from attestation object
create or replace function fn_pk_extract_pubkey (
    p_attestation_hex in varchar2
) return varchar2 as
    mle module mle_passkey_core env passkey_auth_env signature 'extractPublicKey(string)';
/

-- Java wrapper: ECDSA P-256 signature verification
create or replace function fn_ecdsa_p256_verify (
    p_pub_x in raw,
    p_pub_y in raw,
    p_sig   in raw,
    p_data  in raw
) return number as
    language java name 'ECDSAVerify.verify(byte[], byte[], byte[], byte[]) return int';
/
