create or replace package os_auth as

    -- Constants
    c_challenge_timeout_seconds constant number := 300;
    c_max_challenges_per_session constant number := 10;
    c_algorithm_es256 constant number := -7;
    c_algorithm_rs256 constant number := -257;
    c_flag_user_present constant number := 1;
    c_flag_user_verified constant number := 4;
    c_flag_attested_cred constant number := 64;
    c_default_pbkdf2_iterations constant number := 10000;

    -- Exceptions
    e_invalid_challenge exception;
    e_challenge_expired exception;
    e_challenge_used exception;
    e_invalid_origin exception;
    e_invalid_rp_id exception;
    e_signature_invalid exception;
    e_credential_not_found exception;
    e_credential_inactive exception;
    e_user_verification_failed exception;
    e_user_presence_failed exception;
    e_counter_anomaly exception;
    pragma exception_init ( e_invalid_challenge, -20001 );
    pragma exception_init ( e_challenge_expired, -20002 );
    pragma exception_init ( e_challenge_used, -20003 );
    pragma exception_init ( e_invalid_origin, -20004 );
    pragma exception_init ( e_invalid_rp_id, -20005 );
    pragma exception_init ( e_signature_invalid, -20006 );
    pragma exception_init ( e_credential_not_found, -20007 );
    pragma exception_init ( e_credential_inactive, -20008 );
    pragma exception_init ( e_user_verification_failed, -20009 );
    pragma exception_init ( e_user_presence_failed, -20010 );
    pragma exception_init ( e_counter_anomaly, -20011 );
    e_invalid_password exception;
    e_user_not_found exception;
    e_username_taken exception;
    pragma exception_init ( e_invalid_password, -20012 );
    pragma exception_init ( e_user_not_found, -20013 );
    pragma exception_init ( e_username_taken, -20014 );

    -- Types
    type t_auth_data_rec is record (
            rp_id_hash    raw(32),
            flags         number,
            flag_up       boolean,
            flag_uv       boolean,
            flag_at       boolean,
            sign_count    number,
            aaguid        raw(16),
            credential_id raw(128),
            public_key_x  raw(32),
            public_key_y  raw(32)
    );

    -- Encoding Utilities
    function base64url_encode (
        p_raw in raw
    ) return varchar2;

    function base64url_decode (
        p_str in varchar2
    ) return raw;

    function base64url_decode_str (
        p_base64url in varchar2
    ) return varchar2;

    function base64url_to_raw (
        p_base64url in varchar2
    ) return raw;


    -- Crypto Functions
    function sha256 (
        p_data in raw
    ) return raw;

    function sha256_str (
        p_str in varchar2
    ) return raw;

    function der_to_raw_signature (
        p_der_sig in raw
    ) return raw;

    function verify_ecdsa_p256 (
        p_pub_x in raw,
        p_pub_y in raw,
        p_sig   in raw,
        p_data  in raw
    ) return boolean;


    -- Challenge Management
    function generate_challenge (
        p_user_id        in number default null,
        p_username       in varchar2 default null,
        p_challenge_type in varchar2,
        p_origin         in varchar2 default null,
        p_rp_id          in varchar2 default null,
        p_session_id     in varchar2 default null
    ) return varchar2;

    procedure consume_challenge (
        p_challenge_id in raw
    );

    procedure consume_challenge_by_value (
        p_challenge_value in raw
    );

    procedure cleanup_expired_challenges;


    -- Registration
    function get_registration_options (
        p_user_id           in number,
        p_user_name         in varchar2,
        p_user_display_name in varchar2,
        p_origin            in varchar2,
        p_rp_id             in varchar2,
        p_rp_name           in varchar2
    ) return clob;

    function verify_registration (
        p_user_id              in number,
        p_credential_id_b64    in varchar2,
        p_client_data_json_b64 in varchar2,
        p_attestation_obj_b64  in varchar2,
        p_transports           in varchar2 default null,
        p_credential_name      in varchar2 default null
    ) return raw;

    procedure verify_registration (
        p_user_id              in number,
        p_credential_id_b64    in varchar2,
        p_client_data_json_b64 in varchar2,
        p_attestation_obj_b64  in varchar2,
        p_transports           in varchar2 default null,
        p_credential_name      in varchar2 default null
    );


    -- Authentication
    function get_authentication_options (
        p_user_id   in number default null,
        p_user_name in varchar2 default null,
        p_origin    in varchar2,
        p_rp_id     in varchar2
    ) return clob;

    function verify_authentication (
        p_credential_id_b64    in varchar2,
        p_client_data_json_b64 in varchar2,
        p_auth_data_b64        in varchar2,
        p_signature_b64        in varchar2,
        p_user_handle_b64      in varchar2 default null
    ) return number;


    -- Credential Management
    function ensure_user_exists (
        p_username in varchar2
    ) return os_users.user_id%type;

    function get_user_credentials (
        p_user_id in number
    ) return sys_refcursor;

    function get_credential_count (
        p_user_id     in number,
        p_active_only in boolean default true
    ) return number;

    function has_credentials (
        p_user_id in number
    ) return boolean;

    procedure revoke_credential (
        p_credential_id in raw,
        p_user_id       in number
    );

    procedure revoke_credential (
        p_credential_id_b64 in varchar2,
        p_user_id           in number
    );

    procedure delete_credential (
        p_credential_id in raw,
        p_user_id       in number
    );

    procedure rename_credential (
        p_credential_id   in raw,
        p_user_id         in number,
        p_credential_name in varchar2
    );

    function revoke_all_credentials (
        p_user_id in number
    ) return number;


    -- Parsing
    function parse_authenticator_data (
        p_auth_data in raw
    ) return t_auth_data_rec;

    procedure parse_client_data_json (
        p_client_data_raw in raw,
        p_type            out varchar2,
        p_challenge       out varchar2,
        p_origin          out varchar2
    );


    -- Configuration
    procedure configure (
        p_origin in varchar2,
        p_rp_id  in varchar2
    );


    -- Audit Logging
    procedure log_event (
        p_event_type    in varchar2,
        p_user_id       in number default null,
        p_credential_id in raw default null,
        p_success       in varchar2 default 'Y',
        p_error_message in varchar2 default null
    );


    -- Utility
    function get_apex_origin return varchar2;

    function get_apex_rp_id return varchar2;


    -- Password Authentication
    function hash_password (
        p_password   in varchar2,
        p_salt       in raw,
        p_iterations in number default 10000
    ) return raw;

    function create_user (
        p_username     in varchar2,
        p_password     in varchar2,
        p_display_name in varchar2 default null,
        p_email        in varchar2 default null
    ) return number;

    function verify_password (
        p_username in varchar2,
        p_password in varchar2
    ) return number;

    procedure change_password (
        p_user_id      in number,
        p_old_password in varchar2,
        p_new_password in varchar2
    );

    procedure set_password (
        p_user_id      in number,
        p_new_password in varchar2
    );

end os_auth;
/


-- os_auth_apex: APEX AJAX layer for WebAuthn
create or replace package os_auth_apex as
    ---Thin wrapper that handles JSON I/O via apex_json/htp.p and APEX
    -- parameter extraction. All core logic delegates to os_auth.
    
    -- User identification via v('G_USER_ID') APEX application item.
    

    -- Registration endpoints
    procedure ajax_get_registration_options (
        p_user_name         in varchar2 default null,
        p_user_display_name in varchar2 default null,
        p_credential_name   in varchar2 default null
    );

    procedure ajax_verify_registration (
        p_credential_id    in varchar2,
        p_client_data_json in varchar2,
        p_attestation_obj  in varchar2,
        p_transports       in varchar2 default null,
        p_credential_name  in varchar2 default null
    );

    -- Authentication endpoints
    procedure ajax_get_auth_options;

    procedure ajax_verify_authentication (
        p_credential_id    in varchar2,
        p_client_data_json in varchar2,
        p_auth_data        in varchar2,
        p_signature        in varchar2,
        p_user_handle      in varchar2 default null
    );

    procedure pk_challenge_auth;

    -- Credential management
    procedure ajax_get_credentials;

    procedure ajax_revoke_credential (
        p_credential_id in varchar2
    );


    -- Pre-Login Endpoints (no session user required)
    
    -- APEX custom authentication function (passkey JSON in password field or password)
    function my_authentication (
        p_username in varchar2,
        p_password in varchar2
    ) return boolean;

    -- Pre-login: get auth options by username (no session user yet)
    procedure ajax_get_auth_options_by_user (
        p_username in varchar2
    );

    -- Pre-login registration: get options for new user
    procedure ajax_get_reg_options_new_user (
        p_username     in varchar2,
        p_display_name in varchar2 default null,
        p_email        in varchar2 default null
    );

    -- Pre-login registration: register passkey for new/existing user
    procedure ajax_register_with_passkey (
        p_username         in varchar2,
        p_email            in varchar2 default null,
        p_display_name     in varchar2 default null,
        p_credential_id    in varchar2,
        p_client_data_json in varchar2,
        p_attestation_obj  in varchar2,
        p_transports       in varchar2 default null,
        p_credential_name  in varchar2 default null
    );

end os_auth_apex;
/
