create or replace package body os_auth as


    -- Package-Level Configuration
    g_configured_origin varchar2(500) := null;
    g_configured_rp_id  varchar2(255) := null;


    -- Encoding/Decoding Functions
    function base64url_encode (
        p_raw in raw
    ) return varchar2 is
        l_base64 varchar2(32767);
    begin
        if p_raw is null then
            return null;
        end if;
        l_base64 := utl_raw.cast_to_varchar2(utl_encode.base64_encode(p_raw));
        l_base64 := replace(
            replace(l_base64,
                    chr(13),
                    ''),
            chr(10),
            ''
        );

        l_base64 := replace(
            replace(l_base64, '+', '-'),
            '/',
            '_'
        );

        return rtrim(l_base64, '=');
    end base64url_encode;

    function base64url_decode (
        p_str in varchar2
    ) return raw is
        l_base64 varchar2(32767);
    begin
        if p_str is null then
            return null;
        end if;
        l_base64 := replace(
            replace(p_str, '-', '+'),
            '_',
            '/'
        );

        while mod(
            length(l_base64),
            4
        ) != 0 loop
            l_base64 := l_base64 || '=';
        end loop;

        return utl_encode.base64_decode(utl_raw.cast_to_raw(l_base64));
    end base64url_decode;

    function base64url_decode_str (
        p_base64url in varchar2
    ) return varchar2 is
        v_raw raw(32767);
    begin
        v_raw := base64url_decode(p_base64url);
        return utl_raw.cast_to_varchar2(v_raw);
    exception
        when others then
            raise_application_error(-20102, 'Base64 decode failed: ' || sqlerrm);
    end base64url_decode_str;

    function base64url_to_raw (
        p_base64url in varchar2
    ) return raw is
    begin
        return base64url_decode(p_base64url);
    exception
        when others then
            raise_application_error(-20103, 'Base64 to RAW conversion failed: ' || sqlerrm);
    end base64url_to_raw;


    -- Cryptographic Functions
    function sha256 (
        p_data in raw
    ) return raw is
    begin
        return dbms_crypto.hash(p_data, dbms_crypto.hash_sh256);
    end sha256;

    function sha256_str (
        p_str in varchar2
    ) return raw is
    begin
        return sha256(utl_raw.cast_to_raw(p_str));
    end sha256_str;

    function der_to_raw_signature (
        p_der_sig in raw
    ) return raw is
        l_result varchar2(200);
    begin
        -- Use MLE function for DER to raw conversion
        l_result := fn_pk_der_to_raw(rawtohex(p_der_sig));
        if l_result is null
           or length(l_result) = 0 then
            raise_application_error(-20100, 'Invalid DER signature format');
        end if;

        return hextoraw(l_result);
    exception
        when others then
            -- Fallback to PL/SQL implementation if MLE fails
            apex_debug.warn('der_to_raw_signature MLE fallback: %s', sqlerrm);
            declare
                l_sig    raw(256);
                l_offset number := 1;
                l_r_len  number;
                l_s_len  number;
                l_r      raw(33);
                l_s      raw(33);
            begin
                l_sig := p_der_sig;
                if utl_raw.substr(l_sig, l_offset, 1) != '30' then
                    raise_application_error(-20100, 'Invalid DER signature');
                end if;

                l_offset := l_offset + 2;
                if utl_raw.substr(l_sig, l_offset, 1) != '02' then
                    raise_application_error(-20100, 'Invalid DER signature');
                end if;

                l_offset := l_offset + 1;
                l_r_len := to_number ( rawtohex(utl_raw.substr(l_sig, l_offset, 1)), 'XX' );

                l_offset := l_offset + 1;
                l_r := utl_raw.substr(l_sig, l_offset, l_r_len);
                l_offset := l_offset + l_r_len;
                if utl_raw.substr(l_sig, l_offset, 1) != '02' then
                    raise_application_error(-20100, 'Invalid DER signature');
                end if;

                l_offset := l_offset + 1;
                l_s_len := to_number ( rawtohex(utl_raw.substr(l_sig, l_offset, 1)), 'XX' );

                l_offset := l_offset + 1;
                l_s := utl_raw.substr(l_sig, l_offset, l_s_len);
                while
                    utl_raw.length(l_r) > 32
                    and utl_raw.substr(l_r, 1, 1) = '00'
                loop
                    l_r := utl_raw.substr(l_r, 2);
                end loop;

                if utl_raw.length(l_r) < 32 then
                    l_r := utl_raw.concat(
                        utl_raw.copies('00',
                                       32 - utl_raw.length(l_r)),
                        l_r
                    );
                end if;

                while
                    utl_raw.length(l_s) > 32
                    and utl_raw.substr(l_s, 1, 1) = '00'
                loop
                    l_s := utl_raw.substr(l_s, 2);
                end loop;

                if utl_raw.length(l_s) < 32 then
                    l_s := utl_raw.concat(
                        utl_raw.copies('00',
                                       32 - utl_raw.length(l_s)),
                        l_s
                    );
                end if;

                return utl_raw.concat(
                    utl_raw.substr(l_r, 1, 32),
                    utl_raw.substr(l_s, 1, 32)
                );

            end;

    end der_to_raw_signature;

    function verify_ecdsa_p256 (
        p_pub_x in raw,
        p_pub_y in raw,
        p_sig   in raw,
        p_data  in raw
    ) return boolean is
        l_result number;
    begin
        -- Verify ECDSA P-256 signature via Java stored procedure
        -- p_sig is DER-encoded from WebAuthn browser API
        -- p_data is authData || SHA-256(clientDataJSON)
        -- Java SHA256withECDSA handles DER natively and hashes p_data internally
        l_result := fn_ecdsa_p256_verify(p_pub_x, p_pub_y, p_sig, p_data);
        return l_result = 1;
    end verify_ecdsa_p256;


    -- Parsing Functions (using MLE)
    procedure parse_client_data_json (
        p_client_data_raw in raw,
        p_type            out varchar2,
        p_challenge       out varchar2,
        p_origin          out varchar2
    ) is
        l_json varchar2(32767);
    begin
        l_json := utl_raw.cast_to_varchar2(p_client_data_raw);
        p_type := json_value(l_json, '$.type');
        p_challenge := json_value(l_json, '$.challenge');
        p_origin := json_value(l_json, '$.origin');
    end parse_client_data_json;

    function parse_authenticator_data (
        p_auth_data in raw
    ) return t_auth_data_rec is

        l_result   t_auth_data_rec;
        l_mle_json varchar2(4000);
        l_auth_len number;
        l_flags    number;
        l_cred_len number;
        l_offset   number := 1;
    begin
        l_auth_len := utl_raw.length(p_auth_data);

        -- Try MLE parsing first
        begin
            l_mle_json := fn_pk_parse_auth_data(rawtohex(p_auth_data));
            if
                l_mle_json is not null
                and json_value(l_mle_json, '$.error') is null
            then
                l_result.rp_id_hash := hextoraw(json_value(l_mle_json, '$.rpIdHash'));
                l_result.flag_up := json_value(l_mle_json, '$.flags.up' returning number) = 1;
                l_result.flag_uv := json_value(l_mle_json, '$.flags.uv' returning number) = 1;
                l_result.flag_at := json_value(l_mle_json, '$.flags.at' returning number) = 1;
                l_result.sign_count := json_value(l_mle_json, '$.signCount' returning number);
                if json_value(l_mle_json, '$.aaguid') is not null then
                    l_result.aaguid := hextoraw(json_value(l_mle_json, '$.aaguid'));
                end if;

                if json_value(l_mle_json, '$.credentialId') is not null then
                    l_result.credential_id := hextoraw(json_value(l_mle_json, '$.credentialId'));
                end if;

                -- Calculate flags byte
                l_result.flags := 0;
                if l_result.flag_up then
                    l_result.flags := l_result.flags + c_flag_user_present;
                end if;

                if l_result.flag_uv then
                    l_result.flags := l_result.flags + c_flag_user_verified;
                end if;

                if l_result.flag_at then
                    l_result.flags := l_result.flags + c_flag_attested_cred;
                end if;

                return l_result;
            end if;

        exception
            when others then
                apex_debug.warn('parse_authenticator_data MLE fallback: %s', sqlerrm);
        end;

        -- Fallback to PL/SQL parsing
        l_result.rp_id_hash := utl_raw.substr(p_auth_data, l_offset, 32);
        l_offset := l_offset + 32;
        l_flags := to_number ( rawtohex(utl_raw.substr(p_auth_data, l_offset, 1)), 'XX' );

        l_result.flags := l_flags;
        l_result.flag_up := bitand(l_flags, c_flag_user_present) != 0;
        l_result.flag_uv := bitand(l_flags, c_flag_user_verified) != 0;
        l_result.flag_at := bitand(l_flags, c_flag_attested_cred) != 0;
        l_offset := l_offset + 1;
        l_result.sign_count := to_number ( rawtohex(utl_raw.substr(p_auth_data, l_offset, 4)), 'XXXXXXXX' );

        l_offset := l_offset + 4;
        if
            l_result.flag_at
            and l_auth_len > 37
        then
            l_result.aaguid := utl_raw.substr(p_auth_data, l_offset, 16);
            l_offset := l_offset + 16;
            l_cred_len := to_number ( rawtohex(utl_raw.substr(p_auth_data, l_offset, 2)), 'XXXX' );

            l_offset := l_offset + 2;
            l_result.credential_id := utl_raw.substr(p_auth_data, l_offset, l_cred_len);
        end if;

        return l_result;
    end parse_authenticator_data;


    -- Challenge Management
    function generate_challenge (
        p_user_id        in number default null,
        p_username       in varchar2 default null,
        p_challenge_type in varchar2,
        p_origin         in varchar2 default null,
        p_rp_id          in varchar2 default null,
        p_session_id     in varchar2 default null
    ) return varchar2 is

        l_challenge_id    raw(32);
        l_challenge_value raw(32);
        l_expires_at      timestamp;
        l_session_id      varchar2(100);
        l_ip_address      varchar2(45);
        l_origin          varchar2(500);
        l_rp_id           varchar2(255);
        l_recent_count    number;
    begin
        l_challenge_id := dbms_crypto.randombytes(32);
        l_challenge_value := dbms_crypto.randombytes(32);
        l_expires_at := systimestamp + numtodsinterval(c_challenge_timeout_seconds, 'SECOND');
        l_session_id := nvl(p_session_id,
                            v('APP_SESSION'));

        -- Get IP address safely
        begin
            l_ip_address := owa_util.get_cgi_env('REMOTE_ADDR');
        exception
            when others then
                apex_debug.warn('generate_challenge IP fallback: %s', sqlerrm);
                l_ip_address := sys_context('USERENV', 'IP_ADDRESS');
        end;

        -- Rate limit: max challenges per session within timeout window
        select count(*)
          into l_recent_count
          from os_auth_challenges
         where session_id = l_session_id
           and created_at > systimestamp - numtodsinterval(c_challenge_timeout_seconds, 'SECOND');

        if l_recent_count >= c_max_challenges_per_session then
            raise_application_error(-20104, 'Rate limit exceeded: too many challenge requests');
        end if;

        -- Default origin/rp_id from APEX context if not provided
        l_origin := nvl(p_origin, get_apex_origin);
        l_rp_id := nvl(p_rp_id, get_apex_rp_id);

        -- Invalidate any existing unused challenges for this user/type
        update os_auth_challenges
           set used_at = systimestamp
         where challenge_type = p_challenge_type
           and used_at is null
           and ( ( p_user_id is not null
                    and user_id = p_user_id )
                  or ( p_username is not null
                       and lower(username) = lower(p_username) ) );

        insert into os_auth_challenges (
            challenge_id,
            user_id,
            username,
            challenge_type,
            challenge_value,
            origin,
            rp_id,
            session_id,
            ip_address,
            created_at,
            expires_at
        ) values ( l_challenge_id,
                   p_user_id,
                   p_username,
                   p_challenge_type,
                   l_challenge_value,
                   l_origin,
                   l_rp_id,
                   l_session_id,
                   l_ip_address,
                   systimestamp,
                   l_expires_at );

        return base64url_encode(l_challenge_value);
    end generate_challenge;

    procedure consume_challenge (
        p_challenge_id in raw
    ) is
    begin
        update os_auth_challenges
           set used_at = systimestamp
         where challenge_id = p_challenge_id;

    end consume_challenge;

    procedure consume_challenge_by_value (
        p_challenge_value in raw
    ) is
    begin
        update os_auth_challenges
           set used_at = systimestamp
         where challenge_value = p_challenge_value
           and used_at is null;

    end consume_challenge_by_value;

    procedure cleanup_expired_challenges is
        pragma autonomous_transaction;
    begin
        delete from os_auth_challenges
        where expires_at < systimestamp - interval '1' day
           or used_at < systimestamp - interval '1' day;

        commit;
    end cleanup_expired_challenges;


    -- Registration Functions
    function get_registration_options (
        p_user_id           in number,
        p_user_name         in varchar2,
        p_user_display_name in varchar2,
        p_origin            in varchar2,
        p_rp_id             in varchar2,
        p_rp_name           in varchar2
    ) return clob is
        l_challenge     varchar2(100);
        l_user_id_b64   varchar2(100);
        l_exclude_creds clob;
        l_result        clob;
    begin
        l_challenge := generate_challenge(
            p_user_id        => p_user_id,
            p_challenge_type => 'REGISTRATION',
            p_origin         => p_origin,
            p_rp_id          => p_rp_id
        );

        l_user_id_b64 := base64url_encode(utl_raw.cast_to_raw(to_char(p_user_id)));
        select
            nvl(
                json_arrayagg(
                    json_object(
                        'id' value base64url_encode(credential_id),
                                'transports' value
                            json(
                                nvl(transports, '["usb","nfc"]')
                            )
                    )
                returning clob),
                '[]'
            )
         into l_exclude_creds
         from os_auth_credentials
        where user_id = p_user_id
          and is_active = 'Y';

        select
            json_object(
                'challenge' value l_challenge,
                        'rpId' value p_rp_id,
                        'rpName' value p_rp_name,
                        'userId' value l_user_id_b64,
                        'userName' value p_user_name,
                        'userDisplayName' value p_user_display_name,
                        'excludeCredentials' value
                    json(l_exclude_creds)
            returning clob)
        into l_result
        from dual;

        return l_result;
    end get_registration_options;

    function verify_registration (
        p_user_id              in number,
        p_credential_id_b64    in varchar2,
        p_client_data_json_b64 in varchar2,
        p_attestation_obj_b64  in varchar2,
        p_transports           in varchar2 default null,
        p_credential_name      in varchar2 default null
    ) return raw is

        l_cred_id_raw     raw(1024);
        l_client_data_raw raw(32767);
        l_attestation_raw raw(32767);
        l_type            varchar2(50);
        l_challenge_b64   varchar2(100);
        l_origin          varchar2(500);
        l_challenge_raw   raw(32);
        l_challenge_rec   os_auth_challenges%rowtype;
        l_public_key_x    raw(32);
        l_public_key_y    raw(32);
        l_aaguid          raw(16);
        l_attestation_fmt varchar2(50);
        l_exists          number;
        l_pub_key_json    varchar2(4000);
    begin
        l_cred_id_raw := base64url_decode(p_credential_id_b64);
        l_client_data_raw := base64url_decode(p_client_data_json_b64);
        l_attestation_raw := base64url_decode(p_attestation_obj_b64);
        parse_client_data_json(l_client_data_raw, l_type, l_challenge_b64, l_origin);
        if l_type != 'webauthn.create' then
            raise_application_error(-20001, 'Invalid ceremony type');
        end if;
        l_challenge_raw := base64url_decode(l_challenge_b64);
        begin
            select *
              into l_challenge_rec
              from os_auth_challenges
             where challenge_value = l_challenge_raw
               and challenge_type = 'REGISTRATION'
               and used_at is null
               and ( user_id = p_user_id
                      or user_id is null )
            for update nowait;

        exception
            when no_data_found then
                raise e_invalid_challenge;
        end;

        if l_challenge_rec.expires_at < systimestamp then
            raise e_challenge_expired;
        end if;
        if l_origin != l_challenge_rec.origin then
            raise e_invalid_origin;
        end if;
        consume_challenge(l_challenge_rec.challenge_id);

        -- Extract public key using MLE function (no fallback -- MLE is required)
        l_pub_key_json := fn_pk_extract_pubkey(rawtohex(l_attestation_raw));
        if l_pub_key_json is null
           or json_value(l_pub_key_json, '$.error') is not null then
            raise_application_error(-20100,
                                    'Public key extraction failed'
                                    ||
                case
                    when l_pub_key_json is not null then
                        ': ' || json_value(l_pub_key_json, '$.error')
                end
            );
        end if;

        l_public_key_x := hextoraw(json_value(l_pub_key_json, '$.x'));
        l_public_key_y := hextoraw(json_value(l_pub_key_json, '$.y'));
        if json_value(l_pub_key_json, '$.aaguid') is not null then
            l_aaguid := hextoraw(json_value(l_pub_key_json, '$.aaguid'));
        end if;

        l_attestation_fmt := json_value(l_pub_key_json, '$.fmt');
        select
            count(*)
        into l_exists
        from
            os_auth_credentials
        where
            credential_id = l_cred_id_raw;

        if l_exists > 0 then
            raise_application_error(-20020, 'Credential already registered');
        end if;
        insert into os_auth_credentials (
            credential_id,
            user_id,
            public_key_x,
            public_key_y,
            public_key_algorithm,
            aaguid,
            sign_count,
            credential_name,
            transports,
            attestation_fmt,
            attestation_data,
            is_active
        ) values ( l_cred_id_raw,
                   p_user_id,
                   l_public_key_x,
                   l_public_key_y,
                   c_algorithm_es256,
                   l_aaguid,
                   0,
                   nvl(p_credential_name,
                       'YubiKey ' || to_char(sysdate, 'YYYY-MM-DD')),
                   p_transports,
                   nvl(l_attestation_fmt, 'none'),
                   l_attestation_raw,
                   'Y' );

        log_event('REGISTRATION', p_user_id, l_cred_id_raw);
        return l_cred_id_raw;
    end verify_registration;

    procedure verify_registration (
        p_user_id              in number,
        p_credential_id_b64    in varchar2,
        p_client_data_json_b64 in varchar2,
        p_attestation_obj_b64  in varchar2,
        p_transports           in varchar2 default null,
        p_credential_name      in varchar2 default null
    ) is
        l_cred_id raw(1024);
    begin
        l_cred_id := verify_registration(p_user_id, p_credential_id_b64, p_client_data_json_b64, p_attestation_obj_b64, p_transports,
                                         p_credential_name);
    end verify_registration;


    -- Authentication Functions
    function get_authentication_options (
        p_user_id   in number default null,
        p_user_name in varchar2 default null,
        p_origin    in varchar2,
        p_rp_id     in varchar2
    ) return clob is
        l_challenge   varchar2(100);
        l_allow_creds clob;
        l_result      clob;
    begin
        l_challenge := generate_challenge(
            p_user_id        => p_user_id,
            p_challenge_type => 'AUTHENTICATION',
            p_origin         => p_origin,
            p_rp_id          => p_rp_id
        );

        if p_user_id is not null then
            select
                nvl(
                    json_arrayagg(
                        json_object(
                            'id' value base64url_encode(credential_id),
                                    'transports' value
                                json(
                                    nvl(transports, '["usb","nfc"]')
                                )
                        )
                    returning clob),
                    '[]'
                )
             into l_allow_creds
             from os_auth_credentials
            where user_id = p_user_id
              and is_active = 'Y';

        else
            l_allow_creds := '[]';
        end if;

        select
            json_object(
                'challenge' value l_challenge,
                        'rpId' value p_rp_id,
                        'allowCredentials' value
                    json(l_allow_creds)
            returning clob)
        into l_result
        from dual;

        return l_result;
    end get_authentication_options;

    function verify_authentication (
        p_credential_id_b64    in varchar2,
        p_client_data_json_b64 in varchar2,
        p_auth_data_b64        in varchar2,
        p_signature_b64        in varchar2,
        p_user_handle_b64      in varchar2 default null
    ) return number is

        l_cred_id_raw      raw(1024);
        l_client_data_raw  raw(32767);
        l_auth_data_raw    raw(32767);
        l_signature_raw    raw(256);
        l_type             varchar2(50);
        l_challenge_b64    varchar2(100);
        l_origin           varchar2(500);
        l_challenge_raw    raw(32);
        l_challenge_rec    os_auth_challenges%rowtype;
        l_auth_data_rec    t_auth_data_rec;
        l_expected_rp_hash raw(32);
        l_client_data_hash raw(32);
        l_sign_data        raw(32767);
        l_signature_valid  boolean;
        -- credential fields
        l_cred_user_id     number;
        l_pub_key_x        raw(32);
        l_pub_key_y        raw(32);
        l_sign_count       number;
        l_is_active        varchar2(1);
    begin
        l_cred_id_raw := base64url_decode(p_credential_id_b64);
        l_client_data_raw := base64url_decode(p_client_data_json_b64);
        l_auth_data_raw := base64url_decode(p_auth_data_b64);
        l_signature_raw := base64url_decode(p_signature_b64);

        -- Look up credential from os_auth_credentials
        begin
            select user_id,
                   public_key_x,
                   public_key_y,
                   sign_count,
                   is_active
              into l_cred_user_id,
                   l_pub_key_x,
                   l_pub_key_y,
                   l_sign_count,
                   l_is_active
              from os_auth_credentials
             where credential_id = l_cred_id_raw;

        exception
            when no_data_found then
                raise e_credential_not_found;
        end;

        if l_is_active != 'Y' then
            raise e_credential_inactive;
        end if;
        parse_client_data_json(l_client_data_raw, l_type, l_challenge_b64, l_origin);
        if l_type != 'webauthn.get' then
            raise_application_error(-20001, 'Invalid ceremony type');
        end if;
        l_challenge_raw := base64url_decode(l_challenge_b64);
        begin
            select *
              into l_challenge_rec
              from os_auth_challenges
             where challenge_value = l_challenge_raw
               and challenge_type = 'AUTHENTICATION'
               and used_at is null
               and ( user_id = l_cred_user_id
                      or user_id is null )
            for update nowait;

        exception
            when no_data_found then
                raise e_invalid_challenge;
        end;

        if l_challenge_rec.expires_at < systimestamp then
            raise e_challenge_expired;
        end if;
        if l_origin != l_challenge_rec.origin then
            raise e_invalid_origin;
        end if;
        consume_challenge(l_challenge_rec.challenge_id);

        -- Parse authenticator data using MLE
        l_auth_data_rec := parse_authenticator_data(l_auth_data_raw);
        l_expected_rp_hash := sha256_str(l_challenge_rec.rp_id);
        if l_auth_data_rec.rp_id_hash != l_expected_rp_hash then
            raise e_invalid_rp_id;
        end if;

        -- FIPS compliance: require user presence and verification
        if not l_auth_data_rec.flag_up then
            raise e_user_presence_failed;
        end if;
        if not l_auth_data_rec.flag_uv then
            raise e_user_verification_failed;
        end if;

        -- Anti-cloning: check signature counter
        if
            l_auth_data_rec.sign_count > 0
            and l_auth_data_rec.sign_count <= l_sign_count
        then
            log_event('COUNTER_ANOMALY', l_cred_user_id, l_cred_id_raw, 'N', 'Expected >'
                                                                             || l_sign_count
                                                                             || ' got '
                                                                             || l_auth_data_rec.sign_count);

            raise e_counter_anomaly;
        end if;

        -- Build signature verification data
        l_client_data_hash := sha256(l_client_data_raw);
        l_sign_data := utl_raw.concat(l_auth_data_raw, l_client_data_hash);

        -- Verify signature -- public key is required
        if l_pub_key_x is null
           or l_pub_key_y is null then
            raise e_signature_invalid;
        end if;
        l_signature_valid := verify_ecdsa_p256(l_pub_key_x, l_pub_key_y, l_signature_raw, l_sign_data);
        if not l_signature_valid then
            raise e_signature_invalid;
        end if;
        update os_auth_credentials
        set
            sign_count = l_auth_data_rec.sign_count,
            last_used_at = systimestamp
        where
            credential_id = l_cred_id_raw;

        log_event('AUTHENTICATION', l_cred_user_id, l_cred_id_raw);
        return l_cred_user_id;
    end verify_authentication;


    -- Credential Management

    function ensure_user_exists (
        p_username in varchar2
    ) return os_users.user_id%type is
        v_user_id os_users.user_id%type;
    begin
        begin
            select user_id
              into v_user_id
              from os_users
            where lower(username) = lower(p_username);

        exception
            when no_data_found then
                apex_debug.warn('ensure_user_exists no user found');
                return null;
        end;

        return v_user_id;
    end ensure_user_exists;

    function get_user_credentials (
        p_user_id in number
    ) return sys_refcursor is
        l_cursor sys_refcursor;
    begin
        open l_cursor for select credential_id,
                                 base64url_encode(credential_id) as credential_id_b64,
                                 credential_name,
                                 created_at,
                                 last_used_at,
                                 sign_count,
                                 is_active,
                                 transports,
                                 aaguid,
                                 credential_device_type
                            from os_auth_credentials
                           where user_id = p_user_id
                           order by created_at desc;

        return l_cursor;
    end get_user_credentials;

    function get_credential_count (
        p_user_id     in number,
        p_active_only in boolean default true
    ) return number is
        l_count number;
    begin
        if p_active_only then
            select count(*)
              into l_count
              from os_auth_credentials
             where user_id = p_user_id
               and is_active = 'Y';

        else
            select count(*)
              into l_count
              from os_auth_credentials
             where user_id = p_user_id;

        end if;

        return l_count;
    end get_credential_count;

    function has_credentials (
        p_user_id in number
    ) return boolean is
        l_count number;
    begin
        select count(*)
          into l_count
          from os_auth_credentials
         where user_id = p_user_id
           and is_active = 'Y'
           and rownum = 1;

        return l_count > 0;
    end has_credentials;

    procedure revoke_credential (
        p_credential_id in raw,
        p_user_id       in number
    ) is
    begin
        update os_auth_credentials
        set
            is_active = 'N'
        where
                credential_id = p_credential_id
            and user_id = p_user_id;

        if sql%rowcount = 0 then
            raise_application_error(-20030, 'Credential not found');
        end if;
        log_event('REVOKE_CREDENTIAL', p_user_id, p_credential_id);
    end revoke_credential;

    procedure revoke_credential (
        p_credential_id_b64 in varchar2,
        p_user_id           in number
    ) is
        l_credential_id raw(1024);
    begin
        l_credential_id := base64url_decode(p_credential_id_b64);
        update os_auth_credentials
        set
            is_active = 'N'
        where
                credential_id = l_credential_id
            and user_id = p_user_id;

        if sql%rowcount = 0 then
            raise_application_error(-20030, 'Credential not found');
        end if;
        log_event('REVOKE_CREDENTIAL', p_user_id, l_credential_id);
    end revoke_credential;

    procedure delete_credential (
        p_credential_id in raw,
        p_user_id       in number
    ) is
    begin
        delete from os_auth_credentials
         where credential_id = p_credential_id
           and user_id = p_user_id;

        if sql%rowcount = 0 then
            raise_application_error(-20008, 'Credential not found or does not belong to user');
        end if;
    end delete_credential;

    procedure rename_credential (
        p_credential_id   in raw,
        p_user_id         in number,
        p_credential_name in varchar2
    ) is
    begin
        update os_auth_credentials
           set credential_name = p_credential_name
         where credential_id = p_credential_id
           and user_id = p_user_id;

        if sql%rowcount = 0 then
            raise_application_error(-20030, 'Credential not found');
        end if;
    end rename_credential;

    function revoke_all_credentials (
        p_user_id in number
    ) return number is
        l_count number;
    begin
        update os_auth_credentials
           set is_active = 'N'
         where user_id = p_user_id
           and is_active = 'Y';

        l_count := sql%rowcount;
        return l_count;
    end revoke_all_credentials;


    -- Audit Logging
    procedure log_event (
        p_event_type    in varchar2,
        p_user_id       in number default null,
        p_credential_id in raw default null,
        p_success       in varchar2 default 'Y',
        p_error_message in varchar2 default null
    ) is
        pragma autonomous_transaction;
        l_ip_address varchar2(45);
        l_session_id varchar2(100);
    begin
        begin
            l_ip_address := owa_util.get_cgi_env('REMOTE_ADDR');
        exception
            when others then
                l_ip_address := sys_context('USERENV', 'IP_ADDRESS');
        end;

        l_session_id := v('APP_SESSION');
        insert into os_auth_audit_log (
            event_type,
            user_id,
            credential_id,
            success,
            ip_address,
            session_id,
            error_message
        ) values ( p_event_type,
                   p_user_id,
                   p_credential_id,
                   p_success,
                   l_ip_address,
                   l_session_id,
                   substr(p_error_message, 1, 4000) );

        commit;
    exception
        when others then
            rollback;
            apex_debug.warn('os_auth.log_event failed: %s', sqlerrm);
    end log_event;


    -- Configuration
    procedure configure (
        p_origin in varchar2,
        p_rp_id  in varchar2
    ) is
    begin
        g_configured_origin := p_origin;
        g_configured_rp_id := p_rp_id;
    end configure;


    -- Utility Functions


    function get_apex_origin return varchar2 is
        l_host varchar2(500);
    begin
        if g_configured_origin is not null then
            return g_configured_origin;
        end if;
        begin
            l_host := owa_util.get_cgi_env('HTTP_HOST');
        exception
            when others then
                apex_debug.warn('get_apex_origin HTTP_HOST fallback: %s', sqlerrm);
                l_host := 'localhost';
        end;

        return 'https://' || l_host;
    end get_apex_origin;

    function get_apex_rp_id return varchar2 is
        l_host     varchar2(500);
        l_port_pos number;
    begin
        if g_configured_rp_id is not null then
            return g_configured_rp_id;
        end if;
        begin
            l_host := owa_util.get_cgi_env('HTTP_HOST');
        exception
            when others then
                apex_debug.warn('get_apex_rp_id HTTP_HOST fallback: %s', sqlerrm);
                l_host := 'localhost';
        end;

        l_port_pos := instr(l_host, ':');
        if l_port_pos > 0 then
            l_host := substr(l_host, 1, l_port_pos - 1);
        end if;

        return l_host;
    end get_apex_rp_id;


    -- Password Authentication
    function hash_password (
        p_password   in varchar2,
        p_salt       in raw,
        p_iterations in number default 10000
    ) return raw is
        l_password_raw raw(32767);
        l_u            raw(32);
        l_result       raw(32);
    begin
        l_password_raw := utl_raw.cast_to_raw(p_password);

        -- PBKDF2-HMAC-SHA256: U1 = HMAC-SHA256(password, salt || 0x00000001)
        l_u := dbms_crypto.mac(
            src => utl_raw.concat(p_salt,
                                  hextoraw('00000001')),
            typ => dbms_crypto.hmac_sh256,
            key => l_password_raw
        );

        l_result := l_u;

        -- Iterate: Ui = HMAC-SHA256(password, U_{i-1}), result ^= Ui
        for i in 2..p_iterations loop
            l_u := dbms_crypto.mac(
                src => l_u,
                typ => dbms_crypto.hmac_sh256,
                key => l_password_raw
            );

            l_result := utl_raw.bit_xor(l_result, l_u);
        end loop;

        return l_result;
    end hash_password;

    function create_user (
        p_username     in varchar2,
        p_password     in varchar2,
        p_display_name in varchar2 default null,
        p_email        in varchar2 default null
    ) return number is
        l_salt     raw(32);
        l_hash     raw(32);
        l_user_id  number;
        l_existing number;
    begin
        -- Check for existing username
        select count(*)
          into l_existing
          from os_users
         where lower(username) = lower(p_username);

        if l_existing > 0 then
            raise e_username_taken;
        end if;
        l_salt := dbms_crypto.randombytes(32);
        l_hash := hash_password(p_password, l_salt, c_default_pbkdf2_iterations);
        insert into os_users (
            username,
            display_name,
            email,
            password_hash,
            password_salt,
            password_iterations,
            password_changed_at
        ) values ( p_username,
                   p_display_name,
                   p_email,
                   l_hash,
                   l_salt,
                   c_default_pbkdf2_iterations,
                   systimestamp ) returning user_id into l_user_id;

        log_event('USER_CREATED', l_user_id);
        return l_user_id;
    end create_user;

    function verify_password (
        p_username in varchar2,
        p_password in varchar2
    ) return number is

        l_user_id    number;
        l_hash       raw(32);
        l_salt       raw(32);
        l_iterations number;
        l_is_active  varchar2(1);
        l_check_hash raw(32);
    begin
        begin
            select user_id,
                   password_hash,
                   password_salt,
                   password_iterations,
                   is_active
              into l_user_id,
                   l_hash,
                   l_salt,
                   l_iterations,
                   l_is_active
              from os_users
             where lower(username) = lower(p_username);

        exception
            when no_data_found then
                return null;
        end;

        if l_is_active != 'Y' then
            return null;
        end if;
        if l_hash is null
           or l_salt is null then
            return null;
        end if;
        l_check_hash := hash_password(p_password, l_salt, l_iterations);
        if l_check_hash = l_hash then
            update os_users
            set
                last_login_at = systimestamp
            where
                user_id = l_user_id;

            log_event('PASSWORD_LOGIN', l_user_id);
            return l_user_id;
        end if;

        log_event('PASSWORD_LOGIN', l_user_id, null, 'N', 'Invalid password');
        return null;
    end verify_password;

    procedure change_password (
        p_user_id      in number,
        p_old_password in varchar2,
        p_new_password in varchar2
    ) is

        l_hash       raw(32);
        l_salt       raw(32);
        l_iterations number;
        l_check_hash raw(32);
        l_new_salt   raw(32);
        l_new_hash   raw(32);
    begin
        begin
            select password_hash,
                   password_salt,
                   password_iterations
              into l_hash,
                   l_salt,
                   l_iterations
              from os_users
             where user_id = p_user_id;

        exception
            when no_data_found then
                raise e_user_not_found;
        end;

        if l_hash is null
           or l_salt is null then
            raise e_invalid_password;
        end if;
        l_check_hash := hash_password(p_old_password, l_salt, l_iterations);
        if l_check_hash != l_hash then
            raise e_invalid_password;
        end if;
        l_new_salt := dbms_crypto.randombytes(32);
        l_new_hash := hash_password(p_new_password, l_new_salt, c_default_pbkdf2_iterations);
        update os_users
        set
            password_hash = l_new_hash,
            password_salt = l_new_salt,
            password_iterations = c_default_pbkdf2_iterations,
            password_changed_at = systimestamp,
            updated_at = systimestamp
        where
            user_id = p_user_id;

        log_event('PASSWORD_CHANGED', p_user_id);
    end change_password;

    procedure set_password (
        p_user_id      in number,
        p_new_password in varchar2
    ) is
        l_salt   raw(32);
        l_hash   raw(32);
        l_exists number;
    begin
        select count(*)
          into l_exists
          from os_users
         where user_id = p_user_id;

        if l_exists = 0 then
            raise e_user_not_found;
        end if;
        l_salt := dbms_crypto.randombytes(32);
        l_hash := hash_password(p_new_password, l_salt, c_default_pbkdf2_iterations);
        update os_users
        set
            password_hash = l_hash,
            password_salt = l_salt,
            password_iterations = c_default_pbkdf2_iterations,
            password_changed_at = systimestamp,
            updated_at = systimestamp
        where
            user_id = p_user_id;

        log_event('PASSWORD_SET', p_user_id);
    end set_password;

end os_auth;
/


-- os_auth_apex body: APEX AJAX layer
create or replace package body os_auth_apex as


    -- Private Helpers
    function get_current_user_id return number is
        l_user_id number;
    begin
        l_user_id := v('G_USER_ID');
        return l_user_id;
    end get_current_user_id;

    procedure send_error_response (
        p_error in varchar2
    ) is
    begin
        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', false);
        apex_json.write('error', p_error);
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    end send_error_response;

    function is_valid_base64url (
        p_str     in varchar2,
        p_max_len in number default 4000
    ) return boolean is
    begin
        if p_str is null
           or length(p_str) = 0 then
            return false;
        end if;
        if length(p_str) > p_max_len then
            return false;
        end if;
        if regexp_like(p_str, '[^A-Za-z0-9_-]') then
            return false;
        end if;
        return true;
    end is_valid_base64url;


    -- Registration Endpoints
    procedure ajax_get_registration_options (
        p_user_name         in varchar2 default null,
        p_user_display_name in varchar2 default null,
        p_credential_name   in varchar2 default null
    ) is

        l_user_id      number;
        l_user_name    varchar2(255);
        l_display_name varchar2(255);
        l_origin       varchar2(500);
        l_rp_id        varchar2(255);
        l_options      clob;
    begin
        l_user_id := get_current_user_id;
        if l_user_id is null then
            send_error_response('User not authenticated');
            return;
        end if;
        l_user_name := nvl(p_user_name,
                           v('APP_USER'));
        l_display_name := nvl(p_user_display_name,
                              v('APP_USER'));

        -- Input validation
        if
            p_user_name is not null
            and length(p_user_name) > 255
        then
            send_error_response('Invalid input');
            return;
        end if;

        if
            p_user_display_name is not null
            and length(p_user_display_name) > 255
        then
            send_error_response('Invalid input');
            return;
        end if;

        if
            p_credential_name is not null
            and length(p_credential_name) > 255
        then
            send_error_response('Invalid input');
            return;
        end if;

        l_origin := os_auth.get_apex_origin;
        l_rp_id := os_auth.get_apex_rp_id;
        l_options := os_auth.get_registration_options(l_user_id, l_user_name, l_display_name, l_origin, l_rp_id,
                                                      l_rp_id);

        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write_raw('options', l_options);
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_get_registration_options: %s', sqlerrm);
            send_error_response('Registration options failed');
    end ajax_get_registration_options;

    procedure ajax_verify_registration (
        p_credential_id    in varchar2,
        p_client_data_json in varchar2,
        p_attestation_obj  in varchar2,
        p_transports       in varchar2 default null,
        p_credential_name  in varchar2 default null
    ) is
        l_user_id   number;
        l_cred_id   raw(1024);
        l_cred_name varchar2(255);
    begin
        l_user_id := get_current_user_id;
        if l_user_id is null then
            send_error_response('User not authenticated');
            return;
        end if;

        -- Input validation
        if not is_valid_base64url(p_credential_id, 2048) then
            send_error_response('Invalid credential_id format');
            return;
        end if;

        if not is_valid_base64url(p_client_data_json, 8000) then
            send_error_response('Invalid client_data_json format');
            return;
        end if;

        if not is_valid_base64url(p_attestation_obj, 32000) then
            send_error_response('Invalid attestation_obj format');
            return;
        end if;

        if
            p_credential_name is not null
            and length(p_credential_name) > 255
        then
            send_error_response('Invalid input');
            return;
        end if;

        l_cred_name := nvl(
            nullif(p_credential_name, ''),
            'YubiKey ' || to_char(sysdate, 'YYYY-MM-DD HH24:MI')
        );

        l_cred_id := os_auth.verify_registration(l_user_id, p_credential_id, p_client_data_json, p_attestation_obj, p_transports,
                                                 l_cred_name);

        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write('credentialId',
                        os_auth.base64url_encode(l_cred_id));
        apex_json.write('message', 'Credential registered successfully');
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_verify_registration: %s', sqlerrm);
            send_error_response('Registration verification failed');
    end ajax_verify_registration;


    -- Authentication Endpoints
    procedure ajax_get_auth_options is
        l_user_id number;
        l_origin  varchar2(500);
        l_rp_id   varchar2(255);
        l_options clob;
    begin
        l_user_id := get_current_user_id;
        l_origin := os_auth.get_apex_origin;
        l_rp_id := os_auth.get_apex_rp_id;
        l_options := os_auth.get_authentication_options(l_user_id, null, l_origin, l_rp_id);
        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write_raw('options', l_options);
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_get_auth_options: %s', sqlerrm);
            send_error_response('Authentication options failed');
    end ajax_get_auth_options;

    -- NOTE: After successful verification this procedure returns the user_id.
    -- Callers MUST establish an APEX session after receiving a successful
    -- response, e.g. by calling apex_custom_auth.login or setting APP_USER
    -- and G_USER_ID via apex_util.set_session_state. Without this step the
    -- server has no authenticated session for subsequent requests.
    procedure ajax_verify_authentication (
        p_credential_id    in varchar2,
        p_client_data_json in varchar2,
        p_auth_data        in varchar2,
        p_signature        in varchar2,
        p_user_handle      in varchar2 default null
    ) is
        l_user_id number;
    begin
        -- Input validation
        if not is_valid_base64url(p_credential_id, 2048) then
            send_error_response('Invalid credential_id');
            return;
        end if;

        if not is_valid_base64url(p_client_data_json, 8000) then
            send_error_response('Invalid client_data_json');
            return;
        end if;

        if not is_valid_base64url(p_auth_data, 4000) then
            send_error_response('Invalid auth_data');
            return;
        end if;

        if not is_valid_base64url(p_signature, 1024) then
            send_error_response('Invalid signature');
            return;
        end if;

        l_user_id := os_auth.verify_authentication(
            p_credential_id_b64    => p_credential_id,
            p_client_data_json_b64 => p_client_data_json,
            p_auth_data_b64        => p_auth_data,
            p_signature_b64        => p_signature,
            p_user_handle_b64      => p_user_handle
        );

        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write('message', 'Authentication successful');
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_verify_authentication: %s', sqlerrm);
            send_error_response('Authentication failed');
    end ajax_verify_authentication;

    procedure pk_challenge_auth as
        v_username  varchar2(256);
        v_challenge varchar2(500);
    begin
        v_username := v('APP_USER');
        if v_username is null then
            send_error_response('User not authenticated');
            return;
        end if;
        v_challenge := os_auth.generate_challenge(
            p_username       => v_username,
            p_challenge_type => 'AUTHENTICATION'
        );
        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write('challenge', v_challenge);
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('pk_challenge_auth: %s', sqlerrm);
            send_error_response('Challenge generation failed');
    end pk_challenge_auth;


    -- Credential Management
    procedure ajax_get_credentials is
        l_user_id number;
    begin
        l_user_id := get_current_user_id;
        if l_user_id is null then
            send_error_response('User not authenticated');
            return;
        end if;
        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.open_array('credentials');
        for rec in (
            select credential_id,
                   os_auth.base64url_encode(credential_id) as credential_id_b64,
                   credential_name,
                   created_at,
                   last_used_at,
                   sign_count,
                   is_active
              from os_auth_credentials
             where user_id = l_user_id
            order by created_at desc
        ) loop
            apex_json.open_object;
            apex_json.write('credentialId', rec.credential_id_b64);
            apex_json.write('name', rec.credential_name);
            apex_json.write('createdAt',
                            to_char(rec.created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'));
            if rec.last_used_at is not null then
                apex_json.write('lastUsedAt',
                                to_char(rec.last_used_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'));
            end if;

            apex_json.write('signCount', rec.sign_count);
            apex_json.write('isActive', rec.is_active = 'Y');
            apex_json.close_object;
        end loop;

        apex_json.close_array;
        apex_json.write('count',
                        os_auth.get_credential_count(l_user_id));
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_get_credentials: %s', sqlerrm);
            send_error_response('Failed to retrieve credentials');
    end ajax_get_credentials;

    procedure ajax_revoke_credential (
        p_credential_id in varchar2
    ) is
        l_user_id     number;
        l_cred_id_raw raw(1024);
    begin
        l_user_id := get_current_user_id;
        if l_user_id is null then
            send_error_response('User not authenticated');
            return;
        end if;

        -- Input validation
        if not is_valid_base64url(p_credential_id, 2048) then
            send_error_response('Invalid credential_id format');
            return;
        end if;

        l_cred_id_raw := os_auth.base64url_decode(p_credential_id);
        os_auth.revoke_credential(
            p_credential_id => l_cred_id_raw,
            p_user_id       => l_user_id
        );
        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write('message', 'Credential revoked successfully');
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_revoke_credential: %s', sqlerrm);
            send_error_response('Credential revocation failed');
    end ajax_revoke_credential;


    -- Pre-Login Endpoints
    function my_authentication (
        p_username in varchar2,
        p_password in varchar2
    ) return boolean is
        l_user_id number;
    begin
        -- Detect WebAuthn assertion JSON in password field
        if
            p_password is not null
            and length(p_password) > 100
            and substr(
                ltrim(p_password),
                1,
                1
            ) = '{'
        then
            -- Parse the JSON assertion
            declare
                l_json        json_object_t := json_object_t.parse(p_password);
                l_cred_id     varchar2(4000) := l_json.get_string('credentialId');
                l_client_data varchar2(32000) := l_json.get_string('clientDataJSON');
                l_auth_data   varchar2(4000) := l_json.get_string('authenticatorData');
                l_signature   varchar2(4000) := l_json.get_string('signature');
                l_user_handle varchar2(4000);
            begin
                if not l_json.get('userHandle').is_null then
                    l_user_handle := l_json.get_string('userHandle');
                end if;

                l_user_id := os_auth.verify_authentication(
                    p_credential_id_b64    => l_cred_id,
                    p_client_data_json_b64 => l_client_data,
                    p_auth_data_b64        => l_auth_data,
                    p_signature_b64        => l_signature,
                    p_user_handle_b64      => l_user_handle
                );

            end;
        else
            -- Password-based authentication
            l_user_id := os_auth.verify_password(
                p_username => p_username,
                p_password => p_password
            );
        end if;

        if l_user_id is not null then
            apex_util.set_session_state('G_USER_ID',
                                        to_char(l_user_id));
            return true;
        end if;

        return false;
    exception
        when others then
            apex_debug.error('my_authentication: %s', sqlerrm);
            return false;
    end my_authentication;

    procedure ajax_get_auth_options_by_user (
        p_username in varchar2
    ) is
        l_user_id number;
        l_origin  varchar2(500);
        l_rp_id   varchar2(255);
        l_options clob;
    begin
        if p_username is null
           or length(p_username) > 255 then
            send_error_response('Invalid username');
            return;
        end if;

        begin
            select user_id
              into l_user_id
              from os_users
             where lower(username) = lower(p_username)
               and is_active = 'Y';

        exception
            when no_data_found then
                --send_error_response('User not found');
                apex_json.initialize_clob_output;
                apex_json.open_object;
                apex_json.write('success', true);
                apex_json.open_object('options');
                apex_json.write_raw('challenge',
                                    '"'
                                    || os_auth.generate_challenge(
                              p_username       => null,
                              p_challenge_type => 'AUTHENTICATION'
                          )
                                    || '"');

                apex_json.open_array('allowCredentials');
                apex_json.close_array;
                apex_json.write('timeout', 60000);
                apex_json.write('rpId', os_auth.get_apex_rp_id);
                apex_json.write('userVerification', 'preferred');
                apex_json.close_object;
                apex_json.close_object;
                htp.p(apex_json.get_clob_output);
                apex_json.free_output;
                return;
        end;

        l_origin := os_auth.get_apex_origin;
        l_rp_id := os_auth.get_apex_rp_id;
        l_options := os_auth.get_authentication_options(l_user_id, null, l_origin, l_rp_id);
        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write_raw('options', l_options);
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_get_auth_options_by_user: %s', sqlerrm);
            send_error_response('Authentication options failed');
    end ajax_get_auth_options_by_user;

    procedure ajax_get_reg_options_new_user (
        p_username     in varchar2,
        p_display_name in varchar2 default null,
        p_email        in varchar2 default null
    ) is

        l_user_id      number;
        l_display_name varchar2(255);
        l_origin       varchar2(500);
        l_rp_id        varchar2(255);
        l_options      clob;
    begin
        if p_username is null
           or length(p_username) > 255 then
            send_error_response('Invalid username');
            return;
        end if;

        l_display_name := nvl(p_display_name, p_username);

        -- Look up or create user with a dummy password
        begin
          select user_id
            into l_user_id
            from os_users
           where lower(username) = lower(p_username);

        exception
            when no_data_found then
                -- Create user with a random dummy password (passkey-only account)
                l_user_id := os_auth.create_user(
                    p_username     => p_username,
                    p_password     => rawtohex(dbms_crypto.randombytes(32)),
                    p_display_name => l_display_name,
                    p_email        => p_email
                );
        end;

        l_origin := os_auth.get_apex_origin;
        l_rp_id := os_auth.get_apex_rp_id;
        l_options := os_auth.get_registration_options(
            p_user_id           => l_user_id,
            p_user_name         => p_username,
            p_user_display_name => l_display_name,
            p_origin            => l_origin,
            p_rp_id             => l_rp_id,
            p_rp_name           => l_rp_id
        );

        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write_raw('options', l_options);
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_get_reg_options_new_user: %s', sqlerrm);
            send_error_response('Registration options failed');
    end ajax_get_reg_options_new_user;

    procedure ajax_register_with_passkey (
        p_username         in varchar2,
        p_email            in varchar2 default null,
        p_display_name     in varchar2 default null,
        p_credential_id    in varchar2,
        p_client_data_json in varchar2,
        p_attestation_obj  in varchar2,
        p_transports       in varchar2 default null,
        p_credential_name  in varchar2 default null
    ) is
        l_user_id      number;
        l_display_name varchar2(255);
        l_cred_id      raw(1024);
    begin
        if p_username is null
           or length(p_username) > 255 then
            send_error_response('Invalid username');
            return;
        end if;

        if not is_valid_base64url(p_credential_id, 2048) then
            send_error_response('Invalid credential_id format');
            return;
        end if;

        if not is_valid_base64url(p_client_data_json, 8000) then
            send_error_response('Invalid client_data_json format');
            return;
        end if;

        if not is_valid_base64url(p_attestation_obj, 32000) then
            send_error_response('Invalid attestation_obj format');
            return;
        end if;

        l_display_name := nvl(p_display_name, p_username);

        -- Look up or create user
        begin
            select user_id
              into l_user_id
              from os_users
             where lower(username) = lower(p_username);

        exception
            when no_data_found then
                l_user_id := os_auth.create_user(
                    p_username     => p_username,
                    p_password     => rawtohex(dbms_crypto.randombytes(32)),
                    p_display_name => l_display_name,
                    p_email        => p_email
                );
        end;

        l_cred_id := os_auth.verify_registration(
            p_user_id              => l_user_id,
            p_credential_id_b64    => p_credential_id,
            p_client_data_json_b64 => p_client_data_json,
            p_attestation_obj_b64  => p_attestation_obj,
            p_transports           => p_transports,
            p_credential_name      => nvl(p_credential_name,
                                     'Key ' || to_char(sysdate, 'YYYY-MM-DD HH24:MI'))
        );

        apex_json.initialize_clob_output;
        apex_json.open_object;
        apex_json.write('success', true);
        apex_json.write('userId', l_user_id);
        apex_json.write('message', 'Registration successful');
        apex_json.close_object;
        htp.p(apex_json.get_clob_output);
        apex_json.free_output;
    exception
        when others then
            apex_debug.error('ajax_register_with_passkey: %s', sqlerrm);
            send_error_response('Registration failed');
    end ajax_register_with_passkey;

end os_auth_apex;
/
