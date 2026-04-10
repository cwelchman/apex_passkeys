alter table os_auth_credentials
    add constraint os_auth_cred_user_fk
        foreign key ( user_id )
            references ca_sec.os_users ( user_id )
        enable;
