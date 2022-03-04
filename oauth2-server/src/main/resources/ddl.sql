#  OAuth2.0 Authorization Server DDL

CREATE TABLE oauth2_registered_client
(
    id                            varchar(100)                        NOT NULL,
    client_id                     varchar(100)                        NOT NULL,
    client_id_issued_at           timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 varchar(200)                        NULL,
    client_secret_expires_at      timestamp                           NULL,
    client_name                   varchar(200)                        NOT NULL,
    client_authentication_methods varchar(1000)                       NOT NULL,
    authorization_grant_types     varchar(1000)                       NOT NULL,
    redirect_uris                 varchar(1000)                       NULL,
    scopes                        varchar(1000)                       NOT NULL,
    client_settings               varchar(2000)                       NOT NULL,
    token_settings                varchar(2000)                       NOT NULL,
    PRIMARY KEY (id)
);
CREATE TABLE oauth2_authorization_consent
(
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
CREATE TABLE oauth2_authorization
(
    id                            varchar(100)  NOT NULL,
    registered_client_id          varchar(100)  NOT NULL,
    principal_name                varchar(200)  NOT NULL,
    authorization_grant_type      varchar(100)  NOT NULL,
    attributes                    varchar(4000) NULL,
    state                         varchar(500)  NULL,
    authorization_code_value      blob          NULL,
    authorization_code_issued_at  timestamp     NULL,
    authorization_code_expires_at timestamp     NULL,
    authorization_code_metadata   varchar(2000) NULL,
    access_token_value            blob          NULL,
    access_token_issued_at        timestamp     NULL,
    access_token_expires_at       timestamp     NULL,
    access_token_metadata         varchar(2000) NULL,
    access_token_type             varchar(100)  NULL,
    access_token_scopes           varchar(1000) NULL,
    oidc_id_token_value           blob          NULL,
    oidc_id_token_issued_at       timestamp     NULL,
    oidc_id_token_expires_at      timestamp     NULL,
    oidc_id_token_metadata        varchar(2000) NULL,
    refresh_token_value           blob          NULL,
    refresh_token_issued_at       timestamp     NULL,
    refresh_token_expires_at      timestamp     NULL,
    refresh_token_metadata        varchar(2000) NULL,
    PRIMARY KEY (id)
);
