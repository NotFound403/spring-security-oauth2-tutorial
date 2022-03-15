package cn.felord.spring.security.oauth2.server.endpoint;

import lombok.Data;

@Data
public class OAuth2Scope {
    private String scope;
    public String  description;
}
