package cn.felord.oauth2.controller;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.JSONObjectUtils;
import lombok.SneakyThrows;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 基于RFC7517
 */
@RestController
public class JwkController {
    private final JWKSource<SecurityContext> jwkSource;
    private final JWKSelector jwkSelector;

    public JwkController(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
        this.jwkSelector = new JWKSelector(new JWKMatcher.Builder().build());
    }

    /**
     * jwkSetUri端点，可以开放给特定的资源服务器
     *
     * @return pub jwk
     */
    @SneakyThrows
    @GetMapping(value = "/oauth2/jwks")
    public Map<String, Object> jwks() {
        List<JWK> jwks = jwkSource.get(jwkSelector, null);
        JWKSet jwkSet = new JWKSet(jwks);
        // 这里只会输出公钥JWK
        return JSONObjectUtils.parse(jwkSet.toString());
    }

}
