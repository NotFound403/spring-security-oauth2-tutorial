package cn.felord.oauth2.controller;

import cn.felord.oauth2.config.JwkResolver;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import lombok.SneakyThrows;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 基于RFC7517
 * @author felord.cn
 */
@RestController
public class JwkController {
    private final JwkResolver resolver = new JwkResolver();

    /**
     * jwkSetUri端点，可以开放给特定的资源服务器
     *
     * @return pub jwk
     */
    @SneakyThrows
    @GetMapping(value = "/oauth2/jwks")
    public Map<String, Object> jwks() {
        //TODO 这里写的比较随意
        JWK jwk = resolver.apply(null);
        JWKSet jwkSet = new JWKSet(jwk);
        // 这里只会输出公钥JWK
        return JSONObjectUtils.parse(jwkSet.toString());
    }
}
