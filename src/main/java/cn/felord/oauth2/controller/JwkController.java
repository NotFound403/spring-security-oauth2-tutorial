package cn.felord.oauth2.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import lombok.SneakyThrows;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Map;

/**
 * @author felord.cn
 */
@RestController
public class JwkController {
    private static RSAKey rsaKey;

    static {
        // 对应keytool命令中的 alias
        String alias = "jose";
        // 对应keytool命令中的 storepass
        String storePass = "felord.cn";
        char[] pin = storePass.toCharArray();

        try {
            KeyStore jks = KeyStore.getInstance("jks");
            jks.load(new ClassPathResource("jose.jks").getInputStream(), pin);
            rsaKey = RSAKey.load(jks, alias, pin);
        } catch (KeyStoreException | JOSEException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }

    }

    /**
     *  jwkSetUri
     *
     * @return pub jwk
     */
    @PreAuthorize("hasAuthority('SCOPE_user_info')")
    @SneakyThrows
    @GetMapping(value = "/oauth2/jwks")
    public Map<String, Object> jwks() {
//        com.nimbusds.jose.jwk.RSAKey rsaKey = ... ;
        JWKSet jwkSet = new JWKSet(Collections.singletonList(rsaKey));
        // 这里只会输出公钥JWK
        return JSONObjectUtils.parse(jwkSet.toString());
    }
}
