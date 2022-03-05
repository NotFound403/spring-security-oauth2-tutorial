package cn.felord.oauth2.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(
        prefix = "jwt"
)
public class JwtProperties {

    private CertInfo certInfo;
    private Claims claims;

    @Data
    public static class Claims {
        private String issuer;
        private Integer expiresAt;


    }
    @Data
    public static class CertInfo {

        private String publicKeyLocation;

    }
}
