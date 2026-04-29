package tech.cwvermaak.intellisso.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI 3.0 documentation for the intelli-sso API. The Swagger UI is
 * available at {@code /swagger-ui.html} and the JSON spec at
 * {@code /v3/api-docs}.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("intelli-sso API")
                        .description("Multi-tenant SSO / IAM — authentication, OIDC issuer, "
                                + "SAML IdP, SCIM 2.0 provisioning, MFA, and audit trail.")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("CW Vermaak")
                                .url("https://cwvermaak.tech")))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT access token from /api/auth/login"))
                        .addSecuritySchemes("appAuthorization", new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("x-app-authorization")
                                .description("Application-level API key")));
    }
}
