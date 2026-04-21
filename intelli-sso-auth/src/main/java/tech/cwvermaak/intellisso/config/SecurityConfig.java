package tech.cwvermaak.intellisso.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tech.cwvermaak.intellisso.config.logging.MdcEnrichmentFilter;
import tech.cwvermaak.intellisso.config.oauth.DatabaseClientRegistrationRepository;
import tech.cwvermaak.intellisso.config.scim.ScimAuthenticationFilter;
import tech.cwvermaak.intellisso.config.saml.DatabaseRelyingPartyRegistrationRepository;
import tech.cwvermaak.intellisso.config.saml.SamlUserProvisioningSuccessHandler;
import tech.cwvermaak.intellisso.config.tenant.TenantResolverFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AppAuthorizationFilter appAuthorizationFilter;
    private final TenantResolverFilter tenantResolverFilter;
    private final MdcEnrichmentFilter mdcEnrichmentFilter;
    private final ScimAuthenticationFilter scimAuthenticationFilter;
    private final DatabaseClientRegistrationRepository clientRegistrationRepository;
    private final DatabaseRelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
    private final SamlUserProvisioningSuccessHandler samlSuccessHandler;
    private final CorsProperties corsProperties;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // SEC-06: bcrypt cost factor 12. BCrypt encodes the cost into the
        // hash itself, so existing hashes at lower costs still verify
        // correctly — only new passwords are hashed at cost 12.
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        UrlBasedCorsConfigurationSource corsSource = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsProperties.getAllowedOrigins().forEach(corsConfig::addAllowedOrigin);
        corsProperties.getAllowedMethods().forEach(corsConfig::addAllowedMethod);
        corsConfig.addAllowedHeader("*");
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(corsProperties.getMaxAge());
        corsSource.registerCorsConfiguration("/**", corsConfig);

        http
                .cors(cors -> cors.configurationSource(corsSource))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .addFilterBefore(tenantResolverFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(appAuthorizationFilter, TenantResolverFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, AppAuthorizationFilter.class)
                // SCIM has its own bearer-token scheme; the filter only
                // fires on /scim/v2/** paths and authenticates against the
                // app_clients table. Sits inside the chain so MDC enrichment
                // sees the populated tenant context.
                .addFilterAfter(scimAuthenticationFilter, JwtAuthenticationFilter.class)
                // Runs after JWT + SCIM auth so MDC carries actor + tenant +
                // super_admin on every downstream log line.
                .addFilterAfter(mdcEnrichmentFilter, ScimAuthenticationFilter.class)

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/login/**",
                                "/oauth2/**",
                                "/saml2/**",
                                "/error",
                                "/webjars/**",
                                "/api/auth/**",
                                "/api/auth/mfa/verify",
                                "/api/auth/mfa/webauthn/assertion/**",
                                "/t/*/.well-known/openid-configuration",
                                "/t/*/oauth2/jwks",
                                "/t/*/oauth2/token",
                                "/t/*/oauth2/userinfo",
                                "/t/*/oauth2/introspect",
                                "/t/*/oauth2/revoke",
                                "/t/*/oauth2/logout",
                                // /authorize is reachable both authenticated
                                // (renders consent) and unauthenticated (302
                                // to login). Permit so the controller's own
                                // state machine decides.
                                "/t/*/oauth2/authorize",
                                "/t/*/oauth2/authorize/decide",
                                // SAML IdP metadata — public like OIDC discovery
                                "/t/*/oauth2/register",
                                "/t/*/saml2/idp/metadata",
                                // PKI public endpoints — CRL, CA cert, OCSP responder (PRD X50-02/05)
                                "/t/*/pki/ca.pem",
                                "/t/*/pki/crl.pem",
                                "/t/*/pki/ocsp",
                                // SCIM endpoints — authenticated by their own filter
                                // (Bearer token against app_clients), so the Spring
                                // Security chain just passes them through.
                                "/scim/v2/**",
                                "/actuator/health/**",
                                "/actuator/prometheus",
                                "/actuator/circuitbreakers",
                                // OpenAPI / Swagger UI
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                // Public order funnel from www.weldforge.org;
                                // creates a pending_orders row + redirects to
                                // Stripe. No app-authorisation header because
                                // the caller is a browser.
                                "/api/public/orders/**",
                                // Payment gateway webhooks — authenticated by
                                // their own signature header (Stripe-Signature,
                                // Paddle-Signature, etc.) verified per-gateway
                                // against the stored webhook secret.
                                "/api/webhooks/**"
                        ).permitAll()
                        .requestMatchers("/api/admin/**").authenticated()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().authenticated()
                )

                // OAuth2 / social login — dynamic, per-tenant registrations.
                .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository)
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                )

                // SAML 2.0 Service Provider — dynamic, per-tenant upstream IdPs.
                //   SP-initiated login:   /saml2/authenticate/{slug}-saml-{key}
                //   Assertion consumer:   /login/saml2/sso/{slug}-saml-{key}
                //   SP metadata endpoint: /saml2/service-provider-metadata/{slug}-saml-{key}
                .saml2Login(saml2 -> saml2
                        .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository)
                        .successHandler(samlSuccessHandler)
                )
                .saml2Metadata(org.springframework.security.config.Customizer.withDefaults())

                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .permitAll()
                );

        return http.build();
    }
}
