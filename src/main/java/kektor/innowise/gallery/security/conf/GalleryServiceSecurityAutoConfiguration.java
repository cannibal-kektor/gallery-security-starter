package kektor.innowise.gallery.security.conf;

import kektor.innowise.gallery.security.HeadersAuthenticationFilter;
import kektor.innowise.gallery.security.conf.client.ProtectedRestClientConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

import static kektor.innowise.gallery.security.HeaderAuthenticationToken.SYSTEM_AUTHORITY;

@AutoConfiguration
@ConditionalOnClass({HttpSecurity.class, SecurityFilterChain.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Import(ProtectedRestClientConfig.class)
@EnableConfigurationProperties(GallerySecurityProperties.class)
@AutoConfigureBefore(SecurityAutoConfiguration.class)
public class GalleryServiceSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   GallerySecurityProperties galleryProperties,
                                                   Environment env) throws Exception {
        HttpSecurity httpSecurity = http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health/**")
                        .permitAll()
                        .requestMatchers(obtainRequestMatchers(galleryProperties.getOpenEndpoints()))
                        .permitAll()
                        .requestMatchers(obtainRequestMatchers(galleryProperties.getInternalEndpoints()))
                        .hasAuthority(SYSTEM_AUTHORITY.getAuthority())
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .securityContext(context -> context
                        .securityContextRepository(new NullSecurityContextRepository())
                )
                .addFilterBefore(new HeadersAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        if (Arrays.asList(env.getActiveProfiles()).contains("dev")) {
            httpSecurity.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        }
        return httpSecurity.build();
    }

    //cors for swagger endpoints calls from gateway
    @Bean
    @Profile("dev")
    UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"));
        config.setAllowedOrigins(List.of("*"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("*"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    RequestMatcher[] obtainRequestMatchers(List<GallerySecurityProperties.Endpoint> patterns) {
        return patterns.stream()
                .map(pattern ->
                        PathPatternRequestMatcher
                                .withDefaults()
                                .matcher(pattern.method(), pattern.path()))
                .toArray(RequestMatcher[]::new);
    }

}
