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
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;

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
                                                   GallerySecurityProperties galleryProperties) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(galleryProperties.getOpenEndpoints().toArray(String[]::new)).permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .securityContext(context -> context
                        .securityContextRepository(new NullSecurityContextRepository())
                )
                .addFilterBefore(new HeadersAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

}
