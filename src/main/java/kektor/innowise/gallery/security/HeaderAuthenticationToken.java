package kektor.innowise.gallery.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;

public class HeaderAuthenticationToken extends AbstractAuthenticationToken {

    public static final GrantedAuthority SYSTEM_AUTHORITY = new SimpleGrantedAuthority("SYSTEM");

    private final Object principal;

    public HeaderAuthenticationToken(UserPrincipal principal) {
        super(Collections.emptyList());
        this.principal = principal;
        setAuthenticated(true);
    }

    public HeaderAuthenticationToken(SystemPrincipal principal) {
        super(List.of(SYSTEM_AUTHORITY));
        this.principal = principal;
        setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
