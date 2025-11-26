package kektor.innowise.gallery.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;

public class HeaderAuthenticationToken extends AbstractAuthenticationToken {

    private final UserPrincipal principal;

    public HeaderAuthenticationToken(UserPrincipal principal) {
        super(Collections.emptyList());
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
