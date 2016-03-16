package io.github.kc14.guacamole.auth.ldap389ds.utils;

import java.util.Map;

import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.token.StandardTokens;
import org.glyptodon.guacamole.token.TokenFilter;

public class MacroPreProcessor {

	public static void expandStandardTokens(AuthenticatedUser user, Map<String, Connection> connections) {
		// Build credential TokenFilter
	    TokenFilter tokenFilter = new TokenFilter();
	    StandardTokens.addStandardTokens(tokenFilter, user.getCredentials());
	
	    // Filter each configuration
	    for (Connection connection : connections.values()) {
	    	tokenFilter.filterValues(connection.getConfiguration().getParameters());
	    }
	}

    public static String expandStandardTokens(Credentials credentials, String s) {
        // Build credential TokenFilter
        TokenFilter tokenFilter = new TokenFilter();
        StandardTokens.addStandardTokens(tokenFilter, credentials);
        return tokenFilter.filter(s);
    }

	public static String expandTokens(Map<String, String> tokens, String s) {
        TokenFilter tokenFilter = new TokenFilter();
        tokenFilter.setTokens(tokens);
	    return tokenFilter.filter(s);
	}
}
