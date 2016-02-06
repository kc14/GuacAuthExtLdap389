package io.github.kc14.guacamole.auth.ldap389ds.utils;

import java.util.Map;

import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.Connection;
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

}
