package io.github.kc14.guacamole.auth.ldap389ds.ldap.searches;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Credentials;

import com.google.inject.Inject;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import io.github.kc14.guacamole.auth.ldap389ds.config.ConfigurationService;
import io.github.kc14.guacamole.auth.ldap389ds.ldap.EscapingService;

public class LDAPSearchUser {

    /**
     * Service for retrieving LDAP server configuration information.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * Service for escaping parts of LDAP queries.
     */
    @Inject
    private EscapingService escapingService;

    public LDAPSearchResults searchUserByCredentials(LDAPConnection ldapConnection, Credentials credentials) throws GuacamoleException, LDAPException {
		String userBaseDN = confService.getUserBaseDN(); 
		int searchScopeBase = LDAPConnection.SCOPE_BASE;
		String userObjectClass = confService.getUserObjectClass();
		String usernameAttribute = confService.getUsernameAttribute();
		String username = credentials.getUsername();
		String userSearchFilter = "(&(objectClass=" + userObjectClass + ")(" + escapingService.escapeLDAPSearchFilter(usernameAttribute) + "=" + username + "))";
		String attrsAll[] = null;
		boolean typesOnlyFalse = false;            
		LDAPSearchResults ldapSearchResults = ldapConnection.search(userBaseDN, searchScopeBase, userSearchFilter, attrsAll, typesOnlyFalse);
		return ldapSearchResults;
	}

}
