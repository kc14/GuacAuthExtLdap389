/*
 * Copyright (C) 2015 Glyptodon LLC
 * Copyright (C) 2015 kemmer consulting GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package net.sourceforge.guacamole.net.auth.ldap389ds;


import com.google.inject.Guice;
import com.google.inject.Injector;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.UserContext;
import org.kc.guacamole.auth.ldap389ds.AuthenticationProviderService;
import org.kc.guacamole.auth.ldap389ds.LDAP389dsAuthenticationProviderModule;

/**
 * Allows a user to be authenticated against an LDAP server. A user may have
 * any number of authorized configurations. Authorized configurations may be
 * shared.
 * 
 * The bind to the LDAP server is done by a technical user given in the
 * configuration.
 * 
 * The concept of authentication is similar to the way sssd authenticates a user.
 * 
 * First we lookup the LDAP memberOf attribute of the authenticated user to get
 * all guacamole connection groups. Then we iterate over all these guacamole
 * connection groups to get the authorized configurations.
 *
 * @author Michael Jumper
 * @author Frank Kemmer
 */
public class LDAP389dsAuthenticationProvider implements AuthenticationProvider {

    /**
     * The identifier reserved for the root connection group.
     */
    public static final String ROOT_CONNECTION_GROUP = "ROOT";

    /**
     * Injector which will manage the object graph of this authentication
     * provider (IoC).
     */
    private final Injector injector;

    /**
     * Creates a new LDAPAuthenticationProvider that authenticates users
     * against an LDAP directory.
     *
     * @throws GuacamoleException
     *     If a required property is missing, or an error occurs while parsing
     *     a property.
     */
    public LDAP389dsAuthenticationProvider() throws GuacamoleException {

        // Set up Guice injector.
        injector = Guice.createInjector(
            new LDAP389dsAuthenticationProviderModule(this)
        );

    }

    @Override
    public String getIdentifier() {
        return "ldap389ds";
    }

    @Override
    public AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {

        AuthenticationProviderService authProviderService = injector.getInstance(AuthenticationProviderService.class);
        return authProviderService.authenticateUser(credentials);

    }

    @Override
    public AuthenticatedUser updateAuthenticatedUser(AuthenticatedUser authenticatedUser,
            Credentials credentials) throws GuacamoleException {
        return authenticatedUser;
    }

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        AuthenticationProviderService authProviderService = injector.getInstance(AuthenticationProviderService.class);
        return authProviderService.getUserContext(authenticatedUser);

    }

    @Override
    public UserContext updateUserContext(UserContext context, AuthenticatedUser authenticatedUser) throws GuacamoleException {
        return context;
    }

}
