/**
 * MIT License
 *
 * Copyright (c) 2017 Demitrius Belai
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
package br.unesp.fc.central.ldap;

import java.net.SocketAddress;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.authn.AbstractAuthenticator;
import org.apache.directory.server.i18n.I18n;
import org.apache.mina.core.session.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CentralAuthenticator extends AbstractAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(CentralAuthenticator.class);

    private CentralService central;

    public CentralAuthenticator(AuthenticationLevel type) {
        super(type);
    }

    public CentralAuthenticator(AuthenticationLevel type, Dn baseDn) {
        super(type, baseDn);
    }

    public void setCentral(CentralService central) {
        this.central = central;
    }

    private Entry lookupUser(BindOperationContext bindContext) throws LdapException {
        Entry userEntry;

        try {
            LookupOperationContext lookupContext = new LookupOperationContext(getDirectoryService().getAdminSession(),
                    bindContext.getDn(), SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);

            userEntry = getDirectoryService().getPartitionNexus().lookup(lookupContext);

            if (userEntry == null) {
                Dn dn = bindContext.getDn();
                String upDn = (dn == null ? "" : dn.getName());

                throw new LdapAuthenticationException(I18n.err(I18n.ERR_231, upDn));
            }

            return userEntry;

        } catch (Exception cause) {
            LOG.error(I18n.err(I18n.ERR_6, cause.getLocalizedMessage()));
            LdapAuthenticationException e = new LdapAuthenticationException(cause.getLocalizedMessage());
            e.initCause(cause);
            throw e;
        }

    }

    @Override
    public LdapPrincipal authenticate(BindOperationContext bindContext) throws LdapException {
        log.trace("Authenticating {}", bindContext.getDn());
        byte[] credentials = bindContext.getCredentials();
        Entry user = lookupUser(bindContext);
        LdapPrincipal principal = new LdapPrincipal(getDirectoryService().getSchemaManager(), bindContext.getDn(),
                AuthenticationLevel.SIMPLE);
        IoSession session = bindContext.getIoSession();

        if (session != null) {
            SocketAddress clientAddress = session.getRemoteAddress();
            principal.setClientAddress(clientAddress);
            SocketAddress serverAddress = session.getServiceAddress();
            principal.setServerAddress(serverAddress);
        }

        if (central.login(user.get(SchemaConstants.UID_AT).getString(), new String(credentials)) == null) {
            String  message = I18n.err(I18n.ERR_230, bindContext.getDn().getName());
            LOG.info(message);
            throw new LdapAuthenticationException(message);
        }

        return principal;
    }

}
