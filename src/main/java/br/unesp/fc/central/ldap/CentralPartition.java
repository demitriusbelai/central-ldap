/*
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
 */
package br.unesp.fc.central.ldap;

import br.unesp.fc.central.ldap.dto.LdapUser;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.OperationManager;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.partition.impl.avl.AvlPartition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CentralPartition extends AvlPartition {

    private static final Logger log = LoggerFactory.getLogger(CentralPartition.class);

    private DirectoryService directoryService;
    private CoreSession adminSession;
    private final ReadWriteLock rwLock = new ReentrantReadWriteLock();

    private final Map<Integer, String> unidades = new HashMap<>();

    public CentralPartition(SchemaManager schemaManager, DirectoryService directoryService, CoreSession adminSession) throws LdapException {
        super(schemaManager, directoryService.getDnFactory());
        this.directoryService = directoryService;
        // Hack for local lock
        this.adminSession = (CoreSession) Proxy.newProxyInstance(
                CoreSession.class.getClassLoader(),
                new Class[]{CoreSession.class},
                new CoreSessionInvocationHandler(adminSession));
        this.setId("central");
        this.setSuffixDn(dnFactory.create("dc=unesp, dc=br"));
        unidades.put(1, "feb");
        unidades.put(2, "fc");
        unidades.put(3, "faac");
        unidades.put(37, "bauru");
    }

    public Map<Integer, String> getUnidades() {
        return Collections.unmodifiableMap(unidades);
    }

    private void addSubDomain(String subdomain) throws Exception {
        Entry entry = new DefaultEntry(schemaManager, dnFactory.create("dc=" + subdomain, getSuffixDn().toString()));
        entry.put(SchemaConstants.OBJECT_CLASS_AT,
                SchemaConstants.TOP_OC,
                SchemaConstants.DC_OBJECT_OC);
        entry.put(SchemaConstants.DC_AT, subdomain);
        entry.add(SchemaConstants.ENTRY_CSN_AT, directoryService.getCSN().toString());
        entry.add(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        add(new AddOperationContext(adminSession, entry));
    }

    @Override
    protected void doInit() throws Exception {
        super.doInit();
        Entry domain = new DefaultEntry(schemaManager, getSuffixDn());
        domain.put(SchemaConstants.OBJECT_CLASS_AT,
                SchemaConstants.TOP_OC,
                SchemaConstants.DC_OBJECT_OC);
        domain.put(SchemaConstants.DC_AT, "unesp");
        domain.add(SchemaConstants.ENTRY_CSN_AT, directoryService.getCSN().toString());
        domain.add(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        add(new AddOperationContext(adminSession, domain));
        for (String unidade : unidades.values()) {
            addSubDomain(unidade);
        }
    }

    @Override
    public Entry lookup(LookupOperationContext lookupContext) throws LdapException {
        return super.lookup(lookupContext);
    }

    @Override
    public EntryFilteringCursor search(SearchOperationContext searchContext) throws LdapException {
        return super.search(searchContext);
    }

    public synchronized void update(List<LdapUser> users) {
        Set<Dn> setDn = new HashSet<>();
        for (LdapUser ldapUser : users) {
            String dcUnidade = "dc=" + unidades.get(ldapUser.getUnidade());
            try {
                Dn dn = dnFactory.create(String.format("uid=%s", ldapUser.getId()), dcUnidade, getSuffixDn().toString());
                setDn.add(dn);
                Entry entry = lookup(new LookupOperationContext(adminSession, dn));
                if (entry != null) {
                    modifyAttributes(entry, ldapUser);
                } else {
                    newEntry(dn, ldapUser);
                }
            } catch (Exception ex) {
                log.error("Error uptating entries", ex);
            }
        }
        try {
            AttributeType uid = schemaManager.lookupAttributeTypeRegistry(SchemaConstants.UID_AT);
            Set<Dn> setDnDelete = new HashSet<>();
            try (EntryFilteringCursor cursor = super.search(
                    new SearchOperationContext(adminSession, suffixDn,
                            SearchScope.SUBTREE, new PresenceNode(uid)))) {
                Entry e;
                cursor.beforeFirst();
                while (cursor.next()) {
                    e = cursor.get();
                    if (!setDn.contains(e.getDn())) {
                        setDnDelete.add(e.getDn());
                    }
                }
            }
            for (Dn dn : setDnDelete) {
                delete(new DeleteOperationContext(adminSession, dn));
            }
        } catch (LdapException | CursorException | IOException ex) {
            log.error("Error uptating entries", ex);
        }
    }

    private void newEntry(Dn dn, LdapUser u) throws LdapException {
        Entry entry = new DefaultEntry(getSchemaManager(), dn);
        entry.put(SchemaConstants.OBJECT_CLASS_AT,
                SchemaConstants.TOP_OC,
                SchemaConstants.PERSON_OC,
                SchemaConstants.ORGANIZATIONAL_PERSON_OC,
                SchemaConstants.INET_ORG_PERSON_OC);
        entry.put(SchemaConstants.UID_AT, u.getId());
        entry.put(SchemaConstants.MAIL_AT, u.getEmail());
        entry.put(SchemaConstants.CN_AT, u.getName());
        entry.put(SchemaConstants.DISPLAY_NAME_AT, u.getName());
        entry.put(SchemaConstants.GIVENNAME_AT, u.getGivenName());
        entry.put(SchemaConstants.SN_AT, u.getSurName());
        entry.add(SchemaConstants.ENTRY_CSN_AT, directoryService.getCSN().toString());
        entry.add(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        add(new AddOperationContext(adminSession, entry));
    }

    private void modifyAttributes(Entry entry, LdapUser u) throws LdapInvalidAttributeValueException, Exception {
        List<Modification> list = new ArrayList<>();
        if (entry.get(SchemaConstants.MAIL_AT) != null && u.getEmail() != null
                && !entry.get(SchemaConstants.MAIL_AT).getString().equals(u.getEmail())) {
            list.add(new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
                    new DefaultAttribute(SchemaConstants.MAIL_AT, u.getEmail())));
        }
        if (entry.get(SchemaConstants.CN_AT) != null && u.getName() != null
                && !entry.get(SchemaConstants.CN_AT).getString().equals(u.getName())) {
            list.add(new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
                    new DefaultAttribute(SchemaConstants.CN_AT, u.getName())));
            list.add(new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
                    new DefaultAttribute(SchemaConstants.DISPLAY_NAME_AT, u.getName())));
            list.add(new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
                    new DefaultAttribute(SchemaConstants.GIVENNAME_AT, u.getGivenName())));
            list.add(new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
                    new DefaultAttribute(SchemaConstants.SN_AT, u.getSurName())));
        }
        if (!list.isEmpty()) {
            modify(entry.getDn(), list.toArray(new Modification[list.size()]));
        }
    }

    public class CoreSessionInvocationHandler implements InvocationHandler {

        private final CoreSession coreSessionProxied;
        private final DirectoryService directoryServiceProxy;

        public CoreSessionInvocationHandler(CoreSession coreSessionProxied) {
            this.coreSessionProxied = coreSessionProxied;
            directoryServiceProxy = (DirectoryService) Proxy.newProxyInstance(
                    DirectoryService.class.getClassLoader(),
                    new Class[]{DirectoryService.class},
                    new DirectoryServiceInvocationHandler(
                            coreSessionProxied.getDirectoryService()));
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getName().equals("getDirectoryService")) {
                return directoryServiceProxy;
            }
            return method.invoke(coreSessionProxied, args);
        }

    }

    public class DirectoryServiceInvocationHandler implements InvocationHandler {

        private final DirectoryService directoryServiceProxied;
        private final OperationManager operationManagerProxy;

        public DirectoryServiceInvocationHandler(DirectoryService directoryServiceProxied) {
            this.directoryServiceProxied = directoryServiceProxied;
            operationManagerProxy = (OperationManager) Proxy.newProxyInstance(
                    OperationManager.class.getClassLoader(),
                    new Class[]{OperationManager.class},
                    new OperationManagerInvocationHandler(
                            directoryServiceProxied.getOperationManager()));
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getName().equals("getOperationManager")) {
                return operationManagerProxy;
            }
            return method.invoke(directoryServiceProxied, args);
        }

    }

    public class OperationManagerInvocationHandler implements InvocationHandler {

        private final OperationManager operationManagerProxied;

        public OperationManagerInvocationHandler(OperationManager operationManagerProxied) {
            this.operationManagerProxied = operationManagerProxied;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getName().equals("getRWLock")) {
                return rwLock;
            }
            return method.invoke(operationManagerProxied, args);
        }

    }

}
