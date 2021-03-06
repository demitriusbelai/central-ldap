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

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Properties;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.InterceptorEnum;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.authn.AnonymousAuthenticator;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.authn.Authenticator;
import org.apache.directory.server.core.authn.SimpleAuthenticator;
import org.apache.directory.server.core.authn.StrongAuthenticator;
import org.apache.directory.server.core.partition.impl.btree.AbstractBTreePartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.shared.DefaultCoreSession;
import org.apache.directory.server.core.shared.DefaultDnFactory;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        properties.load(new FileInputStream(new File("config.properties")));

        LdapServer server = new LdapServer();
        ArrayList<Transport> transports = new ArrayList<>();
        for (String transport : properties.getProperty("transports").split("\\s+")) {
            Transport t = new TcpTransport(properties.getProperty(transport.trim() + ".address"),
                    Integer.valueOf(properties.getProperty(transport.trim() + ".port")));
            boolean enableSSL = Boolean.valueOf(properties.getProperty(transport + ".enableSSL", "false"));
            t.setEnableSSL(enableSSL);
            transports.add(t);
        }
        server.setTransports(transports.toArray(new Transport[transports.size()]));

        if (properties.getProperty("server.keystoreFile") != null)
            server.setKeystoreFile(properties.getProperty("server.keystoreFile"));

        if (properties.getProperty("server.certificatePassword") != null)
            server.setCertificatePassword(properties.getProperty("server.certificatePassword"));

        try {
            DirectoryService directoryService = new DefaultDirectoryService();
            InstanceLayout instanceLayout = new InstanceLayout(Paths.get("instance").toFile());
            directoryService.setInstanceLayout(instanceLayout);
            server.setDirectoryService(directoryService);

            File schemaPartitionDirectory = new File(instanceLayout.getPartitionsDirectory(),
                    "schema");
            if (!schemaPartitionDirectory.exists()) {
                SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(
                        instanceLayout.getPartitionsDirectory());
                extractor.extractOrCopy();
            }
            SchemaLoader loader = new LdifSchemaLoader(
                    schemaPartitionDirectory);
            SchemaManager schemaManager = new DefaultSchemaManager(loader);
            schemaManager.loadAllEnabled();
            directoryService.setSchemaManager(schemaManager);
            directoryService.setDnFactory(new DefaultDnFactory(schemaManager, AbstractBTreePartition.DEFAULT_CACHE_SIZE));

            CentralService central = new CentralService(properties);

            Dn adminDn = directoryService.getDnFactory().create(ServerDNConstants.ADMIN_SYSTEM_DN);
            CoreSession adminSession = new DefaultCoreSession(
                    new LdapPrincipal(schemaManager, adminDn, AuthenticationLevel.STRONG), directoryService);

            LdifPartition schemaLdifPartition = new LdifPartition(schemaManager,
                    directoryService.getDnFactory());
            schemaLdifPartition.setPartitionPath(schemaPartitionDirectory.toURI());

            SchemaPartition schemaPartition = new SchemaPartition(
				schemaManager);
            schemaPartition.setWrappedPartition(schemaLdifPartition);
            directoryService.setSchemaPartition(schemaPartition);

            JdbmPartition systemPartition = new JdbmPartition(
                    schemaManager, directoryService.getDnFactory());
            systemPartition.setId("system");
            systemPartition.setPartitionPath(new File(instanceLayout.getPartitionsDirectory(),
                    systemPartition.getId()).toURI());
            systemPartition.setSuffixDn(new Dn(ServerDNConstants.SYSTEM_DN));
            systemPartition.setSchemaManager(schemaManager);

            directoryService.setSystemPartition(systemPartition);

            directoryService.getChangeLog().setEnabled(false);
            directoryService.setDenormalizeOpAttrsEnabled(true);

            CentralPartition p = new CentralPartition(schemaManager, directoryService, adminSession);
            p.setSchemaManager(schemaManager);
            p.setCentral(central);
            p.setInterval(Integer.valueOf(properties.getProperty("expire.interval")));
            p.setSistema(Integer.valueOf(properties.getProperty("sistema")));
            p.setPerfil(Integer.valueOf(properties.getProperty("perfil")));

            directoryService.addPartition(p);

            CentralAuthenticator authenticator = new CentralAuthenticator(AuthenticationLevel.SIMPLE, p.getSuffixDn());
            authenticator.setCentral(central);

            AuthenticationInterceptor authenticationInterceptor = (AuthenticationInterceptor) directoryService
                    .getInterceptor(InterceptorEnum.AUTHENTICATION_INTERCEPTOR.getName());
            authenticationInterceptor.setAuthenticators(new Authenticator[]{
                new AnonymousAuthenticator(Dn.ROOT_DSE),
                new SimpleAuthenticator(Dn.ROOT_DSE),
                new StrongAuthenticator(Dn.ROOT_DSE),
                authenticator
            });

            directoryService.startup();

            server.start();
        } catch (Exception e) {
            LOG.error("Failed to start the service.", e);
            System.exit(1);
        }
    }

}
