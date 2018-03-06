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

import br.unesp.fc.central.ldap.dto.User;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import net.sf.json.JSONObject;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

public class CentralService {

    private final String authUrl;
    private final String serviceUrl;
    private final String clientId;
    private final String clientKey;
    private String lastToken = null;
    private Long expire = 0l;

    public CentralService(Properties properties) {
        authUrl = properties.getProperty("central.auth");
        serviceUrl = properties.getProperty("central.service");
        clientId = properties.getProperty("central.client-id");
        clientKey = properties.getProperty("central.client-key");
    }

    public String getClientToken() {
        Long currentTimeMillis = System.currentTimeMillis();
        if (expire > currentTimeMillis)
            return lastToken;
        HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(clientId, clientKey);
        Client client = ClientBuilder.newClient();
        client.register(feature);
        WebTarget target = client.target(authUrl)
                .path("/oauth/token");
        Form form = new Form()
                .param("grant_type", "client_credentials");
        Entity<Form> entity = Entity.entity(form,
                MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        JSONObject response = target.request()
                .post(entity, JSONObject.class);
        lastToken = response.getString("access_token");
        expire = currentTimeMillis + response.getInt("expires_in") * 1000;
        return lastToken;
    }

    public String login(String username, String password) {
        HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(clientId, clientKey);
        Client client = ClientBuilder.newClient();
        client.register(feature);
        WebTarget target = client.target(authUrl)
                .path("/oauth/token");
        Form form = new Form()
                .param("grant_type", "password")
                .param("username", username)
                .param("password", password);
        Entity<Form> entity = Entity.entity(form,
                MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        Response response = target.request()
                .post(entity);
        if (!response.getStatusInfo().equals(Response.Status.OK))
            return null;
        JSONObject json = response.readEntity(JSONObject.class);
        return json.getString("access_token");
    }

    public List<User> listarUsuariosBySistemaPerfil(Integer idSistema, Integer idPerfil) {
        HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(clientId, clientKey);
        Client client = ClientBuilder.newClient();
        client.register(feature);
        WebTarget target = client.target(serviceUrl)
                .path(String.format("/v1/sistemas/%d/perfis/%d/usuarios", idSistema, idPerfil));
        Builder builder = target.request();
        builder.header("Authorization", "Bearer " + getClientToken());
        User[] usuarios = builder.get(User[].class);
        return Arrays.asList(usuarios);
    }

}
