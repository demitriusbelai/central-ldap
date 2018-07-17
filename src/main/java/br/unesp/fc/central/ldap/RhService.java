/*
 * MIT License
 *
 * Copyright (c) 2018 Demitrius Belai
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

import br.unesp.fc.central.ldap.dto.Funcionario;
import br.unesp.fc.central.ldap.dto.ServidorPublico;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

class RhService {

    private final String rhUrl;

    public RhService(Properties properties) {
        rhUrl = properties.getProperty("rh.url");
    }

    public List<Funcionario> listarFuncionarioPorUnidadeUniversitaria(Integer unidadeUniversitaria) {
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(rhUrl)
                .path("/v1/funcionarios")
                .queryParam("idUnidadeUniversitaria", unidadeUniversitaria)
                .queryParam("ativo", true);
        Funcionario[] lista = target.request().get(Funcionario[].class);
        return Arrays.asList(lista);
    }

    public List<ServidorPublico> listarServidorPublicoPorUnidadeUniversitaria(Integer unidadeUniversitaria) {
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(rhUrl)
                .path("/v2/unidadeUniversitaria")
                .path(String.valueOf(unidadeUniversitaria))
                .path("/servidoresPublico");
        ServidorPublico[] lista = target.request().get(ServidorPublico[].class);
        return Arrays.asList(lista);
    }

}
