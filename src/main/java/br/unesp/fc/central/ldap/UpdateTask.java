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
import br.unesp.fc.central.ldap.dto.LdapUser;
import br.unesp.fc.central.ldap.dto.Lotacao;
import br.unesp.fc.central.ldap.dto.User;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UpdateTask implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(UpdateTask.class);

    private CentralService central;
    private RhService rh;
    private final CentralPartition centralPartition;

    public UpdateTask(CentralPartition centralPartition) {
        this.centralPartition = centralPartition;
    }

    public void setCentral(CentralService central) {
        this.central = central;
    }

    public void setRh(RhService rh) {
        this.rh = rh;
    }

    @Override
    public void run() {
        try {
            log.info("Updating Users");
            centralPartition.update(getLdapUsers());
            System.gc();
            log.info("Users uptaded");
        } catch (Exception ex) {
            log.error("Error updating users", ex);
        }
    }

    private List<LdapUser> getLdapUsers() {
        List ret = new LinkedList();
        Map<Integer, Lotacao> mapLotacao = montarMap(rh.listarLotacao());
        for (Integer unidade : centralPartition.getUnidades().keySet()) {
            log.info("Getting funcionarios unidade={}", unidade);
            List<Funcionario> funcionarios = rh.listarFuncionarioPorUnidadeUniversitaria(unidade);
            for (Funcionario f : funcionarios) {
                if (f.getIdLotacao() == null
                    || mapLotacao.get(f.getIdLotacao()).getIdUnidadeUniversitaria() != unidade) {
                    continue;
                }
                List<User> users = central.listarUsuariosPorCpf(f.getCpf());
                if (users.isEmpty() || users.get(0).getIdentificacao() == null) {
                    continue;
                }
                LdapUser ldapUser = new LdapUser();
                ldapUser.setId(users.get(0).getIdentificacao());
                ldapUser.setName(f.getNome());
                ldapUser.setEmail(users.get(0).getIdentificacao() + "@unesp.br");
                ldapUser.setUnidade(unidade);
                ret.add(ldapUser);
            }
            System.gc();
        }
        return ret;
    }

    private Map<Integer, Lotacao> montarMap(List<Lotacao> lista) {
        HashMap map = new HashMap();
        for (Lotacao l : lista) {
            map.put(l.getId(), l);
        }
        return map;
    }

}
