package br.unesp.fc.central.ldap.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ServidorPublico {

    private Integer id;
	private Integer idPessoaFisica;
	private Integer idLotacaoOficial;
	private Integer idLotacaoPrestacao;

    private String nome;
	private String cpf;

    private TipoServidorPublico tipoServidorPublico;

    private Boolean ativo;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getIdPessoaFisica() {
        return idPessoaFisica;
    }

    public void setIdPessoaFisica(Integer idPessoaFisica) {
        this.idPessoaFisica = idPessoaFisica;
    }

    public Integer getIdLotacaoOficial() {
        return idLotacaoOficial;
    }

    public void setIdLotacaoOficial(Integer idLotacaoOficial) {
        this.idLotacaoOficial = idLotacaoOficial;
    }

    public Integer getIdLotacaoPrestacao() {
        return idLotacaoPrestacao;
    }

    public void setIdLotacaoPrestacao(Integer idLotacaoPrestacao) {
        this.idLotacaoPrestacao = idLotacaoPrestacao;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getCpf() {
        return cpf;
    }

    public void setCpf(String cpf) {
        this.cpf = cpf;
    }

    public TipoServidorPublico getTipoServidorPublico() {
        return tipoServidorPublico;
    }

    public void setTipoServidorPublico(TipoServidorPublico tipoServidorPublico) {
        this.tipoServidorPublico = tipoServidorPublico;
    }

    public Boolean getAtivo() {
        return ativo;
    }

    public void setAtivo(Boolean ativo) {
        this.ativo = ativo;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + Objects.hashCode(this.id);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ServidorPublico other = (ServidorPublico) obj;
        if (!Objects.equals(this.id, other.id)) {
            return false;
        }
        return true;
    }

}
