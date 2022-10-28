package com.alex6.springsecurityprojeto1.authority.model;

import com.alex6.springsecurityprojeto1.usuario.model.Usuario;
import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@Table(name = "authority")
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "cd_authority")
    private Integer cdAuthority;

    @Column(name = "nome_authority")
    private String nomeAuthority;

    @ManyToOne
    @JoinColumn(name = "rf_usuario")
    private Usuario usuario;
}
