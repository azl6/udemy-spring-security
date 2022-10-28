package com.alex6.springsecurityprojeto1.usuario.model;

import com.alex6.springsecurityprojeto1.authority.model.Authority;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.*;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name = "usuario")
@Data
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "cd_usuario")
    private Long cdUsuario;

    @Column(name = "email")
    private String email;

    @Column(name = "senha")
    private String senha;

    @OneToMany(mappedBy = "usuario", fetch = FetchType.EAGER)
    private List<Authority> dbAuthorities;

    public List<GrantedAuthority> getGrantedAuthorities(){
        return dbAuthorities.stream().map(dbAuthority -> new SimpleGrantedAuthority(dbAuthority.getNomeAuthority())).collect(Collectors.toList());
    }
}
