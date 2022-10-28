package com.alex6.springsecurityprojeto1.security;

import com.alex6.springsecurityprojeto1.usuario.model.Usuario;
import com.alex6.springsecurityprojeto1.usuario.repository.UsuarioRepository;
import org.hibernate.ObjectNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findByEmail(email);

        return new UsuarioSS(usuario.getCdUsuario(), usuario.getEmail(), usuario.getSenha(), usuario.getGrantedAuthorities());
    }
}
