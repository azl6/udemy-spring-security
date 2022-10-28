package com.alex6.springsecurityprojeto1.usuario.repository;

import com.alex6.springsecurityprojeto1.usuario.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {

    @Query(nativeQuery = true, value = "SELECT * FROM usuario u WHERE u.email = ?1")
    Usuario findByEmail(String email);
}
