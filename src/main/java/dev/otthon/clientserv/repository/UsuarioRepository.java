package dev.otthon.clientserv.repository;

import dev.otthon.clientserv.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
}
