package dev.otthon.clientserv.repository;

import dev.otthon.clientserv.model.Cliente;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClienteRepository extends JpaRepository<Cliente, Long> {
}
