package dev.otthon.clientserv.controller;

import dev.otthon.clientserv.dto.ServicoPrestadoDTO;
import dev.otthon.clientserv.model.Cliente;
import dev.otthon.clientserv.model.ServicoPrestado;
import dev.otthon.clientserv.repository.ClienteRepository;
import dev.otthon.clientserv.repository.ServicoPrestadoRepository;
import dev.otthon.clientserv.util.BigDecimalConverter;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;

@RestController
@RequestMapping("/api/servicos-prestados")
public class ServicoPrestadoController {

  @Autowired
  private ClienteRepository clienteRepository;
  @Autowired
  private ServicoPrestadoRepository servicoPrestadoRepository;
  @Autowired
  private BigDecimalConverter bigDecimalConverter;

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public ServicoPrestado salvar(@RequestBody @Valid ServicoPrestadoDTO dto) {

    LocalDate data = LocalDate.parse(dto.getData(), DateTimeFormatter.ofPattern("dd/MM/yyyy"));
    Long idCliente = dto.getIdCliente();

    Cliente cliente = clienteRepository.findById(idCliente)
      .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cliente inexistente"));

    ServicoPrestado servicoPrestado = new ServicoPrestado();
    servicoPrestado.setDescricao(dto.getDescricao());
    servicoPrestado.setData(data);
    servicoPrestado.setCliente(cliente);
    servicoPrestado.setValor(bigDecimalConverter.converter(dto.getPreco()));

    return servicoPrestadoRepository.save(servicoPrestado);
  }

  @GetMapping
  public List<ServicoPrestado> pesquisar(
          @RequestParam(value = "nome", required = false, defaultValue = "") String nome,
          @RequestParam(value = "mes", required = false) Integer mes
    ) {
    return servicoPrestadoRepository.findByNomeClienteAndMes("%" + nome + "%", mes);
  }
}
