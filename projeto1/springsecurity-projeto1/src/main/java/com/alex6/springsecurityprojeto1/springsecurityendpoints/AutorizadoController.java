package com.alex6.springsecurityprojeto1.springsecurityendpoints;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/autorizado")
public class AutorizadoController {

    @GetMapping
    public String endpointAutorizado(){
        return "AUTORIZAÇÃO: Esse endpoint requer a role de ADMIN!";
    }
}

