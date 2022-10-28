package com.alex6.springsecurityprojeto1.springsecurityendpoints;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/autenticado")
public class AutenticadoController {

    @GetMapping
    public String endpointAutenticado(){
        return "AUTENTICAÇÃO: Esse endpoint requer autenticação!";
    }
}
