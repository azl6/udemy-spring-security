package com.alex6.springsecurityprojeto1.springsecurityendpoints;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/publico")
public class PublicoController {

    @GetMapping
    public String endpointPublico(){
        return "PÚBLICO: Esse endpoint é público!";
    }
}
