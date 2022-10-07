## Informações gerais
`JSESSIONID:` Cookie gerado pelo Spring Security. Permite que façamos múltiplos requests com as nossas credenciais. <br>
![flow](https://user-images.githubusercontent.com/80921933/194652133-4a70471f-c76d-4f86-ad36-0684d3244189.png) <br><br>


`Security Context:` Interface que armazena os dados do usuário autenticado. <br>
`Authentication Provider:` Interface que identica o serviço de autenticação (LDAP, OAUTH2, etc).

## Liberação de endpoints básica
Com a depreciação da classe `WebSecurityConfigurerAdapter`, podemos utilizar a `SecurityFilterChain` como alternativa para configurações de liberação de endpoints.<br>
<a href="https://github.com/azl6/eazybytes-spring-security/blob/main/section2/springsecsection2latest/src/main/java/com/eazybytes/config/ProjectSecurityConfig.java" target="_blank">Exemplo de utilização do SecurityFilterChain</a>
