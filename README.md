## Informações gerais
`JSESSIONID:` Cookie gerado pelo Spring Security. Permite que façamos múltiplos requests com as nossas credenciais. <br>
![flow](https://user-images.githubusercontent.com/80921933/194652133-4a70471f-c76d-4f86-ad36-0684d3244189.png) <br>

`Security Context:` Interface que armazena os dados do usuário autenticado. <br>

## Liberação de endpoints básica
Com a depreciação da classe `WebSecurityConfigurerAdapter`, podemos utilizar a `SecurityFilterChain` como alternativa para configurações de liberação de endpoints.<br>

<a href="https://github.com/azl6/eazybytes-spring-security/blob/main/section2/springsecsection2/src/main/java/com/eazybytes/config/ProjectSecurityConfig.java" target="_blank">Exemplo de utilização do SecurityFilterChain</a>

## Criando múltiplos usuários autenticáveis

![img](https://user-images.githubusercontent.com/80921933/194680566-736ffd24-236b-4eb4-b3da-0498eee9006e.png)

Pela imagem acima, observamos que as classes concretas `InMemoryUserDetailsManager`,  `JdbcUserDetailsManager`, `LdapUserDetailsManager` utilizam das funções de todas as suas interfaces superiores. 


⚠️ Todas as implementações precisam de um `PasswordEncoder`, caso contrário, o Spring lançará uma exception. ⚠️ <br><br>


### InMemoryUserDetailsManager

Classe para gerenciamento de usuários em memória. O `PasswordEncoder`, neste caso, é passado como um @Bean, que o Spring utilizará sempre que necessário. 

<br>

**Exemplo:** 
```java
@Bean
public InMemoryUserDetailsManager userDetailsService() {
        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
        UserDetails admin = User.withUsername("admin").password("12345").authorities("admin").build();
        UserDetails user = User.withUsername("user").password("12345").authorities("read").build();
        userDetailsService.createUser(admin);
        userDetailsService.createUser(user);
        return userDetailsService; 
}

@Bean
public PasswordEncoder passwordEncoder() {
       return NoOpPasswordEncoder.getInstance();
}
```

<br>

### JdbcUserDetailsManager
Classe para gerenciamento de usuários em bancos convencionais (MySQL, Oracle, PostgreSQL, etc)

<a href="https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/jdbc.html" target="_blank">Link para a documentação do JdbcUserDetailsManager</a>

Neste caso, a idéia é que tenhamos um banco com os usuários registrados, e o acesso a um endpoint protegido será liberado quando forem informados um username/password que estejam registrados no banco. 

Como optamos por utilizar uma implementação pronta do Spring, devemos criar as seguintes tabelas, que são esperadas pelo framework para que a autenticação funcione.

```sql
create table users(
	username varchar_ignorecase(50) not null primary key,
	password varchar_ignorecase(500) not null,
	enabled boolean not null
);

create table authorities (
	username varchar_ignorecase(50) not null,
	authority varchar_ignorecase(50) not null,
	constraint fk_authorities_users foreign key(username) references users(username)
);
```

Tendo o data source no app.properties apontando para um banco com as tabelas acima, basta criarmos os seguintes @Bean

```java
@Bean
public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
}

@Bean
public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
}
```

A fim de testar a implementação acima apresentada, podemos inserir o seguinte usuário no banco, subir a aplicação e tentar acessar um endpoint protegido, passando as suas credenciais:

![img](https://user-images.githubusercontent.com/80921933/194734967-2c122440-7d42-43ad-8542-6bd772687b35.png)

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 

**Caso não queiramos utilizar a implementação padrão da autenticação via JDBC do Spring Framework**, podemos começar criando uma nova tabela de usuários personalizada

```sql
CREATE TABLE `customer` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(45) NOT NULL,
  `pwd` varchar(200) NOT NULL,
  `role` varchar(45) NOT NULL,
  PRIMARY KEY (`id`)
);

INSERT INTO `customer` (`email`, `pwd`, `role`)
 VALUES ('johndoe@example.com', '54321', 'admin');
 ```


