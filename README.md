# índice

- [Informações gerais](#informações-gerais)
- [Liberação de endpoints básica](#liberação-de-endpoints-básica)
- [Criando múltiplos usuários autenticáveis](#criando-múltiplos-usuários-autenticáveis)
- [Gerenciamento de senhas com encode, encriptação e hashing](#gerenciamento-de-senhas-com-encode-encriptação-e-hashing)
- [Authentication providers](#authentication-providers)
- [Cross origin resource sharing](#cross-origin-resource-sharing)
- [Autorização com Authorities e Roles](#autorização-com-authorities-e-roles)
- [Roles x Authorities](#roles-x-authorities)
- [Authentication filters](#authentication-filters)
- [JWT Tokens](#jwt-tokens)
- [Projeto 1](#projeto-1)
- [Method level security](#method-level-security)
- [OAUTH2](#oauth2)
- [Implementação do OAUTH2 com o Github](#implementação-do-oauth2-com-o-github)
- [Keycloak](#keycloak)




# Informações gerais
`JSESSIONID:` Cookie gerado pelo Spring Security. Permite que façamos múltiplos requests com as nossas credenciais. <br>
![flow](https://user-images.githubusercontent.com/80921933/194652133-4a70471f-c76d-4f86-ad36-0684d3244189.png) <br>

`Security Context:` Interface que armazena os dados do usuário autenticado. Podemos utilizar métodos como o **SecurityContextHolder.getContext()** para efetuar diversas operações com o usuário logado, por exemplo. <br>

`Claims:` Informações contidas dentro de um token JWT. Na imagem abaixo, por exemplo, observamos que o token possui 2 Claims:

![claims](https://user-images.githubusercontent.com/80921933/198477351-5d441e5e-e896-4033-bc6c-9e2b7416d77a.png)

As Claims foram definidas no seguinte trecho de código:

![claims](https://user-images.githubusercontent.com/80921933/198478173-bded5458-02de-4143-ac4f-940d9965947f.png)

`Principal:` O método getPrincipal() retornará o usuário atualmente autenticado:

```java
Authentication auth; //exemplo...

UsuarioSS usuario = (UsuarioSS) auth.getPrincipal();
```


# Liberação de endpoints básica
Com a depreciação da classe `WebSecurityConfigurerAdapter`, podemos utilizar a `SecurityFilterChain` como alternativa para configurações de liberação de endpoints.<br>

<a href="https://github.com/azl6/eazybytes-spring-security/blob/main/section2/springsecsection2/src/main/java/com/eazybytes/config/ProjectSecurityConfig.java" target="_blank">Exemplo de utilização do SecurityFilterChain</a>

# Criando múltiplos usuários autenticáveis

![img](https://user-images.githubusercontent.com/80921933/194680566-736ffd24-236b-4eb4-b3da-0498eee9006e.png)

Pela imagem acima, observamos que as classes concretas `InMemoryUserDetailsManager`,  `JdbcUserDetailsManager`, `LdapUserDetailsManager` utilizam das funções de todas as suas interfaces superiores. 

<br>

⚠️ Todas as implementações precisam de um `PasswordEncoder`, caso contrário, o Spring lançará uma exception. Nos exemplos abaixo, utilizaremos a NoOpPasswordEncoder, que serve exclusivamente para fins de teste e demonstração. Ele salvará a senha no banco em plain-text. 

```java
@Bean
public PasswordEncoder passwordEncoder() {
       return NoOpPasswordEncoder.getInstance();
}
```

<br>

### InMemoryUserDetailsManager

Classe para gerenciamento de usuários em memória. O `PasswordEncoder`, neste caso, é passado como um `@Bean`, que o Spring utilizará sempre que necessário. 

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

Tendo o data source no `app.properties` apontando para um banco com as tabelas acima, basta criarmos os seguintes `@Bean`

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
 
 Após a criação da tabela personalizada, mapeamos a entidade desejada na JPA, e criamos o seu **repository**
 
 ```java
 @Entity
public class Customer {

    @Id
    @GeneratedValue(strategy= GenerationType.AUTO,generator="native")
    @GenericGenerator(name = "native",strategy = "native")
    private int id;
    private String email;
    private String pwd;
    private String role;
 
    //getters and setters...
 ```
 
 Depois, criamos uma classe que extende de **UserDetailsService**, e sobreescrevemos o método **loadUserByUsername**
 
 ```java
 @Service
public class EazyBankUserDetails implements UserDetailsService {

    @Autowired
    private CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    
        String userName, password = null;
        List<GrantedAuthority> authorities = null;
	
        List<Customer> customer = customerRepository.findByEmail(username); //neste caso, o e-mail é o username.
	
        if (customer.size() == 0) {
            throw new UsernameNotFoundException("User details not found for the user : " + username);
        } else{
            userName = customer.get(0).getEmail();
            password = customer.get(0).getPwd();
            authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
        }
	
        return new User(username,password,authorities);
    }
}
 ```
 
 Após isso, utilizando as credenciais cadastradas anteriormente, poderemos acessar endpoints protegidos.
 
 Para **registrar** novos usuários, basta criar um controller que recebe um `@RequestBody` de **Customer** (ou qualquer outro nome escolhido para a classe do usuário) e salvá-lo no banco. Pontos importantes:
 
- Os valores conhecidos do campo **role**, até o momento, são **admin** e **user**

![img](https://user-images.githubusercontent.com/80921933/194880715-1d1f9e07-6b2a-44bc-9170-4b231b02a77f.png)

- Por padrão, **o Spring Security desativará requisições que podem fazer alterações no banco (POST/PUT)**. Isso é uma feature do `CSRF`. Como esse assunto ainda não fora abordado, **desativaremos esse recurso** na classe **SecurityFilterChain** 

```java
@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable() //Desativação do CSRF...
                        .authorizeRequests()
                        .antMatchers("/myAccount","/myBalance","/myLoans","/myCards").authenticated()
                        //Restante do código de liberação de endpoints...
        return http.build();
    }
```

# Gerenciamento de senhas com encode, encriptação e hashing

![image](https://user-images.githubusercontent.com/80921933/194893581-f0c0b114-49ef-435c-b5f8-f1a450c55804.png)

A fim de armazenar senhas de forma segura no banco, podemos utilizar algumas implementações do `PasswordEncoder`. As mais conhecidas com encriptação hashing são:
- BCryptPasswordEncoder
- SCryptPasswordEncoder
- Argon2PasswordEncoder

Neste exemplo, utilizaremos a `BCryptPasswordEncoder`. Para tal, devemos disponibilizar um `@Bean` de `PasswordEncoder` que retorna a implementação `BCryptPasswordEncoder` sempre que um `PasswordEncoder` for injetado

```java
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

Depois, basta que encriptemos a senha antes de salvá-la no banco. Importante ressaltar que devemos injetar uma instância de `PasswordEncoder` na classe que realizará a encriptação

```java
@RestController
public class LoginController {

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private PasswordEncoder passwordEncoder; //Injetando o PasswordEncoder com o @Bean de BCryptPasswordEncoder

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        Customer savedCustomer = null;
        ResponseEntity response = null;
        try {
            String hashPwd = passwordEncoder.encode(customer.getPwd()); //Realizando a encriptação da senha antes de salvar
            customer.setPwd(hashPwd); //Setando a senha no objeto a ser salvo
            savedCustomer = customerRepository.save(customer); //Salvando
	    // ...
```

# Authentication providers

Serve para determinarmos as regras de autenticação, além de determinarmos quais tipos de autenticação nosso serviço terá.

O código abaixo exemplifica a criação de um **Authentication provider**

```java
@Component
public class EazyBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomerRepository customerRepository; //Repo que mapeia a entidade cujo user e pwd serão usados na autenticação 

    @Autowired
    private PasswordEncoder passwordEncoder; //Encoder para verificar se a senha passada bate com a encodada no banco

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName(); //Forma de pegar o username informado
        String pwd = authentication.getCredentials().toString(); //Forma de pegar o pwd informado
        List<Customer> customer = customerRepository.findByEmail(username);
        if (customer.size() > 0) {
            if (passwordEncoder.matches(pwd, customer.get(0).getPwd())) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
                return new UsernamePasswordAuthenticationToken(username, pwd, authorities);
            } else {
                throw new BadCredentialsException("Invalid password!");
            }
        }else {
            throw new BadCredentialsException("No user registered with this details!");
        }
    }

    //Informando que quero utilizar a autenticação com username/password
    //O retorno do método pode ser encontrado na classe DaoAuthenticationProvider
    //O instrutor copiou para exemplificar a necessidade de implementarmos uma autenticação com user/pwd
    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
```

Para a testar a implementação, basta tentar acessar um endpoint protegido, e ter o usuário informado salvo no banco.

**Importante**: A utilização deste método de autenticação diverge do UserDetailsService demonstrado acima. O UserDetailsService utilizaria o **DaoAuthenticationProvider** padrão, fornecido pelo Spring. Aqui, basicamente substituimos o DaoAuthenticationProvider e o UserDetailsService, escrevendo a forma de autenticar-se em uma só classe.

![superrrr](https://user-images.githubusercontent.com/80921933/197309987-28bded4a-b3ed-406a-bf13-c9bf7d0217e2.png)

# Cross origin resource sharing

![CORS1](https://user-images.githubusercontent.com/80921933/197358563-6342145a-94ce-468e-9bc9-7be9f1100e9f.png)

Para resolver o problema de CORS, podemos anotar os controllers com a annotation `@CrossOrigin` e específicar as origens permitidas, como é demonstrado abaixo:

![CORS2](https://user-images.githubusercontent.com/80921933/197358622-d4497e6a-bda5-4d76-b036-3139fdc9ce47.png)

Entretanto, em um ambiente com muitos controllers, talvez haja a preferência de definir as configurações no `SecurityFilterChain`, como é demonstrado abaixo:

![CORS3](https://user-images.githubusercontent.com/80921933/197358573-c4f6da23-657f-47f5-be1b-41b5162bd55a.png)

# Autorização com Authorities e Roles

Authorities são permissões concedidas a um usuário autenticado, como por exemplo:

- READPURCHASES
- READPURCHASEDETAILS
- READACCOUNTDETAILS
- READALLCUSTOMERS

A relação USUARIO-AUTHORITY é `One to Many` (ou `Many to Many`, dependendo da implementação), o que significa que um cliente com o perfil de **USUÁRIO** poderia ter as authorities **READPURCHASES**, **READPURCHASEDETAILS** e **READACCOUNTDETAILS**, mas não a authority **READALLCUSTOMERS**, que seria voltada para o perfil de **ADMINISTRADOR**. 

Para uma implementação inicial de authorities, criamos 2 tabelas e mapeamos-as na JPA:

**Tabela do usuário**

**(SQL)**

```sql
CREATE TABLE `customer` (
  `customer_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `mobile_number` varchar(20) NOT NULL,
  `pwd` varchar(500) NOT NULL,
  `role` varchar(100) NOT NULL,
  `create_dt` date DEFAULT NULL,
  PRIMARY KEY (`customer_id`)
);
```

**(JPA)**

```java
@Entity
@Table(name = "customer")
public class Customer {

    //demais atributos...

    @JsonIgnore
    @OneToMany(mappedBy="customer",fetch=FetchType.EAGER)
    private Set<Authority> authorities;
    
    //getters and setters
```

<br>
<br>

**Tabela das authorities, que tem uma chave estrangeira referenciando o ID do usuário**

**(SQL)**

```sql
CREATE TABLE `authorities` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` int NOT NULL,
  `name` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `customer_id` (`customer_id`),
  CONSTRAINT `authorities_ibfk_1` FOREIGN KEY (`customer_id`) REFERENCES `customer` (`customer_id`)
);

INSERT INTO `authorities` (`customer_id`, `name`)
 VALUES (1, 'VIEWACCOUNT');

INSERT INTO `authorities` (`customer_id`, `name`)
 VALUES (1, 'VIEWCARDS');

 INSERT INTO `authorities` (`customer_id`, `name`)
  VALUES (1, 'VIEWLOANS');

 INSERT INTO `authorities` (`customer_id`, `name`)
   VALUES (1, 'VIEWBALANCE');
```

**(JPA)**

```java
@Entity
@Table(name = "authorities")
public class Authority {

    @Id
    @GeneratedValue(strategy= GenerationType.AUTO,generator="native")
    @GenericGenerator(name = "native",strategy = "native")
    private Long id;

    private String name;

    @ManyToOne
    @JoinColumn(name = "customer_id")
    private Customer customer;
    
    //getters and setters
```

Após os mapeamentos, podemos alterar/implementar o nosso `AuthenticationProvider` (explicado acima), para retornar um objeto do tipo `UsernamePasswordAuthenticationToken` com a lista de authorities vinculadas ao usuário autenticado, authorities essas que permitirão o posterior acesso do usuário a demais recursos do sistema.

```java
@Component
public class EazyBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        List<Customer> customer = customerRepository.findByEmail(username);
        if (customer.size() > 0) {
            if (passwordEncoder.matches(pwd, customer.get(0).getPwd())) {
	    	//Se o usuário for válido, retorna um objeto com seu username, password e sua lista de authorities (c/ a função getGrantedAuthorities(...))
                return new UsernamePasswordAuthenticationToken(username, pwd, getGrantedAuthorities(customer.get(0).getAuthorities()));
            } else {
                throw new BadCredentialsException("Invalid password!");
            }
        }else {
            throw new BadCredentialsException("No user registered with this details!");
        }
    }

    //Método para retornar uma lista de GrantedAuthority a partir das authorities concedidas ao usuário no banco
    private List<GrantedAuthority> getGrantedAuthorities(Set<Authority> authorities) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (Authority authority : authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(authority.getName()));
        }
        return grantedAuthorities;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
```

No Bean do `SecurityFilterChain`, podemos limitar o acesso aos endpoints com authorities da seguinte forma:

```java
@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors().configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                config.setAllowedMethods(Collections.singletonList("*"));
                config.setAllowCredentials(true);
                config.setAllowedHeaders(Collections.singletonList("*"));
                config.setMaxAge(3600L);
                return config;
            }
        }).and().csrf().ignoringAntMatchers("/contact","/register").csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().authorizeRequests()
                        .antMatchers("/myAccount").hasAuthority("VIEWACCOUNT") //Authority necessária para acessar o endpoint /myAccount
                        .antMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT","VIEWBALANCE") //Authority necessária para acessar o endpoint /myBalance
                        .antMatchers("/myLoans").hasAuthority("VIEWLOANS") //Authority necessária para acessar o endpoint /myLoans
                        .antMatchers("/myCards").hasAuthority("VIEWCARDS") //Authority necessária para acessar o endpoint /myCards
                        .antMatchers("/user").authenticated()
                        .antMatchers("/notices","/contact","/register").permitAll()
                .and().formLogin()
                .and().httpBasic();
        return http.build();
    }

```

# Roles x Authorities

![image](https://user-images.githubusercontent.com/80921933/197404066-18c3f2b7-f8b2-4a98-8b35-81e48252a5bc.png)

Uma **role** pode ser usada para agrupar um conjunto de permissões a um usuário. Alguns exemplos de **role** são **ADMIN** ou **USER**.

Para iniciar a implementação de **roles**, podemos seguir o mesmo princípio da tabela de **Authorities**, definida acima. Inserimos as roles de um usuário da mesma forma que inserimos as **Authorities**

```sql
INSERT INTO `authorities` (`customer_id`, `name`)
  VALUES (1, 'ROLE_USER');

 INSERT INTO `authorities` (`customer_id`, `name`)
  VALUES (1, 'ROLE_ADMIN');
```

Após isso, configuramos o Bean de SecurityFilterChain para liberar endpoints por **role**

**Importante:** No Bean, basta definirmos o nome que vem depois do prefixo **ROLE_**. O Spring já adicionará esse prefixo na verificação.

```java
@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors().configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                config.setAllowedMethods(Collections.singletonList("*"));
                config.setAllowCredentials(true);
                config.setAllowedHeaders(Collections.singletonList("*"));
                config.setMaxAge(3600L);
                return config;
            }
        }).and().csrf().ignoringAntMatchers("/contact","/register").csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().authorizeRequests()
                        .antMatchers("/myAccount").hasRole("USER") //Usuários com a role ROLE_USER podem acessar
                        .antMatchers("/myBalance").hasAnyRole("USER","ADMIN") //Usuários com a role ROLE_USER ou ROLE_ADMIN podem acessar
                        .antMatchers("/myLoans").hasRole("USER") //Usuários com a role ROLE_USER podem acessar
                        .antMatchers("/myCards").hasRole("USER") //Usuários com a role ROLE_USER podem acessar
                        .antMatchers("/user").authenticated()
                        .antMatchers("/notices","/contact","/register").permitAll()
                .and().formLogin()
                .and().httpBasic();
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
```

# Authentication filters

Os filtros são a primeira camada executada quando um usuário tenta logar no sistema.

Para visualizar os filtros em funcionamento, podemos inserir a seguinte configuração no application.properties

```
logging.level.org.springframework.security.web.FilterChainProxy=DEBUG
```

Além disso, devemos inserir a annotation `EnableWebSecurity(debug = true)` na classe principal.

Os filtros serão mostrados da seguinte forma no terminal (após a tentativa de login):

![filtros](https://user-images.githubusercontent.com/80921933/197417447-dc896d06-5897-49ec-bea4-1f9bc49afd3a.png)

Podemos incluir novos filtros, devendo implementar a interface `Filter` e sobreescrever o método `doFilter()`

Para incluir um filtro antes do `BasicAuthenticationFilter`, devemos:

**Implementar o filtro em uma classe que implementa a interface `Filter` (Aula 76)**

```java
public class RequestValidationBeforeFilter  implements Filter {

    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";
    private Charset credentialsCharset = StandardCharsets.UTF_8;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String header = req.getHeader(AUTHORIZATION);
        if (header != null) {
            header = header.trim();
            if (StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
                byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
                byte[] decoded;
                try {
                    decoded = Base64.getDecoder().decode(base64Token);
                    String token = new String(decoded, credentialsCharset);
                    int delim = token.indexOf(":");
                    if (delim == -1) {
                        throw new BadCredentialsException("Invalid basic authentication token");
                    }
                    String email = token.substring(0, delim);
                    if (email.toLowerCase().contains("test")) {
                        res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                        return;
                    }
                } catch (IllegalArgumentException e) {
                    throw new BadCredentialsException("Failed to decode basic authentication token");
                }
            }
        }
        chain.doFilter(request, response);
    }
}
```

**Declarar o filtro construído no Bean de `SecurityFilterChain`**

```java
// ...
.and().addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
// ...
```

Outro caso simples da implementação de filtros: Filtro após o `BasicAuthenticationFilter` para printar as authorities do usuário logado:

**Filtro:**
```java
public class AuthoritiesLoggingAfterFilter implements Filter {

    private final Logger LOG =
            Logger.getLogger(AuthoritiesLoggingAfterFilter.class.getName());

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication) {
            LOG.info("User " + authentication.getName() + " is successfully authenticated and "
                    + "has the authorities " + authentication.getAuthorities().toString());
        }
        chain.doFilter(request, response);
    }
}
```

**Adicionando-o ao Bean do `SecurityFilterChain`:**
```java
// ...
.addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
// ...
```

# JWT Tokens

Um token JWT é constituido de 3 partes:

- Header
- Payload
- Signature

![jwt](https://user-images.githubusercontent.com/80921933/197424210-dc0d7228-ed00-43c2-b408-35cf11efac13.png)

O `header` do token armazena metadados, como o algorítmo que foi usado em seu encode

![jwt](https://user-images.githubusercontent.com/80921933/197424333-be2b0bf4-bf4a-4c48-aeae-47ce1a05c98e.png)

O `payload` do token armazena as informações do usuário, tempo de expiração do token, quem gerou o token, etc...

![jwt](https://user-images.githubusercontent.com/80921933/197424391-628d230a-de67-4b62-9d0f-3b8e60cb7655.png)

A `signature` pode ser compreendida abaixo:

![image](https://user-images.githubusercontent.com/80921933/197424847-6b0b23bf-3e16-4684-8a60-fb6f9a3b65f6.png)

![image](https://user-images.githubusercontent.com/80921933/197425096-630e1c42-2fa7-479b-8514-0ac4b4a77854.png)

Para iniciarmos a implementação de tokens JWT, devemos adicionar as seguintes dependencies ao POM:

```xml
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt-api</artifactId>
	<version>0.11.5</version>
</dependency>
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt-impl</artifactId>
	<version>0.11.5</version>
	<scope>runtime</scope>
</dependency>
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt-jackson</artifactId> <!-- or jjwt-gson if Gson is preferred -->
	<version>0.11.5</version>
	<scope>runtime</scope>
</dependency>
```

Após isso, desativamos a geração automática de tokens do tipo `JSESSIONID`, adicionando a seguinte linha em nosso Bean de `SecurityFilterChain`:

```java
// ...
http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
// ...
```

Além disso, também devemos expor o header **Authorization** dentro das configurações de `CORS` no Bean de `SecurityFilterChain`:

```java
 @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .cors().configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                config.setAllowedMethods(Collections.singletonList("*"));
                config.setAllowCredentials(true);
                config.setAllowedHeaders(Collections.singletonList("*"));
                config.setExposedHeaders(Arrays.asList("Authorization")); //Configuração adicional necessária
                config.setMaxAge(3600L);
                return config;
            }
        }).and()
	//...
```

Após isso, precisamos criar o `Filter` para gerar o token JWT **após o filtro de autenticação** 

```java
public class JWTTokenGeneratorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication) {
            SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder().setIssuer("Eazy Bank").setSubject("JWT Token")
                    .claim("username", authentication.getName())
                    .claim("authorities", populateAuthorities(authentication.getAuthorities()))
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + 30000000))
                    .signWith(key).compact();
            response.setHeader(SecurityConstants.JWT_HEADER, jwt);
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals("/user");
    }

    private String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
        Set<String> authoritiesSet = new HashSet<>();
        for (GrantedAuthority authority : collection) {
            authoritiesSet.add(authority.getAuthority());
        }
        return String.join(",", authoritiesSet);
    }
}
```

Declarando o filtro no Bean do `SecurityFilterChain`:

```java
// ...
.addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
// ...
```

Depois, é importante também criarmos o `Filter` de validação do token JWT, além de declará-lo no Bean de `SecurityFilterChain`:

```java
public class JWTTokenValidatorFilter  extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String jwt = request.getHeader(SecurityConstants.JWT_HEADER);
        if (null != jwt) {
            try {
                SecretKey key = Keys.hmacShaKeyFor(
                        SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));

                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();
                String username = String.valueOf(claims.get("username"));
                String authorities = (String) claims.get("authorities");
                Authentication auth = new UsernamePasswordAuthenticationToken(username, null,
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                throw new BadCredentialsException("Invalid Token received!");
            }

        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath().equals("/user");
    }
}
```

```java
// ...
.addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
// ...
```

# Projeto 1

Ao finalizar a sessão de JWT, tentei realizar uma implementação, que falhou.

Sendo assim, usei os vídeos do **Nélio Alves** para realizar a implementação abaixo.

**O projeto segue o seguinte fluxo:**

Há 3 endpoints: /publico, /autenticado e /autorizado.
- O /publico não tem restrições
- O /autenticado exige autenticação (token JWT)
- O /autorizado exige o perfil de 'ADMIN'

![aaaa](https://user-images.githubusercontent.com/80921933/198618048-d01b9498-a095-42db-9d48-4c0fd146f4c0.png)

**Fluxo da requisição com as credenciais pro endpoint /login**

![authentication](https://user-images.githubusercontent.com/80921933/198421020-3877e3a7-b2e7-4790-804e-8717ad9e9a27.png)

**Fluxo da requisição com um token para um endpoint protegido**

![authorization](https://user-images.githubusercontent.com/80921933/198423775-3b34b9d2-a9c6-4f94-b922-e3418e07a6d8.png)


Passo a passo:

- A implementação do `SecurityFilterChain` não poderá ser mantida. Mesmo deprecated, utilizei a seguinte classe-base no SecurityConfig:

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {


        http.cors().and().csrf().disable();
        http.authorizeRequests()
                .antMatchers("/publico").permitAll()
                .anyRequest().authenticated();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration().applyPermitDefaultValues();
        configuration.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

- Devemos mapear uma classe de usuário do banco, e formular uma lógica para recuperar os perfis (ou authorities) desse cliente. Nesta implementação, utilizei 1 usuário ... N authorities. O mapeamento na JPA ficou assim:

Classe **Usuario**
```java
@Entity
@Table(name = "usuario")
@Data
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "cd_usuario")
    private Long cdUsuario;

    @Column(name = "email")
    private String email;

    @Column(name = "senha")
    private String senha;

    @OneToMany(mappedBy = "usuario", fetch = FetchType.EAGER)
    private List<Authority> dbAuthorities;
```

Classe **Authority**
```java
@Entity
@Data
@Table(name = "authority")
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "cd_authority")
    private Integer cdAuthority;

    @Column(name = "nome_authority")
    private String nomeAuthority;

    @ManyToOne
    @JoinColumn(name = "rf_usuario")
    private Usuario usuario;
}
```

- Criar classe que implementa `UserDetails`. Ela deve ter id, email (username), senha e uma lista de GrantedAuthorities

```java
public class UsuarioSS implements UserDetails {

    private Integer id;
    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    //getters e setter
```

- Criar classe que implementa `UserDetailsService`, e sobreescrever o método **loadUserByUsername(String username)**. O usuário será carregado injetando o repositório da classe que mapeia a tabela de usuário no banco. Após confirmarmos que o usuário existe, retornamos um **new UserSS(...)**, passando o id, username, password e a list de authorities (ou perfis) para o construtor.

```java
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
```

- Sobreescrever o método configure na classe de **SecurityConfig** da seguinte maneira:

```java
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }
```

- Criar uma classe chamada **Credenciais** com os atributos **email** e **senha**

```java
public class Credenciais {

    private String email;
    private String senha;
}
```

- Criar as seguintes variáveis no application.properties

```java
jwt.secret=SequenciaDeCaracteresParaAssinarToken //sequencia que será embaralhada juntamente ao token JWT
jwt.expiration=60000 #1min
```

- Criar a classe **JWTUtil**, com o método **generateToken(...)**

```java
@Component
public class JWTUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    public String generateToken(UsuarioSS usuario){
        return Jwts.builder()
                .claim("id", usuario.getId())
                .claim("username", usuario.getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS512, secret.getBytes())
                .compact();
    }
}

```

- Criar a classe **JWTAuthenticationFilter** que extende a classe **UsernamePasswordAuthenticationFilter**, e implementar os métodos **attemptAuthentication(...)** e **successfulAuthentication(...)**

```java
@Data
@AllArgsConstructor
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    private JWTUtil jwtUtil;


    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {

        try {
            Credenciais creds = new ObjectMapper()
                    .readValue(req.getInputStream(), Credenciais.class);

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(creds.getEmail(), creds.getSenha(), new ArrayList<>());

            Authentication auth = authenticationManager.authenticate(authToken);

            return auth;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        UsuarioSS usuario = (UsuarioSS) auth.getPrincipal();

        String token = jwtUtil.generateToken(usuario);

        res.addHeader("Authorization", "Bearer " + token);
        
        res.addHeader("access-control-expose-headers", "Authorization");
    }

}
```

- Para autorizar os usuário, criamos a classe **JWTAuthorizationFilter**, que extende de **BasicAuthenticationFilter**

```java
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private JWTUtil jwtUtil;

    private UserDetailsService userDetailsService;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, UserDetailsService userDetailsService) {
        super(authenticationManager);
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            UsernamePasswordAuthenticationToken auth = getAuthentication(header.substring(7));
            if (auth != null) {
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String token) {
        if (jwtUtil.tokenValido(token)) {
            String username = jwtUtil.getUsername(token);
            UserDetails user = userDetailsService.loadUserByUsername(username);
            return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        }
        return null;
    }
}
```

- Criar os métodos **tokenValido(...)**, **getUsername** e **getClaims(...)** na classe JWTUtil

```java
// ...

public boolean tokenValido(String token) {
        Claims claims = getClaims(token);
        if (claims != null) {
            String username = (String) claims.get("username");
            Date expirationDate = claims.getExpiration();
            Date now = new Date(System.currentTimeMillis());
            if (username != null && expirationDate != null && now.before(expirationDate)) {
                return true;
            }
        }
        return false;
    }

    public String getUsername(String token) {
        Claims claims = getClaims(token);
        if (claims != null) {
            return (String) claims.get("username");
        }
        return null;
    }

    private Claims getClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
        }
        catch (Exception e) {
            return null;
        }
    }

// ...
```

- Depois, registrar os filtros na classe **SecurityConfig**

```java
http.addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtUtil));
http.addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtUtil, userDetailsService));
```

# Method level security

A annotation mais importante dessa categoria é a **@PreAuthorize("hasAnyRole('ROLE_HERE_WITHOUT_ROLE_PREFIX')")**. Ela é utilizada acima dos métodos/endpoints, para indicar que um método só pode ser invocado por usuários logados com certas roles/authorities.

Para utilizá-la, devemos também anotar uma classe de `@Configuration` com o **@EnableGlobalMethodSecurity(prePostEnabled = true)**

# OAUTH2

## **Terminologia**

![image](https://user-images.githubusercontent.com/80921933/198846454-37d7b5df-2ca2-48c3-9ffa-87643fa393f2.png)

## **Grant-type flows**

O **OAUTH2** possui 5 diferentes **grant-type flows**, que são formas como o **Resource Server** fornecerá o acesso aos dados solicitados pelo **Client Server**. São eles:

- Authorization code grant flow
- Implicit grant flow
- Password grant flow
- Client credentials flow
- Refresh token flow

**Authorization code grant flow**

![image](https://user-images.githubusercontent.com/80921933/198847824-30eba5db-d855-4512-a3f6-be7095027fd2.png)

**Client credentials grant flow**

![image](https://user-images.githubusercontent.com/80921933/198847858-225c2825-5461-4699-8f9a-15979ffc8c76.png)

**Refresh token grant flow**

![image](https://user-images.githubusercontent.com/80921933/198848884-f3f715ea-4baa-4d26-8c65-35455f95668d.png)

# Implementação do OAUTH2 com o Github

Dependencies iniciais

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

Settings > Developer settings > OAuth Apps > Register a new application

![oauth1](https://user-images.githubusercontent.com/80921933/198851166-5e1e92c5-5144-4d37-840c-985dce5b0333.png)

Gerar **CLIENT ID** e **CLIENTE SECRET**

![oauth1](https://user-images.githubusercontent.com/80921933/198851251-867eaa4c-6798-40cc-a45a-4d6029039cdd.png)	

Para uma implementação inicial, podemos usar o seguinte **SecurityFilterChain**

```java
@Configuration
public class SpringSecOAUTH2GitHubConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated().and().oauth2Login();
        return http.build();
    }

    /*@Bean Parte comentada, configs realizadas no app.properties para esse exemplo
    
    public ClientRegistrationRepository clientRepository() {
        ClientRegistration clientReg = clientRegistration();
        return new InMemoryClientRegistrationRepository(clientReg);
    }
    private ClientRegistration clientRegistration() {
		return CommonOAuth2Provider.GITHUB.getBuilder("github").clientId("8cf67ab304dc500092e3")
	           .clientSecret("6e6f91851c864684af2f91eaa08fb5041162768e").build();
	 }*/

}
```

No app.properties, realizar as configurações comentadas acima

```properties
spring.security.oauth2.client.registration.github.client-id=8cf67ab304dc500092e3 # CLIENT ID gerado no Github
spring.security.oauth2.client.registration.github.client-secret=6e6f91851c864684af2f91eaa08fb5041162768e # CLIENT SECRET gerado no Github
```

Ao tentar acessar o seguinte endpoint, a aplicação direcionará o usuário para a página de autenticação do Github. Caso a autenticação seja bem sucedida, o endpoint retornará o HTML.

```java
@Controller
public class SecureController {

    @GetMapping("/")
    public String main(OAuth2AuthenticationToken token) {
        System.out.println(token.getPrincipal());
        return "secure.html";
    }

}
```

# Keycloak

Após baixar o Keycloak (https://www.keycloak.org/downloads), basta extrair a pasta para algum diretório (C://Program Files) e rodar 

```
bin/kc.bat start-dev --http-port [PORT_NUMBER]
```

(A porta padrão sem a flag **--http-port** é a 8080)

## Clients

Clients são aplicações que podem requerir autenticação de algum usuário.

![oauth1](https://user-images.githubusercontent.com/80921933/198859522-73270ee4-c81a-46d0-9760-ab8c17642e9a.png)

### Criação de Clients

![oauth1](https://user-images.githubusercontent.com/80921933/198859574-eb7efd40-f57f-496b-a1ed-2827f9188823.png)

![oauth1](https://user-images.githubusercontent.com/80921933/198859603-3c99a7b8-b8c4-4001-b6ae-ca92aab2226e.png)

**Service accounts role:** Utilizado quando duas aplicações precisam "conversar"

Antes de começar a implementação no código, devemos **deletar todas as classes/configurações relacionadas a autenticação (como PasswordEncoders, filtros, etc)**. Essa atribuição ficará agora com o Keycloak.

Para transformar nossa aplicação Spring em um **Resource Server**, começamos adicionando a seguinte dependency

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

Para converter o token recebido do Keycloak em uma lista de authorities do usuário, criamos a seguinte classe

```java
public class KeycloakRoleConverter  implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");

        if (realmAccess == null || realmAccess.isEmpty()) {
            return new ArrayList<>();
        }

        Collection<GrantedAuthority> returnValue = ((List<String>) realmAccess.get("roles"))
                .stream().map(roleName -> "ROLE_" + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return returnValue;
    }

}
```

Em nosso SecurityFilterChain, setamos as seguintes configurações

```java
@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    
JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

// ...

```

Depois, configuramos o SecurityFilterChain para atuar como um **Resource Server**

```java

// ...


.antMatchers("/notices","/contact","/register").permitAll()
.and()
.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);

return http.build();
```

Depois, setamos a seguinte configuração no app.properties

```properties
spring.security.oauth2.resourceserver.jwt.jwk-set-uri = http://localhost:8180/realms/eazybankdev/protocol/openid-connect/certs
```

Para visualizar URLs importantes expostas pelo Keycloak, podemos acessar a URL `localhost:[KEYCLOAK_PORT]/realms/[CLIENT_ID]/.well-known/openid-configuration`

**token_endpoint**: URL para pegar um token do Keycloak

**jwks**: URL usada no app.properties para que o Resource Server (aplicação) possa baixar os certificados públicos do Keycloak

![oauth1](https://user-images.githubusercontent.com/80921933/198893086-38fcfa7d-bb36-4f2a-baff-261b7c33d1cc.png)

Depois de checar essas informações, criamos as roles **USER** e **ADMIN** (usadas no sistema) em **[SEU_CLIENT] > Realm roles > Create role**

Depois, atribuímos as roles de **USER** e **ADMIN** ao nosso Client: **Service accounts roles > Assign Role**

![oauth1](https://user-images.githubusercontent.com/80921933/198893347-42aabd91-999d-4aaa-aa2d-34515ce6e6d1.png)

Já podemos mandar uma requisição para o **token_endpoint**, com os dados abaixo, e recuperar os tokens:

![oauth1](https://user-images.githubusercontent.com/80921933/198894413-26434fde-9e47-4631-8afe-34b843fcb355.png)

Jogando o token no jwt.io, percebemos que ele contém todas as informações, como roles, etc.

![oauth1](https://user-images.githubusercontent.com/80921933/198894511-97f2aff2-92b3-4cbe-a4d3-98ab99d45469.png)

Com as configurações de código definidas acima, agora podemos tentar acessar um endpoint protegido, passando o valor **Bearer  [access_token]** no header Authorization. Caso o access token seja válido, o endpoint terá seu acesso liberado. 




















