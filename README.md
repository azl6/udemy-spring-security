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

## Gerenciamento de senhas com encode, encriptação e hashing

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

## Authentication providers

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

## Cross-origin resource sharing (CORS)

![CORS1](https://user-images.githubusercontent.com/80921933/197358563-6342145a-94ce-468e-9bc9-7be9f1100e9f.png)

Para resolver o problema de CORS, podemos anotar os controllers com a annotation `@CrossOrigin` e específicar as origens permitidas, como é demonstrado abaixo:

![CORS2](https://user-images.githubusercontent.com/80921933/197358622-d4497e6a-bda5-4d76-b036-3139fdc9ce47.png)

Entretanto, em um ambiente com muitos controllers, talvez haja a preferência de definir as configurações no `SecurityFilterChain`, como é demonstrado abaixo:

![CORS3](https://user-images.githubusercontent.com/80921933/197358573-c4f6da23-657f-47f5-be1b-41b5162bd55a.png)

## Autorização com Authorities e Roles

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
<br>

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

<br>

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








