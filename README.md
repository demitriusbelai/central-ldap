# Central Ldap
Servidor LDAP a partir da central de acessos da Unesp utilizando ApacheDS.

Esse servidor tem o proposito de autenticar os usuários utilizando central de acessos em sistemas que não suportam OAuth. Por exemplo, usuários de um servidor Linux, OpenProject, entre outros.

Os usuário são carregados de um determinado perfil de um sistema cadastrado na central. A autenticação dos usuários é feita repassando as credencias recebidas por bind para a central de acessos.

Por questões de performance, os usuários são carregados em uma base In-Memory com tempo de expiração. Quando é feita uma pesquisa na base e passou o tempo de expiração, a base será atualizada fazendo uma nova consulta na central de acessos.

## Configurar
Informar no arquivo `config.properties` a chave do cliente, o id do sistema e do perfil e a URL da central de acessos. Opcionalmente pode ser configurado o endereço e a porta de escuta bem como o tempo de expiração em segundos da base de dados.

## Iniciar
Rode:
```sh
mvn exec:java
```
Será criado um diretório `instance` onde será armazenada a instancia do ApacheDS.

## Considerações
Pode-se utilizar o Apache Directory Studio para testes. A conta admin é a mesma do ApacheDS sendo o usuário `uid=admin,ou=system` e a senha `secret`. Para alterá-la, consulte a documentação do ApacheDS.