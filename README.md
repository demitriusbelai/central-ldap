# Central Ldap
Servidor LDAP a partir da central de acessos da Unesp utilizando ApacheDS.

Esse servidor tem o proposito de autenticar os usuários utilizando central de acessos em sistemas que não suportam OAuth. Por exemplo, usuários de um servidor Linux, OpenProject, entre outros.

Os usuário são carregados a partir da lista de funcionários retornado pelo Sistema de RH e consultando a Central para pegar o nome de usuário. A autenticação dos usuários é feita repassando as credencias recebidas por bind para a central de acessos.

Por questões de performance, os usuários são carregados em uma base In-Memory. Uma thread é executada em intervalos configurado para atualizar os usuários.

## Configurar
Informar no arquivo `config.properties` a chave do cliente, a URL da Central de Acessos e do Sistema de RH. Opcionalmente pode ser configurado o endereço e a porta de escuta bem como o tempo de invervalo em segundos da thread de atualização.

## Iniciar
Rode:
```sh
mvn exec:java
```
Será criado um diretório `instance` onde será armazenada a instancia do ApacheDS.

## Considerações
Pode-se utilizar o Apache Directory Studio para testes. A conta admin é a mesma do ApacheDS sendo o usuário `uid=admin,ou=system` e a senha `secret`. Para alterá-la, consulte a documentação do ApacheDS.
