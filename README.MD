
# ENTREGA II: Users Services

Nessa entrega foi desenvido um serviço simples 
de gerenciamento de usuários, utilizando alguns 
conceitos de Node.js e o Framework Express.js e 
o banco de dados volátil, sendo um array que seja 
zerado toda vez que a aplicação reiniciar!
## Documentação da API

#### Retorna todos os itens

```http
  ROTA localhost:3000
```

| Metodos   | EndPoints       | Responsabilidades                           |
| :---------- | :--------- | :---------------------------------- |
| **POST** | `/signup` | Criação de usuários |
| **GET** | `users` | Listar todos os usuários |
| **POST** | `login` | 	Gera um token JWT recebendo username e password no corpo da requisição como JSON. |    
| **PUT** | `/users/:uuid/password` | Atualiza a senha do usuário, recebendo uma string e gerando a hash novamente para a nova string. |


## Uso/Exemplos

POST / signup  `aqui esperamos um erro pois nao
passamos todos campos`

```javascript
{
  "username": "daniel",
  "email": "daniel@kenzie.com",
  "password": "abcd"
}
```
```javascript
Status: 422 UNPROCESSABLE ENTITY
{
  "message": "age is a required field"
}
```
POST /signup    `exemplo de sucesso`
```javascript
{
  "age": 18,
  "username": "daniel",
  "email": "daniel@kenzie.com",
  "password": "abcd"
}
```
```javascript
Status: 201 CREATED
{
  "uuid": "4b72c6f3-6d0a-(X)6a1-86c6-687d52de4fc7",
  "createdOn": "2021-11-18T01:23:52.910Z",
  "email": "daniel@kenzie.com",
  "age": 18,
  "username": "daniel"
}
```
POST /login
```javascript
{
  "username": "lucas",
  "password": "abcd"
}

Status: 200 -OK
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI.eyJ1c2VybmFtZSI6Imx1Y2FzIijc4ZGE2N2VhLTMw2EtNDYxOC1imOWFkZDY1MiIsImlhdCI6MTYzNzXhwIjoxNjM3MjAyMjQyfQ._XIs736ET7wEMJ5Ldvcsjqsg4Nvs40mM"
}
```

GET /users `(Rota necessita header authorization)`
```javascript
[
  {
    "username": "Lucas",
    "age": 21,
    "email": "lucas@kenzie.com",
    "password": "$2a$10$jz95yeryjhoRd1okKfEkHOOiC3RY0EPeDU6C/ccqFoa6GXE868qm6",
    "createdOn": "2022-03-16T16:42:53.801Z",
    "uuid": "076bd8bd-9534-49bb-9977-3a914a0ca0ff"
  }
]
Status: 200 - OK
```
PUT: /users/:uuid/password `(Rota necessita header authorization)`
```javascript
{
  "password": "0000000"
}

Status: 204 - NO-CONTENT
```
