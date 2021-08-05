# Codeginter 4, jwt

route
- {url}/v1/auth/login
  method POST
  
  parameter in body Raw
  email string, password string
  
- {url}/v1/auth/register
  method POST
  
  parameter in Body raw
  email string, fullname string, password string, confirm_password string 

- {url}/v1/auth/user
  method GET
  
  parameter in header
  Authorization Bearer {token}

