# springboot-security-jwt
##Secure your API with JWT Tokens

#to run this project from terminal/ console with h2 database
    mvn clean install -P h2Development
    java -jar target\tomcatRun.jar --port 8082 target\ROOT.war
      
#to run this project from terminal/ console with mysql database
    mvn clean install -P mysqlProduction
    java -jar target\tomcatRun.jar --port 8082 target\ROOT.war 


POST /api/auth/login HTTP/1.1
Host: localhost:9966  
X-Requested-With: XMLHttpRequest
Content-Type: application/json
Cache-Control: no-cache
{
    "username": "svlada@gmail.com",
    "password": "test1234"
}


### returns
{
    "token":"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdmxhZGFAZ21haWwuY29tIiwic2NvcGVzIjpbIlJPTEVfQURNSU4iLCJST0xFX1BSRU1JVU1fTUVNQkVSIl0sImlzcyI6Imh0dHA6Ly9zb2NpYWxXYXIua3RoIiwiaWF0IjoxNDc5MzMxOTI2LCJleHAiOjE0NzkzMzI4MjZ9.vLQfSeMFniqsngOUn2IKcNwK4OHyd6MHjglkGLjg2Dz0bjTuY_wGo1euHLpLuxcwhUKBLE2osdW3D4oQv2TQeg","refreshToken":"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdmxhZGFAZ21haWwuY29tIiwic2NvcGVzIjpbIlJPTEVfUkVGUkVTSF9UT0tFTiJdLCJpc3MiOiJodHRwOi8vc29jaWFsV2FyLmt0aCIsImp0aSI6IjAxYzVkOGFmLTU1NmMtNGNhMS1iM2Y1LTIyN2U3MmY2OWMyMCIsImlhdCI6MTQ3OTMzMTkyNiwiZXhwIjoxNDc5MzM1NTI2fQ.v7l9GIikUIpc5XMhppAZSJ7JNXkbTUZwE64HEtK_t5SZK7lwwElc_eoy5C2cTZeLgSx4bwZVwDCEEcTzJYxRrw"
}







GET /api/me HTTP/1.1
Host: localhost:9966  
X-Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdmxhZGFAZ21haWwuY29tIiwic2NvcGVzIjpbIlJPTEVfQURNSU4iLCJST0xFX1BSRU1JVU1fTUVNQkVSIl0sImlzcyI6Imh0dHA6Ly9zdmxhZGEuY29tIiwiaWF0IjoxNDcyMzkwMDY1LCJleHAiOjE0NzIzOTA5NjV9.Y9BR7q3f1npsSEYubz-u8tQ8dDOdBcVPFN7AIfWwO37KyhRugVzEbWVPO1obQlHNJWA0Nx1KrEqHqMEjuNWo5w
Cache-Control: no-cache


###returns
{
  "username": "svlada@gmail.com",
  "authorities": [
    {
      "authority": "ROLE_ADMIN"
    },
    {
      "authority": "ROLE_PREMIUM_MEMBER"
    }
  ]
}