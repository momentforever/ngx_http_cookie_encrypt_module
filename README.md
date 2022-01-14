# ngx_http_cookie_encrypt_module

## Description

As a nginx module.

In order to encrypt the parameters of the cookie to improve the security of the backend server.

Using AES encryption algorithm, only cbc mode is supported now, and it will be expanded in the future.

## Usage

```conf
location {
  cookie_encrypt on/off;
}
```

http -> server -> location

## For Developer

### Feature

1. Expand more AES methods.
2. put KEY and IV to conf and ohter optimization. (Next step)
3. Add strict mode. (if can't be encrypted, thtrow away this cookie)
4. ...
