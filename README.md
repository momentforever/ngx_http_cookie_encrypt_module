# ngx_http_cookie_encrypt_module

## Description

As a nginx module.

In order to encrypt the parameters of the cookie to improve the security of the backend server.

Using AES encryption algorithm, only cbc mode is supported now, and it will be expanded in the future.

## Usage

### Example
```conf
location / {
  cookie_encrypt on/off;
  cookie_encrypt_key "12345678901234567890123456789012";
  cookie_encrypt_iv "1234567890123456";
}
```

### Default

```conf
cookie_encrypt off;
cookie_encrypt_key "E10ADC3949BA59ABBE56E056F20F883E";
cookie_encrypt_iv "E10ADC3949BA59AB";
```

### Context

http -> server -> location

## For Developer

### Feature

1. Expand more AES methods.
2. put KEY and IV to conf and ohter optimization. (finish)
3. Add strict mode. (if can't be encrypted, thtrow away this cookie)
4. replace better key and iv.
5. ...
