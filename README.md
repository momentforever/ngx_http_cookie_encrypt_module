# ngx_http_cookie_encrypt_module

## Description

As a nginx module.

In order to encrypt the parameters of the cookie to improve the security of the backend server.

Using AES encryption algorithm, only cbc mode is supported now, and it will be expanded in the future.

## Usage

### Example
```conf
location / {
  cookie_encrypt on/off/strict;
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

### Instruction Description

#### cookie_encrypt

+ on

turn off cookie arg encrypt, as default.

+ off

turn on cookie arg encrypt, if parsing to a parameter that cannot be decrypted, send raw data to backend.(Not Safe)

+ strict

turn on cookie arg encrypt, if parsing to a parameter that cannot be decrypted, discard this cookie.(Safe,Experiment)

#### cookie_encrypt_key

choose aes key, length must be 32.

#### cookie_encrypt_iv

cookie aes iv(Offset),length must be 16.

## For Developer

### Feature

1. Expand more AES methods.
2. put KEY and IV to conf and ohter optimization. (finish)
3. Add strict mode. (if can't be encrypted, thtrow away this cookie) (finish)
4. replace better key and iv.
5. ...
