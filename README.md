Coercive Security Cookie
========================

Cookie allows you to create / read / delete normal or encrypted cookies.

Get
---
```
composer require coercive/cookie
```

Usage
-----
```php
use Coercive\Security\Cookie\Cookie;

# No need to reload the document.
# The Cookie class creates and deletes cookies also in the super global $_COOKIE.

# Instantiate and set your options
$cookie = new Cookie;
$cookie->setPath('/');
$cookie->setDomain('.domain.extension');
// etc...

# Option : anonymise -> cookie names are now sha1 + salt
$cookie->anonymize(true, 'abcd1234');
# You can prefix anonymised cookie : Hello_*************
$cookie->anonymize(true, 'abcd1234', 'Hello_');

# Plain cookie
$cookie->set('MyCookie', 'Hey ! This is an example cookie !', time() + 600);
$var = $cookie->get('MyCookie');

# Crypted cookie
$cookie = new Cookie('My Password');
$cookie->setSafe('MyCookie', 'Hey ! This is an example cookie !', time() + 600);
$var = $cookie->getSafe('MyCookie');

# Delete cookie
$cookie->delete('MyCookie');
```
