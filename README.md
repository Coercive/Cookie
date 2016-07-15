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
use Coercive\Security\Cookie

# No need to reload the document.
# The Cookie class creates and deletes cookies also in the super global $_COOKIE.

# PLAIN COOKIE
Cookie::set('MyCookie', 'Hey ! This is an example cookie !', set TIME[optional], if JSON[optional]);
Cookie::get('MyCookie', if JSON[optional]);

# SAFE COOKIE
Cookie::setCryptKey('My Password');
Cookie::setSafe('MyCookie', 'Hey ! This is an example cookie !', set TIME[optional], if JSON[optional]);
Cookie::getSafe('MyCookie', if JSON[optional]);

# DELETE COOKIE
Cookie::delete('MyCookie');

```
