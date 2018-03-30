<?php
namespace Coercive\Security\Cookie;

use Exception;
use Coercive\Security\Crypt\Crypt;

/**
 * Cookie
 *
 * @package 	Coercive\Security\Cookie
 * @link		@link https://github.com/Coercive/Crypt
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2018 Anthony Moral
 * @license 	MIT
 */
class Cookie
{
	/** @var string The cookie path */
	private $path = '';

	/** @var string The cookie domain */
	private $domain = '';

	/** @var bool If the cookie will be served on https */
	private $secure = false;

	/** @var bool If the cookie will be served by http only (block JS and Trace : security breach) */
	private $httponly = false;

	/** @var string The key for encrypt cookie content */
	private $crypt = '';

	/**
	 * ALIAS Encrypt
	 *
	 * @param string $text
	 * @return string
	 */
	private function encrypt(string $text): string
	{
		return Crypt::encrypt($text, Crypt::createNewKey($this->crypt));
	}

	/**
	 * ALIAS Decrypt
	 *
	 * @param string $cipher
	 * @return string
	 */
	private function decrypt(string $cipher) {
		return Crypt::decrypt($cipher, Crypt::createNewKey($this->crypt));
	}

	/**
	 * Cookie constructor.
	 *
	 * @param string $crypt [optional]
	 * @param string $path [optional]
	 * @param string $domain [optional]
	 * @param bool $secure [optional]
	 * @param bool $httponly [optional]
	 */
	public function __construct(string $crypt = '', string $path = '', string $domain = '', bool $secure = false, bool $httponly = false)
	{
		$this->crypt = $crypt;
		$this->path = $path;
		$this->domain = $domain;
		$this->secure = $secure;
		$this->httponly = $httponly;
	}

	/**
	 * SETTER Crypt Key
	 *
	 * @param string $crypt
	 * @return Cookie
	 */
	public function setCryptKey(string $crypt): Cookie
	{
		$this->crypt = $crypt;
		return $this;
	}

	/**
	 * SETTER Cookie Path
	 *
	 * @param string $path
	 * @return Cookie
	 */
	public function setPath(string $path): Cookie
	{
		$this->path = $path;
		return $this;
	}

	/**
	 * SETTER Cookie Domain
	 *
	 * @param string $domain
	 * @return Cookie
	 */
	public function setDomain(string $domain): Cookie
	{
		$this->domain = $domain;
		return $this;
	}

	/**
	 * SETTER Cookie Secure
	 *
	 * @param bool $secure
	 * @return Cookie
	 */
	public function setSecure(bool $secure): Cookie
	{
		$this->secure = $secure;
		return $this;
	}

	/**
	 * SETTER Cookie Http Only
	 *
	 * @param bool $httponly
	 * @return Cookie
	 */
	public function setHttpOnly(bool $httponly): Cookie
	{
		$this->httponly = $httponly;
		return $this;
	}

	/**
	 * GET
	 *
	 * @param string $name
	 * @return string
	 */
	public function get(string $name)
	{
	    return !$name || !isset($_COOKIE[$name]) ? '' : (string) $_COOKIE[$name];
	}

	/**
	 * SET
	 *
	 * @param string $name
	 * @param string $value
	 * @param int $expire [optional]
	 * @return bool
	 */
	public function set(string $name, string $value, int $expire = 0): bool
	{
	    # Empty
	    if (!$name) { return false; }

	    # Set
		$_COOKIE[$name] = $value;
	    return setcookie($name, $value, $expire, $this->path, $this->domain, $this->secure, $this->httponly);
	}

	/**
	 * GET SAFE
	 *
	 * @param string $name
	 * @return string
	 */
	public function getSafe(string $name): string
	{
	    # Empty
	    if (!$name || !isset($_COOKIE[$name])) { return ''; }

	    # Decrypt
	    try {
	        $value = $this->decrypt($_COOKIE[$name]);
	    }
	    catch(Exception $e) {
			$value = '';
	        $this->delete($name);
	    }

	    # Decoded value
	    return $value;
	}

	/**
	 * SET SAFE
	 *
	 * @param string $name
	 * @param string $value
	 * @param int $expire
	 * @return bool
	 */
	public function setSafe(string $name, string $value, int $expire = 0): bool
	{
		# Empty
	    if (!$name) { return false; }

	    # Crypt
	    try {
			$ciphered = $this->encrypt($value);
	    }
	    catch(Exception $e) {
			$ciphered = '';
	        $this->delete($name);
	    }

	    # Set
		$_COOKIE[$name] = $ciphered;
	    return setcookie($name, $ciphered, $expire, $this->path, $this->domain, $this->secure, $this->httponly);
	}

	/**
	 * DELETE
	 *
	 * @param string $name
	 * @return bool
	 */
	public function delete(string $name): bool
	{
	    $state = setcookie($name, false, time() - 3600, $this->path, $this->domain, $this->secure, $this->httponly);
		unset($_COOKIE[$name]);
		return $state;
	}
}