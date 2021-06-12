<?php
namespace Coercive\Security\Cookie;

use Defuse\Crypto\Crypto;
use Exception;

/**
 * Cookie
 *
 * One Cookie to rule them all.
 *
 * @package Coercive\Security\Cookie
 *
 * @author Anthony Moral <contact@coercive.fr>
 * @copyright 2021 Anthony Moral
 * @license MIT
 */
class Cookie
{
	/** @var bool The enable/disable system status */
	private $state = null;

	/** @var bool Anonymise status */
	private $anonymise = false;

	/** @var string The cookie path */
	private $path = '';

	/** @var string The cookie domain */
	private $domain = '';

	/** @var bool If the cookie will be served on https */
	private $secure = false;

	/** @var bool If the cookie will be served by http only (block JS and Trace : security breach) */
	private $httponly = false;

	/** @var string The key for encrypt cookie content */
	private $password = '';

	/** @var string The salt for anonymise hash mode */
	private $salt = '';

	/** @var string The prefix visible in clearview before anonymised cookie name */
	private $prefix = '';

	/**
	 * Alias encrypt
	 *
	 * @param string $text
	 * @return string
	 */
	private function encrypt(string $text): string
	{
		try {
			return Crypto::encryptWithPassword($text, $this->password);
		}
		catch (Exception $e) {
			return '';
		}
	}

	/**
	 * Alias decrypt
	 *
	 * @param string $cipher
	 * @return string
	 */
	private function decrypt(string $cipher)
	{
		try {
			return Crypto::decryptWithPassword($cipher, $this->password);
		}
		catch (Exception $e) {
			return '';
		}
	}

	/**
	 * Hash cookie name
	 *
	 * @param string $name
	 * @return string
	 */
	private function hash(string $name): string
	{
		return $this->prefix . sha1($name . $this->salt);
	}

	/**
	 * Retrieve the real name of anonymous cookie
	 *
	 * @param string $name
	 * @return string
	 */
	private function getAnonymous(string $name): string
	{
		return $this->anonymise ? $this->hash($name) : $name;
	}

	/**
	 * Cookie constructor.
	 *
	 * @param string $password [optional]
	 * @param string $path [optional]
	 * @param string $domain [optional]
	 * @param bool $secure [optional]
	 * @param bool $httponly [optional]
	 * @return void
	 */
	public function __construct(string $password = '', string $path = '', string $domain = '', bool $secure = false, bool $httponly = false)
	{
		$this->password = $password;
		$this->path = $path;
		$this->domain = $domain;
		$this->secure = $secure;
		$this->httponly = $httponly;
		$this->state = true;
	}

	/**
	 * Anonymise cookie
	 *
	 * @param bool $enable
	 * @param string $salt [optional]
	 * @param string $prefix [optional]
	 * @return $this
	 */
	public function anonymize(bool $enable, string $salt = null, string $prefix = null): Cookie
	{
		$this->anonymise = $enable;
		if(null !== $salt) {
			$this->salt = $salt;
		}
		if(null !== $prefix) {
			$this->prefix = $prefix;
		}
		return $this;
	}

	/**
	 * Set system status
	 *
	 * @param bool $state
	 * @return Cookie
	 */
	public function setState(bool $state): Cookie
	{
		$this->state = $state;
		return $this;
	}

	/**
	 * Enable system status
	 *
	 * @return Cookie
	 */
	public function enable(): Cookie
	{
		$this->state = true;
		return $this;
	}

	/**
	 * Disable system status
	 *
	 * @return Cookie
	 */
	public function disable(): Cookie
	{
		$this->state = false;
		return $this;
	}

	/**
	 * Set crypt key
	 *
	 * @param string $crypt
	 * @return Cookie
	 */
	public function setCryptKey(string $crypt): Cookie
	{
		$this->password = $crypt;
		return $this;
	}

	/**
	 * Set cookie path
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
	 * Set cookie domain
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
	 * Set cookie secure
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
	 * Set cookie http only
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
	 * Get cookie value
	 *
	 * @param string $name
	 * @return string
	 */
	public function get(string $name): string
	{
		if(!$this->state || !$name || !($key = $this->getAnonymous($name))) {
			return '';
		}
		return strval($_COOKIE[$key] ?? '');
	}

	/**
	 * Set cookie
	 *
	 * @param string $name
	 * @param string $value
	 * @param int $expire [optional]
	 * @return bool
	 */
	public function set(string $name, string $value, int $expire = 0): bool
	{
	    if (!$this->state || !$name || !($key = $this->getAnonymous($name))) {
	    	return false;
	    }

		$_COOKIE[$key] = $value;
	    return setcookie($key, $value, $expire, $this->path, $this->domain, $this->secure, $this->httponly);
	}

	/**
	 * Get crypted cookie value
	 *
	 * @param string $name
	 * @return string
	 */
	public function getSafe(string $name): string
	{
	    if (!$this->state || !$name || !($key = $this->getAnonymous($name)) || !isset($_COOKIE[$key])) {
	    	return '';
	    }

	    try {
	        $value = $this->decrypt($_COOKIE[$key]);
	    }
	    catch(Exception $e) {
			$value = '';
	        $this->delete($key);
	    }
	    return $value;
	}

	/**
	 * Set crypted cookie
	 *
	 * @param string $name
	 * @param string $value
	 * @param int $expire
	 * @return bool
	 */
	public function setSafe(string $name, string $value, int $expire = 0): bool
	{
	    if (!$this->state || !$name || !($key = $this->getAnonymous($name))) {
	    	return false;
	    }

	    try {
			$ciphered = $this->encrypt($value);
	    }
	    catch(Exception $e) {
			$ciphered = '';
	        $this->delete($key);
	    }

		$_COOKIE[$key] = $ciphered;
	    return setcookie($key, $ciphered, $expire, $this->path, $this->domain, $this->secure, $this->httponly);
	}

	/**
	 * Delete cookie
	 *
	 * @param string $name
	 * @return bool
	 */
	public function delete(string $name): bool
	{
		if(!$this->state || !$name || !($key = $this->getAnonymous($name))) {
			return false;
		}

	    $state = setcookie($key, false, time() - 3600, $this->path, $this->domain, $this->secure, $this->httponly);
		unset($_COOKIE[$key]);
		return $state;
	}
}