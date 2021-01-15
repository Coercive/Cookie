<?php
namespace Coercive\Security\Cookie;

use Exception;
use Coercive\Security\Crypt\Crypt;

/**
 * Cookie
 *
 * One Cookie to rule them all.
 *
 * @package Coercive\Security\Cookie
 * @link https://github.com/Coercive/Crypt
 *
 * @author Anthony Moral <contact@coercive.fr>
 * @copyright 2021 Anthony Moral
 * @license MIT
 */
class Cookie
{
	const ANONYMISE_MODE_DISABLED = 0;
	const ANONYMISE_MODE_CRYPT = 1;
	const ANONYMISE_MODE_HASH = 2;
	const ANONYMISE_MODES = [
		self::ANONYMISE_MODE_DISABLED,
		self::ANONYMISE_MODE_CRYPT,
		self::ANONYMISE_MODE_HASH,
	];

	/** @var bool The enable/disable system status */
	private $state = null;

	/** @var int Anonymise status/mode */
	private $anonymise = self::ANONYMISE_MODE_DISABLED;

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

	/** @var string The salt for anonymise hash mode */
	private $salt = '';

	/**
	 * Alias encrypt
	 *
	 * @param string $text
	 * @return string
	 */
	private function encrypt(string $text): string
	{
		return Crypt::encrypt($text, Crypt::createNewKey($this->crypt));
	}

	/**
	 * Alias decrypt
	 *
	 * @param string $cipher
	 * @return string
	 */
	private function decrypt(string $cipher)
	{
		return Crypt::decrypt($cipher, Crypt::createNewKey($this->crypt));
	}

	/**
	 * Hash cookie name
	 *
	 * @param string $name
	 * @return string
	 */
	private function hash(string $name): string
	{
		return sha1($name . $this->salt);
	}

	/**
	 * Retrieve the real name of anonymous cookie
	 *
	 * @param string $name
	 * @return string
	 */
	private function getAnonymous(string $name): string
	{
		switch ($this->anonymise)
		{
			case self::ANONYMISE_MODE_DISABLED:
				return $name;
			case self::ANONYMISE_MODE_CRYPT:
				foreach (array_keys($_COOKIE) as $key) {
					if($this->decrypt($key) === $name) {
						return $key;
					}
				}
				return '';
			case self::ANONYMISE_MODE_HASH:
				return $this->hash($name);
			default:
				return '';
		}
	}

	/**
	 * Set name for anonymous cookie
	 *
	 * @param string $name
	 * @return string
	 */
	private function setAnonymous(string $name): string
	{
		switch ($this->anonymise)
		{
			case self::ANONYMISE_MODE_DISABLED:
				return $name;
			case self::ANONYMISE_MODE_CRYPT:
				$this->delete($name);
				return $this->encrypt($name);
			case self::ANONYMISE_MODE_HASH:
				return $this->hash($name);
			default:
				return '';
		}
	}

	/**
	 * Cookie constructor.
	 *
	 * @param string $crypt [optional]
	 * @param string $path [optional]
	 * @param string $domain [optional]
	 * @param bool $secure [optional]
	 * @param bool $httponly [optional]
	 * @return void
	 */
	public function __construct(string $crypt = '', string $path = '', string $domain = '', bool $secure = false, bool $httponly = false)
	{
		$this->crypt = $crypt;
		$this->path = $path;
		$this->domain = $domain;
		$this->secure = $secure;
		$this->httponly = $httponly;
		$this->state = true;
	}

	/**
	 * Anonymise cookie
	 *
	 * @param int $mode [optional]
	 * @param string $salt [optional]
	 * @return $this
	 */
	public function anonymize(int $mode = self::ANONYMISE_MODE_DISABLED, string $salt = null): Cookie
	{
		if(in_array($mode, self::ANONYMISE_MODES, true)) {
			$this->anonymise = $mode;
		}
		if(null !== $salt) {
			$this->salt = $salt;
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
		$this->crypt = $crypt;
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
	    if (!$this->state || !$name || !($key = $this->setAnonymous($name))) {
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
	    if (!$this->state || !$name || !($key = $this->setAnonymous($name))) {
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