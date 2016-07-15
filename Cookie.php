<?php
namespace Coercive\Security\Cookie;

use Coercive\Security\Crypt\Crypt;

/**
 * Cookie
 * PHP Version 	5
 *
 * @version		1
 * @package 	Coercive\Security\Cookie
 * @link		@link https://github.com/Coercive/Crypt
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2016 - 2017 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class Cookie {

	/** @var string CRYPT KEY */
	static private $_sCryptKey = __CLASS__;

	/**
	 * INIT CryptKey
	 *
	 * @param string $sKey
	 */
	static public function setCryptKey($sKey) {
		self::$_sCryptKey = (string) $sKey;
	}

	/**
	 * ALIAS CryptKey
	 *
	 * @return string
	 */
	static private function _getCryptKey() {
	    return Crypt::createNewKey(self::$_sCryptKey);
	}

	/**
	 * ALIAS Encrypt
	 *
	 * @param string $sPlainText
	 * @param string $sKey
	 * @return string
	 */
	static private function _encrypt($sPlainText, $sKey) {
	    return Crypt::encrypt($sPlainText, $sKey);
	}

	/**
	 * ALIAS Decrypt
	 *
	 * @param string $sCipherText
	 * @param string $sKey
	 * @return string
	 */
	static private function _decrypt($sCipherText, $sKey) {
	    return Crypt::decrypt($sCipherText, $sKey);
	}

	/**
	 * GET
	 *
	 * @param string $sName
	 * @param bool $bJson
	 * @return mixed
	 */
	static public function get($sName, $bJson = false) {

	    # Empty
	    if (empty($sName) || !isset($_COOKIE[$sName])) { return null; }

	    # Decode
	    return $bJson ? (array)json_decode($_COOKIE[$sName]) : $_COOKIE[$sName];

	}

	/**
	 * SET
	 *
	 * @param string $sName
	 * @param mixed $mValue
	 * @param int $iTime
	 * @param bool $bJson
	 * @return bool|null
	 */
	static public function set($sName, $mValue, $iTime = null, $bJson = false) {

	    # Empty
	    if (empty($sName)) { return null; }

	    # Encode
	    if($bJson) { $mValue = json_encode($mValue); }

	    # Set
		$_COOKIE[$sName] = $mValue;
	    return setcookie($sName, $mValue, $iTime, '/');

	}

	/**
	 * GET SAFE
	 *
	 * @param string $sName
	 * @param bool $bJson
	 * @return mixed|null
	 */
	static public function getSafe($sName, $bJson = false) {

	    # Empty
	    if (empty($sName) || !isset($_COOKIE[$sName])) { return null; }

	    # Decrypt
	    try {
	        $sValue = self::_decrypt($_COOKIE[$sName], self::_getCryptKey());
	    }
	    catch(\Exception $e) {
	        self::delete($sName);
	        die;
	    }

	    # Decode
	    return $bJson ? (array)json_decode($sValue) : $sValue;

	}

	/**
	 * SET SAFE
	 *
	 * @param string $sName
	 * @param string $mValue
	 * @param null $iTime
	 * @param bool $bJson
	 * @return bool|null
	 */
	static public function setSafe($sName, $mValue, $iTime = null, $bJson = false) {

		# Empty
	    if (empty($sName)) { return null; }

	    # Encode
	    if($bJson ) { $mValue = json_encode($mValue); }

	    # Crypt
	    try {
	        $sValue = self::_encrypt($mValue, self::_getCryptKey());
	    }
	    catch(\Exception $e) {
	        self::delete($sName);
	        die;
	    }

	    # Set
		$_COOKIE[$sName] = $sValue;
	    return setcookie($sName, $sValue, $iTime, '/');

	}

	/**
	 * DELETE
	 *
	 * @param string $sName
	 * @return bool|null
	 */
	static public function delete($sName) {

	    # Empty
	    if (empty($sName) || !isset($_COOKIE[$sName])) { return null; }

	    # Delete
	    $bUnset = setcookie($sName, $_COOKIE[$sName], time() - 3600, '/');
		unset($_COOKIE[$sName]);
		return $bUnset;

	}
}