<?php  
class CryptAES{ 
 	private function _pkcs5Pad($text, $blockSize){
      	$pad = $blockSize - (strlen($text) % $blockSize);
      	return $text . str_repeat(chr($pad), $pad);
  	}
 
  	private function _pkcs5Unpad($text){
      	$end 	= substr($text, -1);
      	$last 	= ord($end);
      	$len 	= strlen($text) - $last;
      	if(substr($text, $len) == str_repeat($end, $last)){
          	return substr($text, 0, $len);
      	}
      	return false;
  	}
 
  	public function encrypt($encrypt, $key){
      	$blockSize 	= mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
      	$paddedData = $this->_pkcs5Pad($encrypt, $blockSize);
      	$ivSize 	= mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
      	$iv 		= mcrypt_create_iv($ivSize, MCRYPT_RAND);
      	$key2 		= substr(openssl_digest(openssl_digest($key, 'sha1', true), 'sha1', true), 0, 16);
      	$encrypted 	= mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key2, $paddedData, MCRYPT_MODE_ECB, $iv);
      	return base64_encode($encrypted);
  	}
 
  	public function decrypt($decrypt, $key){
  	  	$decrypt 	= base64_decode($decrypt);
      	$decoded 	= $decrypt;
      	$blockSize 	= mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
      	$ivSize 	= mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
      	$iv 		= mcrypt_create_iv($ivSize, MCRYPT_RAND);
      	$key2 		= substr(openssl_digest(openssl_digest($key, 'sha1', true), 'sha1', true), 0, 16);
      	$decrypted 	= mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key2, $decoded, MCRYPT_MODE_ECB, $iv);
      	return $this->_pkcs5Unpad($decrypted);
  	}
}
$key 		= '123456789';
$CryptAES 	= new CryptAES();
$decode 	= $CryptAES->encrypt('{"username":"Luke","password":"123456","status":"0"}' ,$key);
var_dump($decode);
$encode 	= $CryptAES->decrypt($decode ,$key);
var_dump($encode);