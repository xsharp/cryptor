<?php

namespace Zeed\Cryptor;


class Cryptor
{
    /**
     * 私钥签名
     *
     * @param string $data_str
     * @param string|resource $pkey
     *            私钥，连续不换行
     * @param mixed $signature_alg
     *            默认：OPENSSL_ALGO_SHA1，有的渠道是：OPENSSL_ALGO_SHA256
     * @return string
     */
    public static function openssl_sign($data_str, $pkey, $signature_alg = null)
    {
        if (is_string($pkey)) {
            $private_key_id = openssl_pkey_get_private(self::pkeyFormatWithLabel($pkey, Label::CERT_LABEL_RSA));
        } elseif (is_resource($pkey)) {
            $private_key_id = $pkey;
        } else {
            return false;
        }

        $signature = false;
        if (is_null($signature_alg)) {
            openssl_sign($data_str, $signature, $private_key_id);
        } else {
            openssl_sign($data_str, $signature, $private_key_id, $signature_alg);
        }
        openssl_free_key($private_key_id);

        return base64_encode($signature);
    }

    /**
     * 公钥校验签名
     *
     * @param string $data_str
     * @param string $sign
     * @param string|resource $pkey
     * @param mixed $signature_alg
     *            默认：OPENSSL_ALGO_SHA1，有的渠道是：OPENSSL_ALGO_MD5
     * @return number
     */
    public static function openssl_verify($data_str, $sign, $pkey, $signature_alg = null)
    {
        if (is_string($pkey)) {
            $public_key_id = openssl_pkey_get_public(self::pkeyFormatWithLabel($pkey, Label::CERT_LABEL_PUBLIC));
        } elseif (is_resource($pkey)) {
            $public_key_id = $pkey;
        } else {
            return 0;
        }

        if (is_null($signature_alg)) {
            $result = openssl_verify($data_str, base64_decode($sign), $public_key_id);
        } else {
            $result = openssl_verify($data_str, base64_decode($sign), $public_key_id, $signature_alg);
        }
        openssl_free_key($public_key_id);

        return $result;
    }

    /**
     * 公钥解密-支持超长字串
     *
     * @param string $data
     * @param string|resource $data
     * @param string $padding
     * @return string|boolean
     */
    public static function openssl_public_decrypt($data, $pkey, $padding = OPENSSL_PKCS1_PADDING)
    {
        return self::_decrypt($data, $pkey, SignMethod::OPENSSL_PUBLIG, $padding);
    }

    /**
     * 公钥解密-支持超长字串
     *
     * @param string $data
     * @param string|resource $pkey
     * @param string $padding
     * @return boolean|string
     */
    public static function openssl_public_encrypt($data, $pkey, $padding = OPENSSL_PKCS1_PADDING)
    {
        return self::_encrypt($data, $pkey, SignMethod::OPENSSL_PUBLIG, $padding);
    }

    /**
     * 公钥加密-支持超长字串
     *
     * @param string $data
     * @param string|resource $pkey
     * @param string $padding
     * @return boolean
     */
    public static function openssl_private_decrypt($data, $pkey, $padding = OPENSSL_PKCS1_PADDING)
    {
        return self::_decrypt($data, $pkey, SignMethod::OPENSSL_PRIVATE, $padding);
    }

    /**
     * 私钥加密-支持超长字串
     *
     * @param string $data
     * @param string|resource $pkey
     * @param string $padding
     * @return boolean|string
     */
    public static function openssl_private_encrypt($data, $pkey, $padding = OPENSSL_PKCS1_PADDING)
    {
        return self::_encrypt($data, $pkey, SignMethod::OPENSSL_PRIVATE, $padding);
    }

    /**
     * 公钥/私钥分段解密
     * openssl_private_encrypt($data, $crypted, $key);
     * openssl_public_encrypt($data, $crypted, $key);
     *
     * @param string $data
     * @param string|resource $pkey
     * @param string $method
     * @param int $padding
     * @return boolean|string
     */
    private static function _encrypt($data, $pkey, $method = SignMethod::OPENSSL_PRIVATE, $padding = OPENSSL_PKCS1_PADDING)
    {
        if ($method == SignMethod::OPENSSL_PRIVATE) {
            $pkey_get_function = 'openssl_pkey_get_private';
            $pkey_encrypt_function = 'openssl_private_encrypt';
            $pkey_pem = Label::CERT_LABEL_RSA;
        } elseif ($method == SignMethod::OPENSSL_PUBLIG) {
            $pkey_get_function = 'openssl_pkey_get_public';
            $pkey_encrypt_function = 'openssl_public_encrypt';
            $pkey_pem = Label::CERT_LABEL_PUBLIC;
        } else {
            return false;
        }

        if (is_string($pkey)) {
            $pkey_id = $pkey_get_function(self::pkeyFormatWithLabel($pkey, $pkey_pem));
        } elseif (is_resource($pkey)) {
            $pkey_id = $pkey;
        } else {
            return false;
        }

        $pkey_detail = openssl_pkey_get_details($pkey_id);
        if (!$pkey_detail) {
            return false;
        }
        $bits = $pkey_detail['bits'];
        $maxBlock = $bits / 8 - 11; // 117

        $dataLen = strlen($data);
        $offSet = 0;
        $i = 0;
        $return = '';
        while ($dataLen - $offSet > 0) {
            $cache = '';
            if ($dataLen - $offSet > $maxBlock) {
                $pkey_encrypt_function(substr($data, $offSet, $maxBlock), $cache, $pkey_id, $padding);
            } else {
                $pkey_encrypt_function(substr($data, $offSet, $dataLen - $offSet), $cache, $pkey_id, $padding);
            }

            $return .= $cache;

            $i = $i + 1;
            $offSet = $i * $maxBlock;
        }

        return $return;
    }

    /**
     * 公钥/私钥分段加密
     * openssl_private_decrypt($data, $decrypted, $key);
     * openssl_public_decrypt($data, $decrypted, $key)
     *
     * @param string $data
     * @param string|resource $pkey
     * @param string $method
     * @param int $padding
     * @return boolean
     */
    private static function _decrypt($data, $pkey, $method = SignMethod::OPENSSL_PUBLIG, $padding = OPENSSL_PKCS1_PADDING)
    {
        if ($method == SignMethod::OPENSSL_PRIVATE) {
            $pkey_get_function = 'openssl_pkey_get_private';
            $pkey_decrypt_function = 'openssl_private_decrypt';
            $pkey_pem = Label::CERT_LABEL_RSA;
        } elseif ($method == SignMethod::OPENSSL_PUBLIG) {
            $pkey_get_function = 'openssl_pkey_get_public';
            $pkey_decrypt_function = 'openssl_public_decrypt';
            $pkey_pem = Label::CERT_LABEL_PUBLIC;
        } else {
            return false;
        }

        if (is_string($pkey)) {
            $pkey_id = $pkey_get_function(self::pkeyFormatWithLabel($pkey, $pkey_pem));
        } elseif (is_resource($pkey)) {
            $pkey_id = $pkey;
        } else {
            return false;
        }

        $pkey_detail = openssl_pkey_get_details($pkey_id);
        if (!$pkey_detail) {
            return false;
        }
        $bits = $pkey_detail['bits'];
        $maxBlock = $bits / 8; // 1024 => 128

        $dataLen = strlen($data);
        $offSet = 0;
        $i = 0;
        $return = '';
        while ($dataLen - $offSet > 0) {
            $cache = '';
            if ($dataLen - $offSet > $maxBlock) {
                $pkey_decrypt_function(substr($data, $offSet, $maxBlock), $cache, $pkey_id, $padding);
            } else {
                $pkey_decrypt_function(substr($data, $offSet, $dataLen - $offSet), $cache, $pkey_id, $padding);
            }

            $return .= $cache;

            $i = $i + 1;
            $offSet = $i * $maxBlock;
        }

        return $return;
    }

    /**
     *
     * @param string $pkey
     * @return array | false
     */
    public static function openssl_private_key_details($pkey)
    {
        if (is_string($pkey)) {
            $pkey_id = openssl_pkey_get_private(self::pkeyFormatWithLabel($pkey, Label::CERT_LABEL_RSA));
        } elseif (is_resource($pkey)) {
            $pkey_id = $pkey;
        } else {
            return false;
        }

        return openssl_pkey_get_details($pkey_id);
    }

    /**
     *
     * @param string $pkey
     * @return array | false
     */
    public static function openssl_public_key_details($pkey)
    {
        if (is_string($pkey)) {
            $pkey_id = openssl_pkey_get_public(self::pkeyFormatWithLabel($pkey, Label::CERT_LABEL_PUBLIC));
        } elseif (is_resource($pkey)) {
            $pkey_id = $pkey;
        } else {
            return false;
        }

        return openssl_pkey_get_details($pkey_id);
    }

    /**
     * 格式化成 PEM 格式：
     *
     * -----BEGIN CERTIFICATE REQUEST----- and -----END CERTIFICATE REQUEST----- show a CSR in PEM format.
     * -----BEGIN RSA PRIVATE KEY----- and -----END RSA PRIVATE KEY----- show a private key in PEM format.
     * -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- show a certificate file in PEM format.
     *
     * @see https://tools.ietf.org/html/rfc7468
     * @see https://github.com/libressl-portable/openbsd/blob/master/src/lib/libcrypto/pem/pem.h
     * @see http://deerchao.net/tutorials/regex/regex.htm
     * @see https://en.wikipedia.org/wiki/PKCS
     *
     * @param string $pkey_str
     * @return string
     */
    public static function pkeyFormatWithLabel($pkey_str, $label)
    {
        if (!preg_match('~^-----BEGIN ([A-Z ]+)-----\s*?([A-Za-z0-9+=/\r\n]+)\s*?-----END \1-----\s*$~D', $pkey_str)) {
            $pkey_str = preg_replace("/\r|\n|\s+/", "", $pkey_str);

            $pkey_str = chunk_split($pkey_str, 64, "\n");
            $pkey_str = "-----BEGIN " . $label . "-----\n" . $pkey_str . "-----END " . $label . "-----\n";
        }

        return $pkey_str;
    }
}

class SignMethod
{

    const OPENSSL_PUBLIG = 1;

    const OPENSSL_PRIVATE = 0;
}

/**
 * Privacy-enhanced Electronic Mail
 *
 * @see https://tools.ietf.org/html/rfc7468
 * @see https://github.com/libressl-portable/openbsd/blob/master/src/lib/libcrypto/pem/pem.h
 */
class Label
{

    const CERT_LABEL_X509_OLD = "X509 CERTIFICATE";

    const CERT_LABEL_X509 = "CERTIFICATE";

    const CERT_LABEL_X509_PAIR = "CERTIFICATE PAIR";

    const CERT_LABEL_X509_TRUSTED = "TRUSTED CERTIFICATE";

    const CERT_LABEL_X509_REQ_OLD = "NEW CERTIFICATE REQUEST";

    const CERT_LABEL_X509_REQ = "CERTIFICATE REQUEST";

    const CERT_LABEL_X509_CRL = "X509 CRL";

    const CERT_LABEL_EVP_PKEY = "ANY PRIVATE KEY";

    const CERT_LABEL_PUBLIC = "PUBLIC KEY";

    const CERT_LABEL_RSA = "RSA PRIVATE KEY";

    const CERT_LABEL_RSA_PUBLIC = "RSA PUBLIC KEY";

    const CERT_LABEL_DSA = "DSA PRIVATE KEY";

    const CERT_LABEL_DSA_PUBLIC = "DSA PUBLIC KEY";

    const CERT_LABEL_PKCS7 = "PKCS7";

    const CERT_LABEL_PKCS7_SIGNED = "PKCS #7 SIGNED DATA";

    const CERT_LABEL_PKCS8 = "ENCRYPTED PRIVATE KEY";

    const CERT_LABEL_PKCS8INF = "PRIVATE KEY";

    const CERT_LABEL_DHPARAMS = "DH PARAMETERS";

    const CERT_LABEL_SSL_SESSION = "SSL SESSION PARAMETERS";

    const CERT_LABEL_DSAPARAMS = "DSA PARAMETERS";

    const CERT_LABEL_ECDSA_PUBLIC = "ECDSA PUBLIC KEY";

    const CERT_LABEL_ECPARAMETERS = "EC PARAMETERS";

    const CERT_LABEL_ECPRIVATEKEY = "EC PRIVATE KEY";

    const CERT_LABEL_PARAMETERS = "PARAMETERS";

    const CERT_LABEL_CMS = "CMS";
}