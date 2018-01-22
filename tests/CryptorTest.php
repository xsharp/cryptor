<?php

use Zeed\Cryptor\Cryptor;

require_once __DIR__ . '/../src/Cryptor.php';

$prik = '-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCtxKMuGIv1ERWmJm4g7a9SfOXymu1pGv1AolFnkjHSa+edVJop
kIg0QDyW7fC14NPZXLT6V765YtZv7EU6OEnrZ+lxrQS2gAbbj0F+OEzO9yd/9cKc
XoRb7EBYiw91Lc49cBcAn0QMO9iYb95qRxEdzxymAs9Te5B1B+sATVa7cQIDAQAB
AoGAd9BRw4LhXcS97KYq4UGB1ZqQ4sq4T/RwEpTZFFTVTYVhWjXvZiFmCMESBe9i
PcYbzJADqWm+9AyWVu3Ofeo57JfpxUJw93mVyUvj6IIs+3ktmY3Db/G0RoGpao3C
NvsIwZDjQBlyHH4/ZuIHfRQ80PZCvylx1jBC9SZ2pLYixJECQQDZPgEms96zkJK1
vuwsf510IaQz79w9Rb1nSG08iBlxNJjbQAhwrNbxXjRz6Afd9RfZLoE01YNhg7ZK
+1YbIagnAkEAzMUP9yeFdQ1Hxmw5f4t9e0RL3Tbyf6A9uUr4V2hPCh/h8BFcaDo4
Nk98svsgJtabMBRo8d1xjHVFj+7O8pnmpwJAV4YnqJQnUWkZ8qdtN7Bim3tCULp+
nSEP4iDIAe9DcNykCRGPVPYN00kFEP2WzdIFPbcCz2qGeC88rpD8bAnvWQJBAJxn
FDe6JxRtrVngRdamq5RgaPWxR2217g8+NQtGL8DS81bTW9p8RX0uH1fxufAQUP5b
SIEcm+Mlm5lBVS414NcCQQC3N4m1L8UmoX+64DkYrrj1s/2IWMUX594qD7hNyRC2
urDAx2ImZbpnfosueHiryTA3G5QV7Y2VoFRvkr/sImTk
-----END RSA PRIVATE KEY-----';

$pubk = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtxKMuGIv1ERWmJm4g7a9SfOXy
mu1pGv1AolFnkjHSa+edVJopkIg0QDyW7fC14NPZXLT6V765YtZv7EU6OEnrZ+lx
rQS2gAbbj0F+OEzO9yd/9cKcXoRb7EBYiw91Lc49cBcAn0QMO9iYb95qRxEdzxym
As9Te5B1B+sATVa7cQIDAQAB
-----END PUBLIC KEY-----';

$t1 = <<<EOT
富强、民主、文明、和谐；
自由、平等、公正、法治；
爱国、敬业、诚信、友善。
EOT;

echo "原始内容：\n" . $t1 . PHP_EOL . PHP_EOL;

$enPrivate = Cryptor::openssl_private_encrypt($t1, $prik);
echo "私钥加密（Base64）：" . base64_encode($enPrivate) . PHP_EOL;

$dePublic = Cryptor::openssl_public_decrypt($enPrivate, $pubk);
echo "公钥解密：\n" . $dePublic . PHP_EOL . PHP_EOL;


$enPublic = Cryptor::openssl_public_encrypt($t1, $pubk);
echo "公钥加密（Base64）：" . base64_encode($enPublic) . PHP_EOL;

$dePrivate = Cryptor::openssl_private_decrypt($enPublic, $prik);
echo "私钥解密：\n" . $dePrivate . PHP_EOL;