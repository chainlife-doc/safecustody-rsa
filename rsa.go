package safecustody_rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

const PublicKeyName = "PublicKey.pem"
const PrivateKeyName = "private.pem"

//创建公私钥
func GetKeys() {
	//生成私钥
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	fp, _ := os.Create(PrivateKeyName)
	defer fp.Close()

	pemBlock := pem.Block{
		Type:  "privateKey",
		Bytes: x509PrivateKey,
	}
	pem.Encode(fp, &pemBlock)

	//生成公钥
	publicKey := privateKey.PublicKey
	x509PublicKey, _ := x509.MarshalPKIXPublicKey(&publicKey)
	pemPublicKey := pem.Block{
		Type:  "PublicKey",
		Bytes: x509PublicKey,
	}

	file, _ := os.Create(PublicKeyName)
	defer file.Close()

	pem.Encode(file, &pemPublicKey)
}

//使用公钥进行加密
func RSAEncrypt(path string, msg []byte) []byte {
	return RSAEncryptInput(RSAUnmarshalByte(path), msg)
}

//使用私钥进行解密
func RSADecrypt(path string, cipherText []byte) []byte {
	return RSADecryptInput(RSAUnmarshalByte(path), cipherText)
}

//解析成字节
func RSAUnmarshalByte(path string) []byte {
	fp, _ := os.Open(path)
	defer fp.Close()

	fileinfo, _ := fp.Stat()
	buf := make([]byte, fileinfo.Size())
	_, _ = fp.Read(buf)
	return buf
}

//使用公钥的内容进行加密
func RSAEncryptInput(publicKey, msg []byte) []byte {
	block, _ := pem.Decode(publicKey)

	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	cipherText, _ := rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), msg)

	return cipherText
}

//使用私钥的内容进行解密
func RSADecryptInput(privateKey, cipherText []byte) []byte {
	block, _ := pem.Decode(privateKey)
	PrivateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	afterDecrypt, _ := rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, cipherText)
	return afterDecrypt
}
