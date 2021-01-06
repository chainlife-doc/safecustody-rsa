package test

import (
	"encoding/hex"
	"fmt"
	rsa "safecustody_rsa"
	"testing"
)

func Test_Rsa1(t *testing.T) {
	msg := []byte("RSA非对称加密1")
	//加密
	ciphertext := rsa.RSAEncrypt(rsa.PublicKeyName, msg)

	//转化为十六进制方便查看结果
	fmt.Println(hex.EncodeToString(ciphertext))

	//解密
	result := rsa.RSADecrypt(rsa.PrivateKeyName, ciphertext)
	fmt.Println(string(result))
}

func Test_Rsa2(t *testing.T) {

	bk := `-----BEGIN PublicKey-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuPi+xewEu/OCUiIyIRRg
0HmJa1acz+ClKzynUSkB7CXZu8or3TP/kvqPkKy+zTTWr+FVBusF214xs50geqy6
afEqTonWKoeoDw8xLeKZucN+yc7iEK3WmDtPmbLGA7r4oV5I5ehrxXiJy6bL9Vsz
Kj79J41rJKUQEjHWH92oAzvNeMJGGGVtqM2plQosBqMmJWRwaMJXnVBf60W5UfF7
EOtI1Y07MGFWeWxaS7gLOvRHGAmuiRmLlREwA+IoTU3b5VRb/D5JulIU1ybtVOrL
zzxYJGSUAZbCWZguIxLinYqU9ZTQzvV9nIX1oK1XUXAyVdD55iyVzz4zhQhS/VrO
nQIDAQAB
-----END PublicKey-----`

	pk := `-----BEGIN privateKey-----
MIIEpAIBAAKCAQEAuPi+xewEu/OCUiIyIRRg0HmJa1acz+ClKzynUSkB7CXZu8or
3TP/kvqPkKy+zTTWr+FVBusF214xs50geqy6afEqTonWKoeoDw8xLeKZucN+yc7i
EK3WmDtPmbLGA7r4oV5I5ehrxXiJy6bL9VszKj79J41rJKUQEjHWH92oAzvNeMJG
GGVtqM2plQosBqMmJWRwaMJXnVBf60W5UfF7EOtI1Y07MGFWeWxaS7gLOvRHGAmu
iRmLlREwA+IoTU3b5VRb/D5JulIU1ybtVOrLzzxYJGSUAZbCWZguIxLinYqU9ZTQ
zvV9nIX1oK1XUXAyVdD55iyVzz4zhQhS/VrOnQIDAQABAoIBAQChypGztVn+vGRF
Szvly1lTgLs+dCf9fFV8mDURvHi+Ae2NYK01cwIdoaRpu2+5NnqCpOomfvREiQOY
Q9vg8aysdhG3WMFHuhi582Pk6svjvKfuBVOfmy6VQWvC2KhzItvO6hWBY+bAd0qw
I1lLZ1Y9oZL1QbFyAB8qiwTsIomPKQZfNaPbeJ0ueqCh6UqYFMIGTcqd9JpMSasb
YS7diI1RJrOpgp/NoGptGtsDb1r63XoqXD0Bk9AndUnR+TaZS8KqfpdXyC91r+cB
gyxzXkkbPJ8DiZfXa6hzSfNN6UxqhY80hB5wHM9pRxmAW3TvSWIkMpbqshPldfhA
b2YbAXTRAoGBAMsdnOcnm7SorGyLCKzJy5P6TtVH0zm2SDH3QDJmbOUYbTQJ4aIm
gqq64RqSU87bFYzUlSlT/U/BkLMYHesGvFE1hq6MzOhH/z/oxRmtwnbUH4/l7x4I
7wVMGSPZkS5FHRIWLpTOQwV4qxEv+mrI6nkwG5+kz8dpg86YcgI74Vm7AoGBAOkh
xM4+BvABgZRe5uDa2LRvN1PxuYH4F3SUjvUyQmzOTJQEgFg/Ogqy/5xDm5Vp2oZs
ugeQ9cizMs/0BhTJOoL1reh/t/HBo8kU2aCtalXClcLCW/j6DQGrrv3j/IXLVYNT
7NbuQ/f2BjdrA5tnST/Uf41SKuJoCsD/xiRoeyeHAoGAD5rP0iaF3ORUkuY/nV7H
iC/j3JjvDnEFrOkNApJB7Xvp7+SOdDG3OjyvTKZPUAYe6rnuV8V/IaCCaHAC5GqZ
Dzgoh8KDf5kAcD2G3wktdomnfxuwOkN/cY2+JLXzZHWk3R3dKEuMdKAnrGNePtP+
x569kI9N80kU+ktV/vvwvT8CgYEAtCr8xcb55ZHEar3NAAkhYJBy2dT94Iuy1M3a
jXQCEcR9OgcgiRKT8KDVGhbFrnrX/vsX6bEFwc17f2q/KGE7buofNIc/yP41bblH
Vv2uKAjxZEqAebIFSz07R8th5KR3ub6qUpBgxsjDlSCG8RqpaUL4MGdH7SEq7my8
3HZCdxECgYBTK4r5dWNBkvrIaqTsx8l1TALIE2UU1YRT8rwB0L1KdKZRlJi9vaNn
w1KsWbzv/iiPkOcAgkKDXadW1mJOIsvmFZahE67FizUnKAYGkLxIdbekm0GxhdqA
C+LCzs3N3Q1uwtksTueDfaSMyvq9DzB87I3xEN2z+9TOv5pjcTAHdw==
-----END privateKey-----`

	msg := []byte("RSA非对称加密2")
	ciphertext := rsa.RSAEncryptInput([]byte(bk), msg)

	result := rsa.RSADecryptInput([]byte(pk), ciphertext)
	fmt.Println(string(result))
}

//获取公私钥
func Test_GetKeys(t *testing.T) {
	rsa.GetKeys()
}
