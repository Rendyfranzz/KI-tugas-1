package main

import (
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/gansidui/gotcp/examples/echo"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func ExportPublicKeyAsPemStr(pubkey *rsa.PublicKey) string {
	pubkey_pem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pubkey)}))
	return pubkey_pem
}
func ExportPrivateKeyAsPemStr(privatekey *rsa.PrivateKey) string {
	privatekey_pem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}))
	return privatekey_pem
}
func ExportMsgAsPemStr(msg []byte) string {
	msg_pem := string(pem.EncodeToMemory(&pem.Block{Type: "MESSAGE", Bytes: msg}))
	return msg_pem
}

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	checkError(err)

	dat2, err := os.ReadFile("key.rsa")
	dat, err := base64.StdEncoding.DecodeString(string(dat2))
	check(err)
	renPrivateKey, err := x509.ParsePKCS1PrivateKey(dat)
	check(err)
	renPublicKey := &renPrivateKey.PublicKey

	echoProtocol := &echo.EchoProtocol{}

	fmt.Printf("%s\n", ExportPrivateKeyAsPemStr(renPrivateKey))

	masterkey := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	sessionkey := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	message := []byte{1}

	// encrypt session key
	sessionEncryptKey, err := rsa.EncryptPKCS1v15(rand.Reader, renPublicKey, sessionkey)
	if err != nil {
		fmt.Printf("error encrypting: %s", err)
	}
	// tampilkan session key yang sudah di encrypt
	fmt.Println(sessionEncryptKey)

	// decrypt session key(cuman buat ngecek)
	// plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, renPrivateKey, sessionEncryptKey)
	// if err != nil {
	// 	fmt.Printf("error decrypting: %s", err)
	// }
	// fmt.Println("SESSION KEY:", plaintext)

	// encrypt pesan1
	block, err := des.NewCipher(masterkey)
	check(err)
	block2, err := des.NewCipher(sessionkey)
	check(err)

	ciphertext := make([]byte, 8)
	block.Encrypt(ciphertext[0:8], sessionkey[0:8])
	message = append(message, sessionEncryptKey...)
	fmt.Println(message)

	//message = append(message, sessionkey...)

	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())
	p, err := echoProtocol.ReadPacket(conn)
	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	// encrypt pesan2
	//                       1234567812345678
	secretmessage := []byte("HELLOPEACEWORLD!")
	message = []byte{2}
	ciphertext = make([]byte, 16)
	block2.Encrypt(ciphertext[0:8], secretmessage[0:8])
	block2.Encrypt(ciphertext[8:16], secretmessage[8:16])
	message = append(message, ciphertext...)
	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())

	p, err = echoProtocol.ReadPacket(conn)
	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	if false {
		// ping <--> pong
		for i := 0; i < 3; i++ {
			// write
			conn.Write(echo.NewEchoPacket([]byte("hello"), false).Serialize())

			// read
			p, err := echoProtocol.ReadPacket(conn)
			if err == nil {
				echoPacket := p.(*echo.EchoPacket)
				fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
			}

			time.Sleep(2 * time.Second)
		}
	}

	conn.Close()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
