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
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/gansidui/gotcp"
	"github.com/gansidui/gotcp/examples/echo"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

var sessionkey = []byte{9, 10, 11, 12, 13, 14, 15, 16}

type Callback struct{}

func (this *Callback) OnConnect(c *gotcp.Conn) bool {
	addr := c.GetRawConn().RemoteAddr()
	c.PutExtraData(addr)
	fmt.Println("OnConnect:", addr)
	return true
}
func ExportPrivateKeyAsPemStr(privatekey *rsa.PrivateKey) string {
	privatekey_pem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}))
	return privatekey_pem
}

func (this *Callback) OnMessage(c *gotcp.Conn, p gotcp.Packet) bool {
	echoPacket := p.(*echo.EchoPacket)
	fmt.Printf("OnMessage:[%v] [%v]\n", echoPacket.GetLength(), echoPacket.GetBody())
	body := echoPacket.GetBody()
	if body[0] == 1 {
		// masterkey := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		paket := echo.NewEchoPacket([]byte("OK1"), false)
		plaintext := make([]byte, 8)

		sessionEncryptKey := echoPacket.GetBody()[1:]
		fmt.Println("sessionEncryptKey:", sessionEncryptKey)
		dat2, err := os.ReadFile("key.rsa")
		dat, err := base64.StdEncoding.DecodeString(string(dat2))
		check(err)
		renPrivateKey, err := x509.ParsePKCS1PrivateKey(dat)
		check(err)
		fmt.Println(ExportPrivateKeyAsPemStr(renPrivateKey))

		sessionkey, err := rsa.DecryptPKCS1v15(rand.Reader, renPrivateKey, sessionEncryptKey)
		if err != nil {
			fmt.Printf("error decrypting: %s", err)
		}
		copy(sessionkey, plaintext[0:8])
		fmt.Println("SESSION KEY:", sessionkey)
		c.AsyncWritePacket(paket, time.Second)

	} else if body[0] == 2 {
		pak := echoPacket.GetBody()[1:]
		plaintext := make([]byte, 16)

		block, err := des.NewCipher(sessionkey)
		check(err)

		block.Decrypt(plaintext[0:8], pak[0:8])
		block.Decrypt(plaintext[8:16], pak[8:16])
		fmt.Println("SECRET MESSAGE: " + string(plaintext))

		paket := echo.NewEchoPacket([]byte("OK2"), false)
		c.AsyncWritePacket(paket, time.Second)

	}
	return true
}

func (this *Callback) OnClose(c *gotcp.Conn) {
	fmt.Println("OnClose:", c.GetExtraData())
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// creates a tcp listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":8989")
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	// creates a server
	config := &gotcp.Config{
		PacketSendChanLimit:    20,
		PacketReceiveChanLimit: 20,
	}
	srv := gotcp.NewServer(config, &Callback{}, &echo.EchoProtocol{})

	// starts service
	go srv.Start(listener, time.Second)
	fmt.Println("listening:", listener.Addr())

	// catchs system signal
	chSig := make(chan os.Signal)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Signal: ", <-chSig)

	// stops service
	srv.Stop()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
