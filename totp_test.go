package totp_test

import (
	"fmt"
	"time"

	"github.com/nikolaydubina/totp"
)

func ExampleTOTP() {
	code := totp.TOTP(time.Date(2023, 10, 10, 11, 0, 0, 0, time.UTC), []byte("example-secret"))
	fmt.Println(code)
	// Output: 0031983894
}
