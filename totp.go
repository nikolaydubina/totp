package totp

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"strconv"
	"time"
)

var (
	TimeStep time.Duration = 30 * time.Second
	TimeZero time.Time     = time.Unix(0, 0)
	Hash                   = sha512.New
	Digits                 = 10
)

// TOTP is Time based One-Time Password RFC-6238
func TOTP(t time.Time, key []byte) string { return HOTP(timeStepWindow(t, TimeZero, TimeStep), key) }

// HOTP is HMAC-based One-Time Password RFC-4226
func HOTP(counter uint64, key []byte) string {
	ctr := make([]byte, 8)
	binary.BigEndian.PutUint64(ctr, counter)
	h := hmac.New(Hash, key)
	h.Write(ctr)
	return formatDecimal(truncate(h.Sum(nil)), Digits)
}

func timeStepWindow(t, zero time.Time, step time.Duration) uint64 { return uint64(t.Sub(zero) / step) }

func truncate(digest []byte) uint64 {
	offset := digest[len(digest)-1] & 0x0f
	var code uint64
	code |= uint64((digest[offset+0] & 0x7f)) << 24
	code |= uint64((digest[offset+1] & 0xff)) << 16
	code |= uint64((digest[offset+2] & 0xff)) << 8
	code |= uint64((digest[offset+3] & 0xff)) << 0
	return code
}

func formatDecimal(v uint64, width int) string {
	const padding = "00000000000000000000"
	s := strconv.FormatUint(v, 10)
	if len(s) < width {
		s = padding[:width-len(s)] + s
	}
	return s[len(s)-width:]
}
