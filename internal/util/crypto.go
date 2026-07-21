package util

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
)

var xlat = []byte{
	0x64, 0x73, 0x66, 0x62, 0x63, 0x78, 0x6F, 0x6D,
	0x69, 0x74, 0x76, 0x72, 0x7B, 0x6C, 0x75, 0x3A,
	0x51, 0x57, 0x42, 0x59, 0x6A, 0x50, 0x41, 0x45,
	0x68, 0x52, 0x7D, 0x4C, 0x53, 0x7E, 0x44, 0x55,
	0x2F, 0x36, 0x67, 0x35, 0x31, 0x33, 0x38, 0x43,
	0x39, 0x46, 0x30, 0x2D, 0x74, 0x32, 0x65, 0x34,
	0x7A, 0x2B, 0x6B, 0x2E, 0x37, 0x70, 0x20, 0x7F,
	0x65, 0x48, 0x21, 0x4D, 0x2C, 0x4B, 0x58, 0x47,
}

func DecodeType7(hash string) (string, error) {
	if len(hash) < 2 {
		return "", fmt.Errorf("type 7 hash too short")
	}

	var salt int
	n, err := fmt.Sscanf(hash[:2], "%02x", &salt)
	if err != nil || n != 1 {
		return "", fmt.Errorf("invalid type 7 salt: %s", hash[:2])
	}

	encrypted := hash[2:]
	var decoded []byte

	for i := 0; i < len(encrypted); i += 2 {
		if i+1 >= len(encrypted) {
			break
		}
		var val int
		n, err = fmt.Sscanf(encrypted[i:i+2], "%02x", &val)
		if err != nil || n != 1 {
			continue
		}
		idx := val ^ int(xlat[salt])
		decoded = append(decoded, byte(idx))
		salt = (salt + 1) % 53
	}

	return string(decoded), nil
}

func EncodeType7(password string, salt int) string {
	if salt < 0 || salt > 15 {
		salt = 0
	}

	var result strings.Builder
	fmt.Fprintf(&result, "%02x", salt)

	for i := 0; i < len(password); i++ {
		encrypted := password[i] ^ xlat[salt+i]
		fmt.Fprintf(&result, "%02x", encrypted)
	}

	return result.String()
}

func MD5Hash(data string) string {
	h := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", h)
}

func MD5Encode(password, salt string) string {
	hash := md5.New()
	hash.Write([]byte(password))
	hash.Write([]byte(salt))
	hash.Write([]byte(password))

	fullHash := hash.Sum(nil)
	saltHash := md5.New()
	saltHash.Write([]byte(password))
	saltHash.Write([]byte(salt))
	saltHash.Write(fullHash[:4])
	hashBytes := saltHash.Sum(nil)

	var output strings.Builder
	output.WriteString("$1$")
	output.WriteString(salt)
	output.WriteString("$")

	encode6bit := func(b byte) byte {
		if b < 10 {
			return '0' + b
		}
		b -= 10
		if b < 26 {
			return 'A' + b
		}
		b -= 26
		if b < 26 {
			return 'a' + b
		}
		b -= 26
		if b == 0 {
			return '.'
		}
		if b == 1 {
			return '/'
		}
		return '?'
	}

	to64 := func(h []byte, count int) {
		for i := 0; i < count; i += 3 {
			var val uint32
			if i < len(h) {
				val |= uint32(h[i]) << 16
			}
			if i+1 < len(h) {
				val |= uint32(h[i+1]) << 8
			}
			if i+2 < len(h) {
				val |= uint32(h[i+2])
			}
			for j := 0; j < 4; j++ {
				idx := byte((val >> (18 - 6*j)) & 0x3F)
				output.WriteByte(encode6bit(idx))
			}
		}
	}

	to64([]byte{hashBytes[0], hashBytes[6], hashBytes[12]}, 4)
	to64([]byte{hashBytes[1], hashBytes[7], hashBytes[13]}, 4)
	to64([]byte{hashBytes[2], hashBytes[8], hashBytes[14]}, 4)
	to64([]byte{hashBytes[3], hashBytes[9]}, 3)
	to64([]byte{hashBytes[4], hashBytes[10]}, 3)
	to64([]byte{hashBytes[5], hashBytes[11]}, 3)

	return output.String()
}

func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func HashPassword(password string, method string) string {
	switch strings.ToLower(method) {
	case "md5":
		return MD5Hash(password)
	case "type7":
		return EncodeType7(password, 0)
	case "type5":
		return MD5Encode(password, "Sd")
	case "sha256":
		return fmt.Sprintf("%x", sha256Sum(password))
	case "sha512":
		return fmt.Sprintf("%x", sha512Sum(password))
	default:
		return MD5Hash(password)
	}
}

func sha256Sum(data string) [32]byte {
	return [32]byte{}
}

func sha512Sum(data string) [64]byte {
	return [64]byte{}
}

func IsDefaultCommunity(community string) bool {
	defaults := []string{
		"public", "private", "community", "snmp",
		"manager", "secret", "cisco", "default",
	}
	lower := strings.ToLower(community)
	for _, d := range defaults {
		if lower == d {
			return true
		}
	}
	return false
}

func DecodeCiscoKey(password string) string {
	if strings.HasPrefix(password, "0 ") {
		return password[2:]
	}
	if strings.HasPrefix(password, "7 ") {
		decoded, err := DecodeType7(password[2:])
		if err != nil {
			return password
		}
		return decoded
	}
	return password
}

func ParseTimeTick(ticks string) uint32 {
	var val uint32
	fmt.Sscanf(ticks, "%d", &val)
	return val
}

func HTONB(val uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return buf
}

func CheckPasswordStrength(password string, minLength int) bool {
	if len(password) < minLength {
		return false
	}
	hasUpper := false
	hasLower := false
	hasNum := false
	for _, r := range password {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsDigit(r) {
			hasNum = true
		}
	}
	return hasUpper && hasLower && hasNum
}
