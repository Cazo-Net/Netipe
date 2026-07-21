package util

import (
	"bufio"
	"os"
	"strings"
	"unicode"
)

var defaultDictionary = []string{
	"password", "cisco", "enable", "admin", "test",
	"root", "default", "pass", "1234", "12345",
	"123456", "secret", "changeme", "welcome", "login",
	"public", "private", "manager", "snmp", "community",
	"access", "system", "network", "server", "switch",
	"router", "firewall", "monitor", "debug", "temp",
	"temporary", "guest", "user", "support", "help",
	"info", "data", "backup", "cisco123", "Cisco",
	"tacacs", "rad", "aaa", "nt", "unix",
	"linux", "windows", "sun", "oracle", "sql",
	"passw0rd", "letmein", "trustno1", "master",
	"superman", "michael", "jennifer", "thomas",
	"jordan", "killer", "dragon", "batman",
	"shadow", "qwerty", "abc123", "mustang",
	"password1", "password123", "iloveyou",
	"sunshine", "princess", "football", "charlie",
	"shadow1", "hello", "freedom", "whatever",
	"nicole", "daniel", "jessica", "pepper",
	"ranger", "buster", "soccer", "hockey",
	"phoenix", "matrix", "spider", "eagle",
	"falcon", "tiger", "panther", "diamond",
}

type PasswordCheckResult struct {
	Password      string
	IsDefault     bool
	IsWeak        bool
	IsDictionary  bool
	IsShort       bool
	MinLength     int
	HasUppercase  bool
	HasLowercase  bool
	HasNumbers    bool
	HasSpecial    bool
	Score         int
}

func CheckPassword(password string, minLength int, dictFile string) *PasswordCheckResult {
	result := &PasswordCheckResult{
		Password: password,
		MinLength: minLength,
	}

	dictionary := loadDictionary(dictFile)

	result.IsDefault = isDefaultPassword(password)
	result.IsDictionary = isDictionaryWord(password, dictionary)
	result.IsShort = len(password) < minLength
	result.HasUppercase = containsUppercase(password)
	result.HasLowercase = containsLowercase(password)
	result.HasNumbers = containsNumbers(password)
	result.HasSpecial = containsSpecial(password)

	if result.IsDefault || result.IsDictionary || result.IsShort {
		result.IsWeak = true
	}

	result.Score = calculateStrength(password)

	return result
}

func isDefaultPassword(password string) bool {
	defaults := []string{
		"", "password", "cisco", "enable", "admin",
		"test", "root", "default", "pass", "secret",
		"changeme", "public", "private", "manager",
		"cisco123", "Cisco", "tacacs",
	}
	lower := strings.ToLower(password)
	for _, d := range defaults {
		if lower == strings.ToLower(d) {
			return true
		}
	}
	return false
}

func isDictionaryWord(password string, dictionary []string) bool {
	lower := strings.ToLower(password)
	for _, word := range dictionary {
		if strings.Contains(lower, strings.ToLower(word)) {
			return true
		}
	}
	return false
}

func loadDictionary(path string) []string {
	if path == "" {
		return defaultDictionary
	}

	file, err := os.Open(path)
	if err != nil {
		return defaultDictionary
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			words = append(words, word)
		}
	}

	if len(words) == 0 {
		return defaultDictionary
	}
	return words
}

func containsUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func containsNumbers(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func calculateStrength(password string) int {
	score := 0

	score += len(password) * 4

	if containsUppercase(password) {
		score += (len(password) - countUpper(password)) * 2
	}
	if containsLowercase(password) {
		score += (len(password) - countLower(password)) * 2
	}
	if containsNumbers(password) {
		score += countNumbers(password) * 4
	}
	if containsSpecial(password) {
		score += countSpecial(password) * 6
	}

	if len(password) >= 8 {
		score += 25
	}
	if len(password) >= 12 {
		score += 25
	}
	if len(password) >= 16 {
		score += 25
	}

	hasUpper := containsUppercase(password)
	hasLower := containsLowercase(password)
	hasNum := containsNumbers(password)
	hasSpecial := containsSpecial(password)
	if hasUpper && hasLower && hasNum && hasSpecial {
		score += 50
	}

	if score < 20 {
		score = 0
	} else if score < 40 {
		score = 1
	} else if score < 60 {
		score = 2
	} else if score < 80 {
		score = 3
	} else {
		score = 4
	}

	return score
}

func countUpper(s string) int {
	count := 0
	for _, r := range s {
		if unicode.IsUpper(r) {
			count++
		}
	}
	return count
}

func countLower(s string) int {
	count := 0
	for _, r := range s {
		if unicode.IsLower(r) {
			count++
		}
	}
	return count
}

func countNumbers(s string) int {
	count := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			count++
		}
	}
	return count
}

func countSpecial(s string) int {
	count := 0
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			count++
		}
	}
	return count
}

func IsWeakPassword(password string) bool {
	result := CheckPassword(password, 8, "")
	return result.IsWeak
}
