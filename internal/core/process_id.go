package core

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
)

// ParseProcessIDNumber preserves exact integral JSON forms without float rounding.
// Bound the lexical work before parsing; a process ID needs at most 31 value bits.
func ParseProcessIDNumber(number json.Number) (string, bool) {
	text := string(number)
	if len(text) > 128 || !json.Valid([]byte(text)) {
		return "", false
	}
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		exponent, err := strconv.ParseInt(text[i+1:], 10, 32)
		if err != nil || exponent < -256 || exponent > 256 {
			return "", false
		}
	}
	n, ok := new(big.Rat).SetString(text)
	if !ok || !n.IsInt() || !n.Num().IsInt64() {
		return "", false
	}
	pid := n.Num().Int64()
	if pid <= 0 || pid > 1<<31-1 {
		return "", false
	}
	return strconv.FormatInt(pid, 10), true
}
