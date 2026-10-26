package injection

import (
	"strings"
	"testing"
)

func TestBoundedNormalizationPreservesEntityAndCommentSemantics(t *testing.T) {
	for input, want := range map[string]string{
		"&#0000060;": "<", "&#00000060;": "&#00000060;", "&#x00003C;": "<",
		"&#bad &#60;": "&#bad <", "&#👁👁👁&#60;": "&#👁👁👁<", "&#;": "\x00",
	} {
		if got := decodeHTMLEntities(input); got != want {
			t.Errorf("%q: got %q want %q", input, got, want)
		}
	}
	for input, want := range map[string]string{"SEL/**/ECT": "SELECT", "a/*done*/b/*unterminated": "ab/*unterminated", "/*a/*b": "/*a/*b", "正常/*x*/尾部": "正常尾部"} {
		if got := stripInlineComments(input); got != want {
			t.Errorf("%q: got %q want %q", input, got, want)
		}
	}
	entity, comment := strings.Repeat("&#", 32768), strings.Repeat("/*a", 21845)
	if got := decodeHTMLEntities(entity); got != entity {
		t.Fatal("unterminated entities changed")
	}
	if got := stripInlineComments(comment); got != comment {
		t.Fatal("unterminated comments changed")
	}
}

func BenchmarkUnterminatedNormalization(b *testing.B) {
	for _, n := range []int{1024, 16384, 65536} {
		b.Run("entities/"+sizeName(n), func(b *testing.B) {
			input := strings.Repeat("&#", n/2)
			b.SetBytes(int64(len(input)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decodeHTMLEntities(input)
			}
		})
		b.Run("comments/"+sizeName(n), func(b *testing.B) {
			input := strings.Repeat("/*a", n/3)
			b.SetBytes(int64(len(input)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stripInlineComments(input)
			}
		})
	}
}
func sizeName(n int) string {
	switch n {
	case 1024:
		return "1KiB"
	case 16384:
		return "16KiB"
	default:
		return "64KiB"
	}
}
