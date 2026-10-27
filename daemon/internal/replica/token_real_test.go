package replica

import (
	"strings"
	"testing"
)

// realToken is a resume token OpenZFS 2.2.2 (Ubuntu 24.04, CI's ZFS job)
// left after an interrupted incremental receive.
const realToken = "1-f44d11ce7-148-789c636064000310a501c49c50360710a715e5e7a69766a630408144d62c0187996c490a40363b92bafca4acd4e412060666a83a0cf9b4b4e2d41290cc2cb83c1b927c5265496a3190fe913107abfe927c882b5e4f7ed413f5f0a14904923c27583e2f3137958121a3a8b82859bf3823b128b5583f37352533d101c84ea9cc2fd62d4a2dc8d13530333730b548b43033d035323032333430320f3134323436368e82f80f6a1f2c3c5273935253f2b3c1eee146124fcecf2d005a510c94820300d8f734c5"

func TestDecodeRealToken(t *testing.T) {
	tk, err := DecodeToken(realToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tk.ToName, "hrsrc/shares/media@hardyos-repl-067058a860-") || tk.ToGUID == 0 || !tk.HasFrom || tk.FromGUID == 0 {
		t.Fatalf("%+v", tk)
	}
	t.Logf("%s keys %v", tk, tk.Keys)
}
