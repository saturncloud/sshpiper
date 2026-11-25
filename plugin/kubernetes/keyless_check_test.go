package main

import (
	"encoding/base64"
	"testing"

	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
)

// Independent check (#118): keys fields that are present but hold no usable key must deny,
// and a deliberate htpasswd entry is denied too while password auth is off.
func TestCheckPresentButEmptyKeysDeny(t *testing.T) {
	cases := map[string]string{
		"newline-only-b64": base64.StdEncoding.EncodeToString([]byte("\n")),
		"spaces-b64":       base64.StdEncoding.EncodeToString([]byte("   \n  ")),
		"garbage-raw":      "not-a-key",
		"comment-only":     base64.StdEncoding.EncodeToString([]byte("# nothing\n")),
	}
	for name, data := range cases {
		for _, allow := range []bool{false, true} {
			p := newTestPlugin(t, allow, atlasPipe("ssh-victim", "victim", data))
			cfg := p.createConfig()
			if u, err := cfg.PublicKeyCallback(fakeConn{user: "victim"}, newClientKey(t).Marshal()); err == nil || u != nil {
				t.Fatalf("%s allow=%v: accepted arbitrary key", name, allow)
			}
			if cfg.PasswordCallback != nil {
				if u, err := cfg.PasswordCallback(fakeConn{user: "victim"}, []byte("x")); err == nil || u != nil {
					t.Fatalf("%s allow=%v: accepted a password", name, allow)
				}
			}
		}
	}
}

func TestCheckHtpasswdEntryDeniedWhenPasswordOff(t *testing.T) {
	pipe := atlasPipe("ssh-pw", "pw", "")
	pipe.Spec.From[0].HtpasswdData = base64.StdEncoding.EncodeToString([]byte("pw:{PLAIN}secret\n"))
	p := newTestPlugin(t, false, pipe)
	if p.createConfig().PasswordCallback != nil {
		t.Fatal("password callback registered with flag off")
	}
	w := &skelpipeWrapper{plugin: p, pipe: pipe}
	if n := len(w.From()); n != 0 {
		t.Fatalf("htpasswd-only entry produced %d auth entries with password off", n)
	}
	_ = piperv1beta1.FromSpec{}
}
