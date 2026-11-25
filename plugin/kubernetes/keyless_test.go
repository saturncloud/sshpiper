package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	piperlister "github.com/tg123/sshpiper/plugin/kubernetes/generated/listers/sshpiper/v1beta1"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// The Pipe Atlas writes (pdc/templates/kube/proxy/ssh.yaml): one `from` entry with inline
// authorized keys, an upstream private key in a Secret. With no keys, Atlas rendered
// `authorized_keys_data:` as null and the field was dropped, leaving a keyless entry.
func atlasPipe(name, username, authorizedKeysData string) *piperv1beta1.Pipe {
	return &piperv1beta1.Pipe{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ingress"},
		Spec: piperv1beta1.PipeSpec{
			From: []piperv1beta1.FromSpec{{
				Username:           username,
				AuthorizedKeysData: authorizedKeysData,
			}},
			To: piperv1beta1.ToSpec{
				Username:         "jovyan",
				Host:             name + ".main-namespace",
				PrivateKeySecret: corev1.LocalObjectReference{Name: name},
			},
		},
	}
}

func newTestPlugin(t *testing.T, allowPasswordAuth bool, pipes ...*piperv1beta1.Pipe) *plugin {
	t.Helper()
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	var secrets []runtime.Object
	for _, p := range pipes {
		if err := store.Add(p); err != nil {
			t.Fatalf("add pipe: %v", err)
		}
		secrets = append(secrets, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: p.Spec.To.PrivateKeySecret.Name, Namespace: p.Namespace},
			Data:       map[string][]byte{"privatekey": []byte("upstream-private-key")},
		})
	}
	return &plugin{
		k8sclient:         fake.NewClientset(secrets...).CoreV1(),
		lister:            piperlister.NewPipeLister(store),
		allowPasswordAuth: allowPasswordAuth,

		kubeExecPipeToKey:   make(map[string]string),
		kubeExecPrivateKeys: make(map[string]string),
		kubeExecTargets:     make(map[string]kubectlExecTarget),
	}
}

func newClientKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("convert key: %v", err)
	}
	return sshPub
}

func authorizedKeysData(keys ...ssh.PublicKey) string {
	var data []byte
	for _, k := range keys {
		data = append(data, ssh.MarshalAuthorizedKey(k)...)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// TestKeylessPipeDeniesArbitraryPublicKey: an arbitrary client key gets no upstream on a
// Pipe whose `from` entry has no keys.
func TestKeylessPipeDeniesArbitraryPublicKey(t *testing.T) {
	for _, allowPassword := range []bool{false, true} {
		p := newTestPlugin(t, allowPassword, atlasPipe("ssh-victim", "victim", ""))
		config := p.createConfig()

		upstream, err := config.PublicKeyCallback(fakeConn{user: "victim"}, newClientKey(t).Marshal())
		if err == nil || upstream != nil {
			t.Fatalf("allowPassword=%v: keyless pipe accepted an arbitrary key (upstream %v)", allowPassword, upstream)
		}
	}
}

// TestKeylessPipeDeniesPassword: password auth is not registered at all by default, so
// sshpiperd neither offers nor accepts it, for a keyless Pipe or any other.
func TestKeylessPipeDeniesPassword(t *testing.T) {
	p := newTestPlugin(t, false,
		atlasPipe("ssh-victim", "victim", ""),
		atlasPipe("ssh-keyed", "keyed", authorizedKeysData(newClientKey(t))),
	)
	config := p.createConfig()

	if config.PasswordCallback != nil {
		t.Fatal("password callback is registered; sshpiperd would accept password logins")
	}
	if config.KeyboardInteractiveCallback != nil || config.NoClientAuthCallback != nil {
		t.Fatal("keyboard-interactive or none auth is registered")
	}

	for _, user := range []string{"victim", "keyed"} {
		methods, err := config.NextAuthMethodsCallback(fakeConn{user: user})
		if err != nil {
			t.Fatalf("NextAuthMethods: %v", err)
		}
		if slices.Contains(methods, "password") || slices.Contains(methods, "keyboard-interactive") {
			t.Fatalf("user %q is offered %v", user, methods)
		}
	}

	// Even called directly, the skel password path finds no entry to verify against.
	skelConfig := skel.NewSkelPlugin(p.listPipe).CreateConfig()
	if _, err := skelConfig.PasswordCallback(fakeConn{user: "victim"}, []byte("anything")); err == nil {
		t.Fatal("keyless pipe accepted a password through the skel password path")
	}
}

// TestKeylessPipeAcceptsAnyPasswordUpstreamBehaviour pins why the default matters: with
// password auth allowed, upstream turns a keyless entry into "any password works".
func TestKeylessPipeAcceptsAnyPasswordUpstreamBehaviour(t *testing.T) {
	p := newTestPlugin(t, true, atlasPipe("ssh-victim", "victim", ""))
	upstream, err := p.createConfig().PasswordCallback(fakeConn{user: "victim"}, []byte("anything"))
	if err != nil || upstream == nil {
		t.Fatalf("expected the upstream behaviour (any password accepted) with the flag on, got %v", err)
	}
}

// TestKeyedPipeStillAcceptsItsKey: the fail-closed change keeps the normal path working, and
// still rejects a key that is not listed.
func TestKeyedPipeStillAcceptsItsKey(t *testing.T) {
	owner := newClientKey(t)
	p := newTestPlugin(t, false, atlasPipe("ssh-keyed", "keyed", authorizedKeysData(owner)))
	config := p.createConfig()

	upstream, err := config.PublicKeyCallback(fakeConn{user: "keyed"}, owner.Marshal())
	if err != nil {
		t.Fatalf("owner key rejected: %v", err)
	}
	if upstream.UserName != "jovyan" || upstream.GetPrivateKey() == nil {
		t.Fatalf("unexpected upstream: %v", upstream)
	}

	if _, err := config.PublicKeyCallback(fakeConn{user: "keyed"}, newClientKey(t).Marshal()); err == nil {
		t.Fatal("keyed pipe accepted a key it does not list")
	}
}

// TestKeylessFromIsSkippedNotPassword: the keyless entry produces no auth entry at all.
func TestKeylessFromIsSkippedNotPassword(t *testing.T) {
	pipe := atlasPipe("ssh-victim", "victim", "")
	w := &skelpipeWrapper{plugin: &plugin{}, pipe: pipe}
	if froms := w.From(); len(froms) != 0 {
		t.Fatalf("expected no from entries for a keyless pipe, got %d", len(froms))
	}

	var _ libplugin.ConnMetadata = fakeConn{}
}
