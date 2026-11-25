package e2e_test

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestKubernetes(t *testing.T) {
	piperhost := "host-k8s-proxy"
	piperport := "2222"
	piperaddr := piperhost + ":" + piperport
	waitForEndpointReadyWithTimeout(piperaddr, time.Minute*5)

	pubkeycases := []struct {
		title string
		user  string
	}{
		{
			title: "key_pubkey_cacthall",
			user:  "anyuser",
		},
		{
			title: "key_custom_field",
			user:  "custom_field",
		},
		{
			title: "key_authorizedfile",
			user:  "authorizedfile",
		},
		{
			title: "key_public_ca",
			user:  "hostcapublickey",
		},
		{
			title: "key_to_pass",
			user:  "keytopass",
		},
	}

	for _, testcase := range pubkeycases {
		t.Run(testcase.title, func(t *testing.T) {
			keyfiledir, err := os.MkdirTemp("", "")
			if err != nil {
				t.Errorf("failed to create temp key file: %v", err)
			}

			keyfile := path.Join(keyfiledir, "key")

			if err := os.WriteFile(keyfile, []byte(testprivatekey), 0o400); err != nil {
				t.Errorf("failed to write to test key: %v", err)
			}

			if err := os.WriteFile(authorizedKeysPath, []byte(testpublickey+"\n"), 0o400); err != nil {
				t.Errorf("failed to write to authorized_keys: %v", err)
			}

			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			c, _, _, err := runCmd(
				"ssh",
				"-v",
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-p",
				piperport,
				"-l",
				testcase.user,
				"-i",
				keyfile,
				piperhost,
				fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			)
			if err != nil {
				t.Errorf("failed to ssh to piper-fixed, %v", err)
			}

			defer killCmd(c)

			time.Sleep(time.Second) // wait for file flush

			checkSharedFileContent(t, targetfie, randtext)
		})
	}

	passwordcases := []struct {
		title    string
		user     string
		password string
	}{
		{
			title:    "password",
			user:     "pass",
			password: "pass",
		},
		{
			title:    "password_htpwd",
			user:     "htpwd",
			password: "htpassword",
		},
		{
			title:    "password_htpasswd_file",
			user:     "htpwdfile",
			password: "htpasswordfile",
		},
	}

	for _, testcase := range passwordcases {
		t.Run(testcase.title, func(t *testing.T) {
			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			c, stdin, stdout, err := runCmd(
				"ssh",
				"-v",
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-p",
				piperport,
				"-l",
				testcase.user,
				piperhost,
				fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			)
			if err != nil {
				t.Errorf("failed to ssh to piper-fixed, %v", err)
			}

			defer killCmd(c)

			enterPassword(stdin, stdout, testcase.password)

			time.Sleep(time.Second) // wait for file flush

			checkSharedFileContent(t, targetfie, randtext)
		})
	}

	{
		// fallback to password
		t.Run("fallback to password", func(t *testing.T) {
			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			keyfiledir, err := os.MkdirTemp("", "")
			if err != nil {
				t.Errorf("failed to create temp key file: %v", err)
			}

			keyfile := path.Join(keyfiledir, "key")

			if err := runCmdAndWait(
				"ssh-keygen",
				"-N",
				"",
				"-f",
				keyfile,
			); err != nil {
				t.Errorf("failed to generate key: %v", err)
			}

			c, stdin, stdout, err := runCmd(
				"ssh",
				"-v",
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-p",
				piperport,
				"-l",
				"pass",
				"-i",
				keyfile,
				piperhost,
				fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			)
			if err != nil {
				t.Errorf("failed to ssh to piper-fixed, %v", err)
			}

			defer killCmd(c)

			enterPassword(stdin, stdout, "pass")

			time.Sleep(time.Second) // wait for file flush

			checkSharedFileContent(t, targetfie, randtext)
		})
	}

	t.Run("kubectl_exec", func(t *testing.T) {
		keyfiledir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("failed to create temp key file: %v", err)
		}

		keyfile := path.Join(keyfiledir, "key")
		if err := os.WriteFile(keyfile, []byte(testprivatekey), 0o400); err != nil {
			t.Errorf("failed to write to test key: %v", err)
		}

		randtext := uuid.New().String()
		var output []byte

		for i := 0; i < 10; i++ {
			c, stdin, stdout, runErr := runCmd(
				"ssh",
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-p",
				piperport,
				"-l",
				"kubectlexec",
				"-i",
				keyfile,
				piperhost,
			)
			if runErr != nil {
				err = runErr
				time.Sleep(time.Second)
				continue
			}

			if _, runErr = fmt.Fprintf(stdin, "echo -n %q\nexit\n", randtext); runErr != nil {
				err = runErr
				killCmd(c)
				time.Sleep(time.Second)
				continue
			}

			err = c.Wait()
			if err == nil {
				var readErr error
				output, readErr = io.ReadAll(stdout)
				if readErr != nil {
					err = fmt.Errorf("failed to read kubectl_exec stdout after ssh completed: %w", readErr)
				}
				break
			}

			time.Sleep(time.Second)
		}

		if err != nil {
			t.Fatalf("failed to ssh to kubectl exec pipe, %v", err)
		}

		if !strings.Contains(string(output), randtext) {
			t.Fatalf("unexpected kubectl exec output: %q (expected to contain %q)", string(output), randtext)
		}
	})
}

// sshLoginDenied runs ssh against the proxy, answers any password prompt with an arbitrary
// password, and reports whether the login was refused without running the remote command.
func sshLoginDenied(t *testing.T, host, port, user string, extra ...string) {
	t.Helper()

	targetfile := uuid.New().String()
	args := []string{
		"-v",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "NumberOfPasswordPrompts=1",
		"-p", port,
		"-l", user,
	}
	args = append(args, extra...)
	args = append(args, host, fmt.Sprintf(`sh -c "echo -n pwned > /shared/%v"`, targetfile))

	c, stdin, stdout, err := runCmd("ssh", args...)
	if err != nil {
		t.Fatalf("failed to start ssh: %v", err)
	}
	defer killCmd(c)

	done := make(chan error, 1)
	go func() { done <- c.Wait() }()

	buf := stdout.(*syncBuffer)
	answered := false
	deadline := time.After(time.Minute)
	for {
		select {
		case waitErr := <-done:
			out := string(buf.Bytes())
			if waitErr == nil {
				t.Fatalf("ssh as %q succeeded; expected the login to be denied\n%s", user, out)
			}
			if !strings.Contains(out, "Permission denied") {
				t.Fatalf("ssh as %q failed without an auth denial: %v\n%s", user, waitErr, out)
			}
			if _, statErr := os.Stat(path.Join("/shared", targetfile)); statErr == nil {
				t.Fatalf("remote command ran for %q", user)
			}
			return
		case <-deadline:
			t.Fatalf("ssh as %q did not finish\n%s", user, string(buf.Bytes()))
		case <-time.After(200 * time.Millisecond):
			if !answered && strings.Contains(string(buf.Bytes()), "'s password") {
				_, _ = fmt.Fprintf(stdin, "any-password\n")
				answered = true
			}
		}
	}
}

// TestKubernetesKeylessPipeDenied: through the plugin's default settings, a Pipe whose `from`
// entry has no keys refuses an arbitrary key and a password (saturn-architecture-docs#118).
func TestKubernetesKeylessPipeDenied(t *testing.T) {
	piperhost := "host-k8s-proxy"
	strictport := "2223"
	waitForEndpointReadyWithTimeout(piperhost+":"+strictport, time.Minute*5)

	keyfiledir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("failed to create temp key dir: %v", err)
	}
	// A key other Pipes do accept, so the denial is about this Pipe and not an unknown key.
	knownkey := path.Join(keyfiledir, "known")
	if err := os.WriteFile(knownkey, []byte(testprivatekey), 0o400); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}
	randomkey := path.Join(keyfiledir, "random")
	if err := runCmdAndWait("ssh-keygen", "-N", "", "-f", randomkey); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("arbitrary_key", func(t *testing.T) {
		sshLoginDenied(t, piperhost, strictport, "atlaskeyless",
			"-o", "PreferredAuthentications=publickey", "-i", randomkey)
	})
	t.Run("key_accepted_by_other_pipes", func(t *testing.T) {
		sshLoginDenied(t, piperhost, strictport, "atlaskeyless",
			"-o", "PreferredAuthentications=publickey", "-i", knownkey)
	})
	t.Run("password", func(t *testing.T) {
		sshLoginDenied(t, piperhost, strictport, "atlaskeyless",
			"-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no")
	})
	t.Run("any_method", func(t *testing.T) {
		sshLoginDenied(t, piperhost, strictport, "atlaskeyless", "-i", randomkey)
	})
	t.Run("control_password_allowed_lets_anyone_in", func(t *testing.T) {
		// The same Pipe through the proxy that allows password auth (the upstream default):
		// any password gets a shell. This is the hole the default closes.
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		c, stdin, stdout, err := runCmd(
			"ssh", "-v",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "PreferredAuthentications=password",
			"-p", "2222",
			"-l", "atlaskeyless",
			piperhost,
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
		)
		if err != nil {
			t.Fatalf("failed to start ssh: %v", err)
		}
		defer killCmd(c)
		enterPassword(stdin, stdout, "any-password")
		time.Sleep(time.Second) // wait for file flush
		checkSharedFileContent(t, targetfile, randtext)
	})
	t.Run("check_keyed_pipe_still_works_through_strict", func(t *testing.T) {
		// Independent check (#118): with password auth off, a Pipe with keys still lets its
		// key in end to end (the Atlas shape: inline authorized_keys_data, private key upstream).
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		c, _, _, err := runCmd(
			"ssh", "-v",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "BatchMode=yes",
			"-p", strictport,
			"-l", "anyuser",
			"-i", knownkey,
			piperhost,
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
		)
		if err != nil {
			t.Fatalf("failed to start ssh: %v", err)
		}
		defer killCmd(c)
		time.Sleep(2 * time.Second) // wait for file flush
		checkSharedFileContent(t, targetfile, randtext)
	})
	t.Run("password_passthrough_pipe", func(t *testing.T) {
		// pipe-password has no keys and forwards the password upstream; with password auth
		// off it is denied too.
		sshLoginDenied(t, piperhost, strictport, "pass",
			"-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no")
	})
}
