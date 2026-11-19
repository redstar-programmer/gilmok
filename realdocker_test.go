package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// UPD-13 (real Docker, GM_REAL_DOCKER=1 only): an update whose new image does not start puts the
// previous image back and the container runs again.
func TestRealUpdateRollback(t *testing.T) {
	if os.Getenv("GM_REAL_DOCKER") != "1" {
		t.Skip("set GM_REAL_DOCKER=1 to run against the local Docker")
	}
	dockerRun = runDocker
	verifyPause = time.Second
	defer func() { verifyPause = 3 * time.Second }()
	sh := func(args ...string) string {
		out, _ := exec.Command("docker", args...).CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	dir := t.TempDir()
	const ctr = "gm-rb-caddy"
	t.Cleanup(func() {
		sh("compose", "--project-directory", dir, "-p", "gm-rb", "down", "--rmi", "local")
		sh("rm", "-f", ctr)
	})
	_ = os.WriteFile(filepath.Join(dir, "Caddyfile"), []byte(":8080 {\n\trespond \"ok\"\n}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM caddy:2\nCOPY Caddyfile /etc/caddy/Caddyfile\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("name: gm-rb\nservices:\n  caddy:\n    build: .\n    image: gm-rb-caddy:local\n    container_name: "+ctr+"\n"), 0o644)
	if out, err := exec.Command("docker", "compose", "--project-directory", dir, "-p", "gm-rb", "up", "-d", "--build").CombinedOutput(); err != nil {
		t.Fatalf("first up: %v %s", err, out)
	}
	time.Sleep(2 * time.Second)
	oldImg, _ := ctrImage(ctr)
	// the "new version" cannot start
	_ = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM caddy:2\nCOPY Caddyfile /etc/caddy/Caddyfile\nCMD [\"caddy\", \"run\", \"--config\", \"/nope\"]\n"), 0o644)

	f := newFullApp(t)
	dockerRun = runDocker // newFullApp installed a fake
	st := Settings{CaddyContainer: ctr, CaddyStackDir: dir, CaddyService: "caddy", CaddyfileInCtr: "/etc/caddy/Caddyfile"}
	f.set(func(d *Data) { d.Settings = st })
	L := &logger{}
	err := f.app.update("caddy", st, L)
	t.Log(strings.Join(L.lines, "\n"))
	if err == nil || !strings.Contains(err.Error(), "되돌렸습니다") {
		t.Fatalf("UPD-13: %v", err)
	}
	time.Sleep(2 * time.Second)
	nowImg, _ := ctrImage(ctr)
	state := sh("inspect", "-f", "{{.State.Status}}", ctr)
	if nowImg != oldImg || state != "running" {
		t.Fatalf("UPD-13: after rollback image=%s (old %s) state=%s", nowImg, oldImg, state)
	}
	if out, err := ctrExecCtx(context.Background(), ctr, "caddy", "version"); err != nil {
		t.Fatalf("UPD-13: caddy not answering after rollback: %s", out)
	}
}

func ctrExecCtx(ctx context.Context, ctr string, args ...string) (string, error) {
	return docker(ctx, nil, nil, append([]string{"exec", ctr}, args...)...)
}
