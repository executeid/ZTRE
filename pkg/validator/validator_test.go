package validator

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func testLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func writeTestWhitelist(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "whitelist.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWhitelist_Classify(t *testing.T) {
	dir := t.TempDir()
	p := writeTestWhitelist(t, dir, `
whitelisted_lineages:
  - parent: nginx
    allowed_children: [nginx, sh]
  - parent: postgres
    allowed_children: [postgres, pg_dump]
`)
	wl, err := NewWhitelist(p, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		parent, child string
		want          Classification
	}{
		{"nginx", "nginx", ClassNormal},
		{"nginx", "sh", ClassNormal},
		{"/usr/sbin/nginx", "/bin/sh", ClassNormal}, // filepath.Base normalization
		{"nginx", "bash", ClassAnomalous},            // parent known, child NOT allowed
		{"postgres", "bash", ClassAnomalous},
		{"postgres", "pg_dump", ClassNormal},
		{"unknown_binary", "ls", ClassSuspicious}, // parent NOT in whitelist
		{"curl", "curl", ClassSuspicious},
	}

	for _, tc := range tests {
		got := wl.Classify(tc.parent, tc.child)
		if got != tc.want {
			t.Errorf("Classify(%q, %q) = %s, want %s", tc.parent, tc.child, got, tc.want)
		}
	}
}

func TestWhitelist_MissingFile(t *testing.T) {
	wl, err := NewWhitelist("/nonexistent/whitelist.yaml", testLogger())
	if err != nil {
		t.Fatal("expected no error for missing file, got:", err)
	}
	// Everything is SUSPICIOUS with empty whitelist
	if got := wl.Classify("nginx", "bash"); got != ClassSuspicious {
		t.Errorf("expected SUSPICIOUS for empty whitelist, got %s", got)
	}
}

func TestWhitelist_Reload(t *testing.T) {
	dir := t.TempDir()
	p := writeTestWhitelist(t, dir, `
whitelisted_lineages:
  - parent: nginx
    allowed_children: [nginx]
`)
	wl, err := NewWhitelist(p, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	if got := wl.Classify("nginx", "sh"); got != ClassAnomalous {
		t.Fatalf("expected ANOMALOUS before reload, got %s", got)
	}

	// Update file and reload
	if err := os.WriteFile(p, []byte(`
whitelisted_lineages:
  - parent: nginx
    allowed_children: [nginx, sh]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := wl.Load(); err != nil {
		t.Fatal(err)
	}

	if got := wl.Classify("nginx", "sh"); got != ClassNormal {
		t.Errorf("expected NORMAL after reload, got %s", got)
	}
}

func TestWhitelist_LoadMulti(t *testing.T) {
	dir := t.TempDir()
	autoPath := writeTestWhitelist(t, dir, `
whitelisted_lineages:
  - parent: nginx
    allowed_children: [nginx]
`)
	manualPath := filepath.Join(dir, "manual.yaml")
	if err := os.WriteFile(manualPath, []byte(`
whitelisted_lineages:
  - parent: nginx
    allowed_children: [php-fpm]
  - parent: java
    allowed_children: [java]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	wl, err := NewWhitelist(autoPath, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := wl.LoadMulti(manualPath); err != nil {
		t.Fatal(err)
	}

	// nginx should have both auto and manual children
	if got := wl.Classify("nginx", "nginx"); got != ClassNormal {
		t.Errorf("expected NORMAL for auto child, got %s", got)
	}
	if got := wl.Classify("nginx", "php-fpm"); got != ClassNormal {
		t.Errorf("expected NORMAL for manual child, got %s", got)
	}
	// java from manual override
	if got := wl.Classify("java", "java"); got != ClassNormal {
		t.Errorf("expected NORMAL for java, got %s", got)
	}
}

func TestWhitelist_EmptyWhitelist_AllSuspicious(t *testing.T) {
	dir := t.TempDir()
	p := writeTestWhitelist(t, dir, `whitelisted_lineages: []`)
	wl, err := NewWhitelist(p, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got := wl.Classify("anything", "whatever"); got != ClassSuspicious {
		t.Errorf("expected SUSPICIOUS, got %s", got)
	}
}

func BenchmarkWhitelist_Classify(b *testing.B) {
	dir := b.TempDir()
	p := filepath.Join(dir, "wl.yaml")
	content := `
whitelisted_lineages:
  - parent: nginx
    allowed_children: [nginx, sh, php-fpm, node]
  - parent: postgres
    allowed_children: [postgres, pg_dump]
  - parent: java
    allowed_children: [java]
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		b.Fatal(err)
	}
	wl, _ := NewWhitelist(p, zap.NewNop())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wl.Classify("nginx", "bash")
	}
}
