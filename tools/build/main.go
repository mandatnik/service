// Cross-platform implementation of Makefile targets. No external Go libraries.
package main

import (
	"archive/zip"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"mandatnik/internal/version"
)

type options struct{ out, productVersion, commit, date, host, sshArgs, wix, productCode, config, evidence string }

func main() {
	if err := mainCommand(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "make:", err)
		os.Exit(1)
	}
}
func mainCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("use make help")
	}
	o := options{}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.StringVar(&o.out, "out", "artifacts/ci", "output directory")
	fs.StringVar(&o.productVersion, "version", "", "numeric MSI version")
	fs.StringVar(&o.commit, "commit", "", "build revision")
	fs.StringVar(&o.date, "date", "", "UTC build date")
	fs.StringVar(&o.host, "host", "", "optional Windows SSH builder")
	fs.StringVar(&o.sshArgs, "ssh-args", "", "additional SSH args, separated by spaces; no shell expansion")
	fs.StringVar(&o.wix, "wix", "", "WiX 3.14 directory on Windows")
	fs.StringVar(&o.productCode, "product-code", "", "MSI ProductCode override")
	fs.StringVar(&o.config, "config", "", "authorized acceptance JSON")
	fs.StringVar(&o.evidence, "evidence", "evidence/local/ci", "E2E evidence directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "publish":
		return publish(o)
	case "help":
		fmt.Print(`make deps          Download/verify Go modules and npm lockfile dependencies.
make test-unit     Unit tests on the current OS; no infrastructure required.
make lint          go vet.
make check         Unit tests and go vet.
make build         Rebuild Vue and build Windows amd64 EXE files + SHA256SUMS.
make binaries      Build EXE with the existing embedded UI (no Node needed).
make msi           Package the existing EXE with WiX on Windows.
make package       Build UI, EXE and MSI; refresh SHA256SUMS.
make integration E2E_CONFIG=...  SQL integration tests on the authorized stand.
make test-e2e E2E_CONFIG=...     SQL tests + HTTPS signed-protocol acceptance.
make publish       Publish a vX.Y.Z Gitea release from built artifacts.
make clean         Delete only the selected generated output directory.

Linux MSI: make package MSI_HOST=builder@windows (SSH keys required).
See CONTRIBUTING.md for Linux/Windows packages, configuration and CI/CD.
`)
		return nil
	case "deps":
		if err := run(nil, "go", "mod", "download"); err != nil {
			return err
		}
		if err := run(nil, "go", "mod", "verify"); err != nil {
			return err
		}
		return npm("ci")
	case "unit":
		return run(map[string]string{"MANDATNIK_POLICY_TEST_CONFIG": ""}, "go", "test", "-count=1", "./...")
	case "lint":
		return run(nil, "go", "vet", "./...")
	case "frontend":
		if err := npm("ci"); err != nil {
			return err
		}
		return npm("run", "build")
	case "build":
		return build(o)
	case "msi":
		return msi(o)
	case "integration", "e2e":
		if err := validateConfig(o.config); err != nil {
			return err
		}
		if err := run(map[string]string{"MANDATNIK_POLICY_TEST_CONFIG": absolute(o.config)}, "go", "test", "-count=1", "./internal/backend/store", "-run", "Test(Policies|Tasks)SQLServer", "-v"); err != nil {
			return err
		}
		if args[0] == "integration" {
			return nil
		}
		return endToEnd(o)
	case "clean":
		return clean(o.out)
	default:
		return fmt.Errorf("unknown target %q", args[0])
	}
}
func absolute(path string) string {
	v, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return v
}
func run(env map[string]string, name string, args ...string) error {
	fmt.Printf("+ %s %s\n", name, strings.Join(args, " "))
	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s is missing; see CONTRIBUTING.md: %w", name, err)
	}
	command := exec.Command(path, args...)
	if runtime.GOOS == "windows" && (strings.HasSuffix(strings.ToLower(path), ".cmd") || strings.HasSuffix(strings.ToLower(path), ".bat")) {
		command = exec.Command("cmd.exe", append([]string{"/d", "/c", path}, args...)...)
	}
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin
	command.Env = append([]string{}, os.Environ()...)
	for key, value := range env {
		prefix := strings.ToUpper(key) + "="
		kept := command.Env[:0]
		for _, item := range command.Env {
			if !strings.HasPrefix(strings.ToUpper(item), prefix) {
				kept = append(kept, item)
			}
		}
		command.Env = append(kept, key+"="+value)
	}
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}
func npm(args ...string) error {
	args = append([]string{"--prefix", "frontend"}, args...)
	// Use Node directly on Windows: npm.cmd under Program Files would otherwise
	// need a second round of cmd.exe quoting.
	if runtime.GOOS == "windows" {
		if command, err := exec.LookPath("npm"); err == nil {
			cli := filepath.Join(filepath.Dir(command), "node_modules", "npm", "bin", "npm-cli.js")
			if _, err := os.Stat(cli); err == nil {
				return run(nil, "node", append([]string{cli}, args...)...)
			}
		}
	}
	return run(nil, "npm", args...)
}
func normalized(o options) (options, error) {
	if o.productVersion == "" {
		o.productVersion = version.Version
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(o.productVersion) {
		return o, fmt.Errorf("VERSION must be numeric x.y.z")
	}
	if o.productVersion != version.Version {
		return o, fmt.Errorf("VERSION must match internal/version.Version (%s)", version.Version)
	}
	if o.commit == "" {
		if data, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output(); err == nil {
			o.commit = strings.TrimSpace(string(data))
		} else {
			o.commit = "unknown"
		}
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(o.commit) {
		return o, fmt.Errorf("invalid COMMIT")
	}
	if o.date == "" {
		if data, err := exec.Command("git", "show", "-s", "--format=%cI", "HEAD").Output(); err == nil {
			if date, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data))); err == nil {
				o.date = date.UTC().Format(time.RFC3339)
			}
		}
		if o.date == "" {
			o.date = time.Now().UTC().Format(time.RFC3339)
		}
	}
	if _, err := time.Parse(time.RFC3339, o.date); err != nil {
		return o, fmt.Errorf("BUILD_DATE must be RFC3339: %w", err)
	}
	return o, nil
}
func build(o options) error {
	var err error
	o, err = normalized(o)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(o.out, 0755); err != nil {
		return err
	}
	if err = run(nil, "go", "mod", "verify"); err != nil {
		return err
	}
	flags := fmt.Sprintf("-s -w -X mandatnik/internal/version.Commit=%s -X mandatnik/internal/version.BuildDate=%s", o.commit, o.date)
	for _, target := range []string{"agent", "backend", "acceptance"} {
		if err = run(map[string]string{"GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0"}, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", filepath.Join(o.out, "mandatnik-"+target+".exe"), "./cmd/"+target); err != nil {
			return err
		}
	}
	metadata := map[string]string{"version": o.productVersion, "commit": o.commit, "build_date": o.date, "go": runtime.Version(), "target": "windows/amd64"}
	data, _ := json.MarshalIndent(metadata, "", "  ")
	if err = os.WriteFile(filepath.Join(o.out, "build-info.json"), append(data, '\n'), 0644); err != nil {
		return err
	}
	return checksums(o.out)
}
func checksums(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	names := []string{}
	for _, entry := range entries {
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if !entry.IsDir() && (ext == ".exe" || ext == ".msi" || entry.Name() == "build-info.json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	var data strings.Builder
	for _, name := range names {
		file, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		file.Close()
		if err != nil {
			return err
		}
		fmt.Fprintf(&data, "%x  %s\n", hash.Sum(nil), name)
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(data.String()), 0644)
}
func validateConfig(path string) error {
	if path == "" {
		return fmt.Errorf("E2E_CONFIG is required; end-to-end tests write temporary data on the authorized stand, see CONTRIBUTING.md")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var v struct {
		ServerURL string `json:"server_url"`
		DB        struct {
			Database string `json:"database"`
		} `json:"db"`
	}
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	if !strings.HasPrefix(v.ServerURL, "https://") || v.DB.Database == "" {
		return fmt.Errorf("E2E_CONFIG must contain HTTPS server_url and an application database")
	}
	return nil
}
func clean(path string) error {
	clean := absolute(path)
	root := absolute(".")
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || !(strings.HasPrefix(filepath.ToSlash(rel), "artifacts/") || strings.HasPrefix(filepath.ToSlash(rel), "build/")) {
		return fmt.Errorf("clean only accepts a child of artifacts/ or build/ inside this repository")
	}
	return os.RemoveAll(clean)
}
func productCode(v string) string {
	if v == "0.4.0" {
		return "{35F44613-8F88-4599-8D86-C901BB368F47}"
	}
	namespace, _ := hex.DecodeString("b1ddabdf21514a9d9e0c6bc30e9e9bdb")
	h := sha1.New()
	h.Write(namespace)
	h.Write([]byte("MandatnikAgent/" + v))
	id := h.Sum(nil)[:16]
	id[6] = id[6]&0x0f | 0x50
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("{%x-%x-%x-%x-%x}", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}
func msi(o options) error {
	var err error
	o, err = normalized(o)
	if err != nil {
		return err
	}
	exe := filepath.Join(o.out, "mandatnik-agent.exe")
	if _, err = os.Stat(exe); err != nil {
		return fmt.Errorf("agent EXE not found; run make build first: %w", err)
	}
	if o.productCode == "" {
		o.productCode = productCode(o.productVersion)
	}
	if !regexp.MustCompile(`^\{[0-9A-Fa-f-]{36}\}$`).MatchString(o.productCode) {
		return fmt.Errorf("invalid PRODUCT_CODE")
	}
	output := filepath.Join(o.out, "MandatnikAgent-"+o.productVersion+".msi")
	if runtime.GOOS == "windows" && o.host == "" {
		args := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "deploy/msi/build-msi.ps1", "-AgentExe", absolute(exe), "-ProductVersion", o.productVersion, "-ProductCode", o.productCode, "-Output", absolute(output)}
		if o.wix != "" {
			args = append(args, "-WixDir", o.wix)
		}
		if err = run(nil, "powershell.exe", args...); err != nil {
			return err
		}
	} else {
		if o.host == "" {
			return fmt.Errorf("MSI needs Windows/WiX: on Linux set MSI_HOST=builder@windows, see CONTRIBUTING.md")
		}
		if err = remoteMSI(o, exe, output); err != nil {
			return err
		}
	}
	return checksums(o.out)
}
func psQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func encodedPS(script string) string {
	words := utf16.Encode([]rune(script))
	data := make([]byte, len(words)*2)
	for i, w := range words {
		data[2*i] = byte(w)
		data[2*i+1] = byte(w >> 8)
	}
	return base64.StdEncoding.EncodeToString(data)
}
func remoteMSI(o options, exe, output string) (err error) {
	if strings.HasPrefix(o.host, "-") || strings.ContainsAny(o.host, " \t\r\n'\"") {
		return fmt.Errorf("invalid MSI_HOST")
	}
	tmp, err := os.MkdirTemp("", "mandatnik-msi-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	bundle := filepath.Join(tmp, "input.zip")
	file, err := os.Create(bundle)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(file)
	paths := map[string]string{"mandatnik-agent.exe": exe, "build-msi.ps1": "deploy/msi/build-msi.ps1", "MandatnikAgent.wxs": "deploy/msi/MandatnikAgent.wxs", "agent-config.example.json": "deploy/msi/agent-config.example.json"}
	for name, path := range paths {
		entry, e := zw.Create(name)
		if e != nil {
			return e
		}
		source, e := os.Open(path)
		if e != nil {
			return e
		}
		_, e = io.Copy(entry, source)
		source.Close()
		if e != nil {
			return e
		}
	}
	if err = zw.Close(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	id := filepath.Base(tmp)
	remote := "C:/Windows/Temp/" + id
	sshArgs := strings.Fields(o.sshArgs)
	ps := func(script string) error {
		return run(nil, "ssh", append(append([]string{}, sshArgs...), o.host, "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "+encodedPS("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+script))...)
	}
	if err = ps("New-Item -ItemType Directory -Force " + psQuote(remote) + " | Out-Null"); err != nil {
		return err
	}
	defer func() {
		cleanupErr := ps("Remove-Item -LiteralPath " + psQuote(remote) + " -Recurse -Force")
		if err == nil {
			err = cleanupErr
		}
	}()
	// scp accepts the same -o/-P options; document these as the portable subset.
	if err = run(nil, "scp", append(append([]string{}, sshArgs...), bundle, o.host+":"+remote+"/input.zip")...); err != nil {
		return err
	}
	command := "Expand-Archive -LiteralPath " + psQuote(remote+"/input.zip") + " -DestinationPath " + psQuote(remote) + " -Force; & " + psQuote(remote+"/build-msi.ps1") + " -AgentExe " + psQuote(remote+"/mandatnik-agent.exe") + " -ProductVersion " + psQuote(o.productVersion) + " -ProductCode " + psQuote(o.productCode) + " -Output " + psQuote(remote+"/output.msi")
	if o.wix != "" {
		command += " -WixDir " + psQuote(o.wix)
	}
	if err = ps(command); err != nil {
		return err
	}
	return run(nil, "scp", append(append([]string{}, sshArgs...), o.host+":"+remote+"/output.msi", output)...)
}
