package folderpolicy

import "testing"

func TestWindowsRules(t *testing.T) {
	p, err := Compile("# comment\nC:/Users/*/AppData/testDir/\n!C:/Users/*/AppData/testDir/trashFolder\nC:/ProgramData/\nC:/Сертификаты/**/Личные/\nC:/Certs/p?rt[12]/\n")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{`C:\Users\Иван\AppData\testDir\a.cer`: true, `c:/users/AGENT/appdata/testdir/nested/a.cer`: true, `C:/Users/a/AppData/testDir/trashFolder/a.cer`: false, `C:/Users/a/AppData/testDir/trashFolder2/a.cer`: true, `C:/Users/a/AppData/testDir2/a.cer`: false, `C:/ProgramData/a.cer`: true, `C:/Certs/part1/a.cer`: true, `C:/Certs/port2/a.cer`: true, `C:/Certs/part3/a.cer`: false, `C:/Сертификаты/Личные/a.cer`: true, `C:/Сертификаты/a/b/Личные/a.cer`: true}
	for file, want := range cases {
		if got := p.Includes(file); got != want {
			t.Errorf("%s = %v, want %v", file, got, want)
		}
	}
	if !p.Excludes("C:/Users/a/AppData/testDir/trashFolder/a.cer") {
		t.Fatal("exclusion not exposed")
	}
}
func TestLastMatchAndExclusionOnly(t *testing.T) {
	p, err := Compile("C:/certs/\n!C:/certs/old/\nC:/certs/old/keep/\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Includes("C:/certs/old/x.cer") || !p.Includes("C:/certs/old/keep/x.cer") {
		t.Fatal("last match")
	}
	p, err = Compile("!C:/certs/trash/")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roots) != 0 || !p.Excludes("C:/certs/trash/a.cer") || p.Includes("C:/certs/a.cer") {
		t.Fatal("exclude-only")
	}
}
func TestInvalidRules(t *testing.T) {
	for _, rules := range []string{"", "# only comment", "relative/path", "C:/a/../b", "C:/a/[abc", "C:/a/[]", "C:/a/\x00"} {
		if _, err := Compile(rules); err == nil {
			t.Errorf("accepted %q", rules)
		}
	}
}

func TestDirectoryPruningWithReinclusion(t *testing.T) {
	p, err := Compile("C:/Users/*/AppData/testDir/\n!C:/Users/*/AppData/testDir/trash\nC:/Users/*/AppData/testDir/trash/keep/")
	if err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]bool{"C:/Users": true, "C:/Users/Иван/Documents": false, "C:/Users/Иван/AppData/testDir/trash": true, "C:/Users/Иван/AppData/testDir/trash/other": false, "C:/Users/Иван/AppData/testDir/trash/keep": true} {
		if p.MayContain(dir) != want {
			t.Errorf("MayContain %s want %v", dir, want)
		}
	}
	p, _ = Compile("C:/Certs/\n!C:/Certs/trash/")
	if p.MayContain("C:/Certs/trash") {
		t.Fatal("excluded subtree would be read")
	}
	p, _ = Compile("C:/[!ab]*/certs/")
	if p.MayContain("C:/agent") || !p.MayContain("C:/user") {
		t.Fatal("negated class pruning")
	}
	p, _ = Compile("//server/share/certs/")
	if p.Roots[0] != "//server/share/certs" || !p.Includes(`\\server\share\certs\a.cer`) {
		t.Fatal("UNC root corrupted")
	}
}
