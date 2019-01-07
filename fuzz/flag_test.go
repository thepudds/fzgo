package fuzz

import (
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name           string
		args           string
		want           string
		wantPkgPattern string
		wantErr        bool
	}{
		{"flag with equal sign", "-fuzz=fuzzfunc", "fuzzfunc", ".", false},
		{"flag with double dash", "--fuzz fuzzfunc", "fuzzfunc", ".", false},
		{"flag without equal sign", "-fuzz fuzzfunc", "fuzzfunc", ".", false},
		{"flag with test. prefix", "-test.fuzz fuzzfunc", "fuzzfunc", ".", false},

		{"one package", "-fuzz=fuzzfunc sample/pkg", "fuzzfunc", "sample/pkg", false},
		{"two packages in a row", "-fuzz=fuzzfunc sample/pkg1 sample/pkg2", "", "", true},
		{"two packages separated by flag", "sample/pkg1 -fuzz=fuzzfunc sample/pkg2", "fuzzfunc", "", true},

		{"incompatible test flag", "-fuzz=fuzzfunc -benchtime=10s", "", "", true},
		{"incompatible build flag", "-fuzz=fuzzfunc -gccgoflags=foo", "", "", true},
		{"not yet implemented fuzzing arg", "-fuzz=fuzzfunc -coverprofile=foo", "", "", true},

		{"no -fuzz", "-fuzznot=fuzzfunc", "", "", false},
		{"empty args", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			flagDef := FlagDef{Name: "fuzz", Ptr: &got}
			usage := func(*flag.FlagSet) func() { return func() {} } // no-op usage function
			fs, _ := FlagSet("test fuzz.ParseArgs", []FlagDef{flagDef}, usage)

			args := strings.Fields(tt.args)
			gotPkgPattern, err := ParseArgs(args, fs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseArgs() = %v, want %v", got, tt.want)
			}
			if gotPkgPattern != tt.wantPkgPattern {
				t.Errorf("ParseArgs() = %v, wantPkgPattern %v", gotPkgPattern, tt.wantPkgPattern)
			}
		})
	}
}

func TestFindFlag(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		want   string
		wantOK bool
	}{
		{"match", []string{"-foo", "bar", "-fuzz=fuzzfunc"}, "fuzz", true},
		{"no value", []string{"-fuzz", "-foo", "bar"}, "fuzz", true},
		{"no value last", []string{"-foo", "bar", "-fuzz"}, "fuzz", true},
		{"no match", []string{"-foo", "bar", "-fuzznot=fuzzfunc"}, "", false},
		{"do not match --", []string{"--", "fuzz"}, "", false},
		{"do not match ---fuzz", []string{"---fuzz", "fuzzFunc"}, "", false},
		{"do not match non-flags", []string{"fuzz", "fuzzFunc"}, "", false},
		{"do not match after -args", []string{"-foo", "bar", "-args", "-fuzz=fuzzfunc"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := []string{"fuzz", "test.fuzz"}
			got, gotOK := FindFlag(tt.args, names)
			if got != tt.want {
				t.Errorf("FindFlag() got = %v, want %v", got, tt.want)
			}
			if gotOK != tt.wantOK {
				t.Errorf("FindFlag() got1 = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

func TestFindPkg(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []string
		wantErr bool
	}{
		{"no pkgs", []string{"-f", "-a=val", "-foo", "bar"}, []string{}, false},
		{"one pkg", []string{"-f", "val", "pkg", "-foo", "bar"}, []string{"pkg"}, false},
		{"two pkgs", []string{"-f", "val", "pkg1", "pkg2", "-foo", "bar"}, []string{"pkg1", "pkg2"}, false},
		{"pkg last", []string{"-a=val", "-foo", "bar", "pkg"}, []string{"pkg"}, false},
		{"pkg first", []string{"pkg", "-a=val", "-foo", "bar"}, []string{"pkg"}, false},
		{"known bool", []string{"-v", "pkg1", "pkg2", "-foo", "bar"}, []string{"pkg1", "pkg2"}, false},
		{"triple dot", []string{"-fuzz=Fuzz", "./...", "-foo"}, []string{"./..."}, false},
		{"stop at -args", []string{"-args", "notpkg1", "notpkg2"}, []string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := FindPkgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("findPkg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findPkg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isFlag(t *testing.T) {
	tests := []struct {
		name   string
		arg    string
		want   string
		wantOK bool
	}{
		{"single", "-flag", "flag", true},
		{"double", "--flag", "flag", true},
		{"value", "-flag=value", "flag=value", true},
		{"non-flag", "opt", "", false},
		{"only hyphens", "--", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotOK := candidateFlag(tt.arg)
			if got != tt.want {
				t.Errorf("isFlag() got = %v, want %v", got, tt.want)
			}
			if gotOK != tt.wantOK {
				t.Errorf("isFlag() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}
