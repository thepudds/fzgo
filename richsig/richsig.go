package main

import (
	"bytes"
	"fmt"
	"go/build"
	"go/types"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
)

// WORKS!
// this uses all basic types:
//   go run richsig.go ./examples FuzzRegexp
// this uses goimports right now to set up imports:
//   go run richsig.go ./examples FuzzAcutalRegexp

// does not yet work (has slash in type name. probably need to do Qualifier):
//   go run richsig.go ./examples FuzzFzgoFunc

// TODO: list
//   - corpus goes to wrong spot. pass arg?

const buildTagsArg = "-tags=gofuzz fuzz"

// Func represents a function that will be fuzzed.
type Func struct {
	FuncName string
	PkgName  string // package name (should be the same as the package's package statement)
	PkgPath  string // import path
	PkgDir   string // local on-disk directory

	Types Types
}

// Types is auxillary information about a Func from the types package
type Types struct {
	f *types.Func
}

func (f Func) String() string {
	return fmt.Sprintf("%v.%v", f.PkgName, f.FuncName)
}

// ### WORKS!!!
//      https://play.golang.org/p/pJUffEt5B0q
//      https://play.golang.org/p/9DpCfJbbxvS (example with empty regexp)

// TODO: temp
func main() {
	// result, err := VistFunc(os.Stdout, createWrapper, os.Args[1], os.Args[2], true)
	// fmt.Printf("%#v err: %v\n", result, err)
	functions, err := FindFunc(os.Args[1], os.Args[2], true)
	for _, function := range functions {
		createWrapper(os.Stdout, function)
		FuzzWrapperFunc(function)
	}
	if err != nil {
		fmt.Printf("fatal error: %v", err)
	}
}

// IsPlainSig reports whether a signature is a classic, plain 'func([]bytes) int'
// go-fuzz signature.
func IsPlainSig(sig *types.Signature) bool {
	results := sig.Results()
	params := sig.Params()
	if params.Len() != 1 || results.Len() != 1 {
		return false
	}
	if types.TypeString(params.At(0).Type(), nil) != "[]byte" {
		return false
	}
	if types.TypeString(results.At(0).Type(), nil) != "int" {
		return false
	}
	return true
}

// FuzzWrapperFunc creates a temp working directory, then
// creates a rich signature wrapping fuzz function.
func FuzzWrapperFunc(function Func) error {
	// create temp dir to work in
	tempDir, err := ioutil.TempDir("", "fzgo-fuzz-rich-signature")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wrapperDir := filepath.Join(tempDir, "gopath", "src", "richsigwrapper")
	if err := os.MkdirAll(wrapperDir, 0700); err != nil {
		return fmt.Errorf("failed to create gopath/src in temp dir: %v", err)
	}

	origGp := os.Getenv("GOPATH")
	if origGp == "" {
		origGp = build.Default.GOPATH
	}
	gp := strings.Join([]string{origGp, filepath.Join(tempDir, "gopath")},
		string(os.PathListSeparator))

	// cd to our temp dir to simplify invoking 'go test'
	oldWd, err := os.Getwd()
	if err != nil {
		return err
	}
	err = os.Chdir(wrapperDir)
	if err != nil {
		return err
	}
	defer func() { os.Chdir(oldWd) }()

	// write out temporary richsigwrapper.go file
	var b bytes.Buffer
	createWrapper(&b, function)
	err = ioutil.WriteFile(filepath.Join(wrapperDir, "richsigwrapper.go"), b.Bytes(), 0700)
	if err != nil {
		return fmt.Errorf("failed to create temporary richsigwrapper.go: %v", err)
	}

	// TODO: duration?

	// If Env contains duplicate environment keys for GOPATH, only the last
	// value in the slice for each duplicate key is used.
	env := append(os.Environ(), "GOPATH="+gp)

	// TODO: stop invoking goimports? maybe this is a hack, or maybe this is a convient way to get what we want for now...
	if _, err := exec.LookPath("goimports"); err == nil {
		err = execCmd("goimports", []string{"-w", "richsigwrapper.go"}, env, 0)
		if err != nil {
			return fmt.Errorf("failed invoking goimports for rich signature: %v", err)
		}
	}
	err = execCmd("fzgo", []string{"test", "-fuzz=FuzzRichSigWrapper", "-fuzztime=10s"}, env, 0)
	if err != nil {
		return fmt.Errorf("failed invoking fzgo for rich signature: %v", err)
	}
	return nil
}

// FindFunc searches for a requested function to visit.
func FindFunc(pkgPattern, funcPattern string, allowMultiFuzz bool) ([]Func, error) {
	report := func(err error) error {
		return fmt.Errorf("error while loading packages for pattern %v: %v", pkgPattern, err)
	}
	var result []Func

	// load packages based on our package pattern
	// build tags example: https://groups.google.com/d/msg/golang-tools/Adwr7jEyDmw/wQZ5qi8ZGAAJ
	cfg := &packages.Config{
		Mode:       packages.LoadSyntax,
		BuildFlags: []string{buildTagsArg},
	}
	pkgs, err := packages.Load(cfg, pkgPattern)
	if err != nil {
		return nil, report(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("package load error for package pattern %v", pkgPattern)
	}

	// look for a func that starts with 'Fuzz' and matches our regexp.
	// loop over the packages we found and loop over the Defs for each package.
	for _, pkg := range pkgs {
		for id, obj := range pkg.TypesInfo.Defs {
			// check if we have a func
			f, ok := obj.(*types.Func)
			if ok {

				// check if it starts with "Fuzz" and matches our fuzz function regular expression
				if !strings.HasPrefix(id.Name, "Fuzz") {
					continue
				}

				matchedPattern, err := regexp.MatchString(funcPattern, id.Name)
				if err != nil {
					return nil, report(err)
				}
				if matchedPattern {
					// found a match.
					// check if we already found a match in a prior iteration our of loops.
					if len(result) > 0 && !allowMultiFuzz {
						return nil, fmt.Errorf("multiple matches not allowed. multiple matches for pattern %v and func %v: %v.%v and %v.%v",
							pkgPattern, funcPattern, pkg.PkgPath, id.Name, result[0].PkgPath, result[0].FuncName)
					}
					pkgDir, err := goListDir(pkg.PkgPath)
					if err != nil {
						return nil, report(err)
					}

					function := Func{
						Types:    Types{f: f},
						FuncName: id.Name, PkgName: pkg.Name, PkgPath: pkg.PkgPath, PkgDir: pkgDir,
					}
					result = append(result, function)

					// keep looping to see if we find another match
				}
			}
		}
	}
	// done looking
	if len(result) == 0 {
		return nil, fmt.Errorf("failed to find fuzz function for pattern %v and func %v", pkgPattern, funcPattern)
	}
	return result, nil
}

func createWrapper(w io.Writer, function Func) {
	f := function.Types.f

	// TODO: remove printfs
	// fmt.Printf("found function: id.Name [%v] value [%v]\n", id.Name, obj)
	// fmt.Fprintf(w, "f: %+v T: %T\n", f, f)
	// fmt.Fprintf(w, "f: %+v T: %T\n", f, f)
	// fmt.Fprintf(w, "f Type: %+v T: %T\n", f.Type(), f.Type())

	sig, ok := f.Type().(*types.Signature)
	if !ok {
		panic("failed to convert type")
	}
	// fmt.Fprintf(w, "sig: %+v T: %T\n", sig, sig)
	tuple := sig.Params()
	// fmt.Fprintf(w, "tuple: %+v T: %T\n", tuple, tuple)

	externalQualifier := func(p *types.Package) string {
		// always return the package name, which
		// should give us things like pkgname.SomeType
		return p.Name()
	}

	// loosly modeled after PrintHugeParams in https://github.com/golang/example/blob/master/gotypes/hugeparam/main.go#L24
	var params []*types.Var
	for i := 0; i < tuple.Len(); i++ {
		v := tuple.At(i)
		params = append(params, v)
		fmt.Printf("PARAM: %s: %s\n", v.Name(), v.Type())
		pkg := v.Pkg()
		if pkg == nil {
			continue
		}
		fmt.Printf("  pkg: %s: %s\n", pkg, pkg.Path())
		fmt.Printf("  typestring: %s\n", types.TypeString(v.Type(), nil))
		fmt.Printf("  typestring with manual qualifier: %s\n", types.TypeString(v.Type(), externalQualifier))
		fmt.Printf("  typestring with RelativeTo: %s\n", types.TypeString(v.Type(),
			types.RelativeTo(pkg)))

	}
	// TODO: add in:
	// fuzzer := gofuzz.New().NilChance(0.1).NumElements(0, 10).MaxDepth(10)
	// fmt.Fprintf(w, "\npackage %s\n", function.PkgName)
	fmt.Fprintf(w, "\npackage richsigwrapper\n")
	fmt.Fprintf(w, "\nimport \"%s\"\n", function.PkgPath)
	fmt.Fprintf(w, `
import gofuzz "github.com/google/gofuzz"

// FuzzRichSigWrapper is an automatically generated wrapper that is
// compatible with dvyukov/go-fuzz.
func FuzzRichSigWrapper(data []byte) int {
	// fuzzer := fuzz.New()
	var seed int64
	if len(data) == 0 {
		seed = 0
	} else {
		seed = int64(data[0])
	}
	fuzzer := gofuzz.NewWithSeed(seed)
	fuzzOne(fuzzer)
	return 0
}

// fuzzOne is an automatically generated function that takes
// uses google/gofuzz fuzzer to automatically fuzz the arguments for a
// user-supplied function.
func fuzzOne (fuzzer *gofuzz.Fuzzer) {

	// Create random args for each parameter from the signature.
	// fuzzer.Fuzz recursively fills all of obj's fields with something random.
	// Only exported (public) fields can be set currently. (That is how google/go-fuzz operates).
`)
	for _, v := range params {
		// want:
		//		var foo string
		//		fuzzer.Fuzz(&foo)

		typeStringWithSelector := types.TypeString(v.Type(), externalQualifier)
		fmt.Fprintf(w, "\tvar %s %s\n", v.Name(), typeStringWithSelector)
		fmt.Fprintf(w, "\tfuzzer.Fuzz(&%s)\n\n", v.Name())
	}
	fmt.Fprintf(w, "\t%s.%s(", f.Pkg().Name(), f.Name()) // was target.%s with f.Name()
	// fmt.Println(types.TypeString(f.Pkg(), qualifier))
	var names []string
	for _, v := range params {
		names = append(names, v.Name())
	}
	fmt.Fprintf(w, "%s)\n\n}\n", strings.Join(names, ", "))
}

// goListDir returns the dir for a package import path
// TODO: make public? put in fzgo/fuzz package?
func goListDir(pkgPath string) (string, error) {
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", buildTagsArg, pkgPath).Output()
	if err != nil {
		return "", fmt.Errorf("failed to find directory of %v: %v", pkgPath, err)
	}
	result := strings.TrimSpace(string(out))
	if strings.Contains(result, "\n") {
		return "", fmt.Errorf("multiple directory results for package %v", pkgPath)
	}
	return result, nil
}

// A maxDuration of 0 means no max time is enforced.
// TODO: make public? put in fzgo/fuzz package? added env
func execCmd(name string, args []string, env []string, maxDuration time.Duration) error {
	report := func(err error) error { return fmt.Errorf("exec %v error: %v", name, err) }

	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = env

	if maxDuration == 0 {
		// invoke cmd and let it run until it returns
		err := cmd.Run()
		if err != nil {
			return report(err)
		}
		return nil
	}

	// we have a maxDuration specified.
	// start and then manually kill cmd after maxDuration if it doesn't exit on its own.
	err := cmd.Start()
	if err != nil {
		return report(err)
	}
	timer := time.AfterFunc(maxDuration, func() {
		err := cmd.Process.Signal(os.Interrupt)
		if err != nil {
			// os.Interrupt expected to fail in some cases (e.g., not implemented on Windows)
			_ = cmd.Process.Kill()
		}
	})
	err = cmd.Wait()
	if timer.Stop() && err != nil {
		// timer.Stop() returned true, which means our kill func never ran, so return this error
		return report(err)
	}
	return nil
}
