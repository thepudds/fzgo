// genfuzzfuncs is an early stage prototype for automatically generating
// fuzz functions, similar in spirit to cweill/gotests.
//
//
// For example, if you run genfuzzfuncs against github.com/google/uuid, it generates
// a uuid_fuzz.go file with 30 or so functions like:
//
// func Fuzz_UUID_MarshalText(u1 uuid.UUID) {
// 	u1.MarshalText()
// }
//
// func Fuzz_UUID_UnmarshalText(u1 *uuid.UUID, data []byte) {
// 	if u1 == nil {
// 		return
// 	}
// 	u1.UnmarshalText(data)
// }
//
// You can then edit or delete as desired, and then fuzz
// using the rich signature fuzzing support in thepudds/fzgo, such as:
//
//  fzgo test -fuzz=. ./...
package main

import (
	"flag"
	"fmt"
	"go/types"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/thepudds/fzgo/fuzz"
	"golang.org/x/tools/go/packages"
)

// Usage contains short usage information.
var Usage = `
usage:
	genfuzzfuncs [-pkg=pkgPattern] [-func=regexp] [-unexported] [-qualifyall] 
	
Running genfuzzfuncs without any arguments targets the package in the current directory.

genfuzzfuncs outputs to stdout a set of wrapper functions for all functions
matching the func regex in the target package, which defaults to current directory.
Any function that already starts with 'Fuzz' is skipped, and so are any functions
with zero parameters or that have interface parameters.

The resulting wrapper functions will all start with 'Fuzz', and are candidates 
for use with fuzzing via thepudds/fzgo.

genfuzzfuncs does not attempt to populate imports, but 'goimports -w <file>' 
should usaully be able to do so.

`

func main() {
	// handle flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, Usage)
		flag.PrintDefaults()
	}
	pkgFlag := flag.String("pkg", ".", "package pattern, defaults to current package '.'")
	funcFlag := flag.String("func", ".", "function regex, defaults to matching all '.'")
	unexportedFlag := flag.Bool("unexported", false, "emit wrappers for unexported functions in addition to exported functions")
	qualifyAllFlag := flag.Bool("qualifyall", true, "all identifiers are qualified with package, including identifiers from the target package."+
		" If the package is '.' or not set, this defaults to false. Else, it defaults to true.")
	flag.Parse()
	if len(flag.Args()) != 0 {
		fmt.Fprintln(os.Stderr, Usage)
		os.Exit(2)
	}

	// search for functions in the requested package that
	// matches the supplied func regex
	options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
	if !*unexportedFlag {
		options |= flagRequireExported
	}
	var qualifyAll bool
	if *pkgFlag == "." {
		qualifyAll = false
	} else {
		// qualifyAllFlag defaults to true, which is what we want
		// for non-local package.
		qualifyAll = *qualifyAllFlag
	}

	functions, err := FindFunc(*pkgFlag, *funcFlag, nil, options)
	if err != nil {
		fail(err)
	}

	err = createWrappers(os.Stdout, functions, qualifyAll)
	if err != nil {
		fail(err)
	}
}

func createWrappers(w io.Writer, functions []fuzz.Func, qualifyAll bool) error {
	if len(functions) == 0 {
		return fmt.Errorf("no matching functions found")
	}

	var pkgSuffix string
	if qualifyAll {
		pkgSuffix = "fuzz    // rename if needed"
	}
	fmt.Fprintf(w, "package %s%s\n\n", functions[0].TypesFunc.Pkg().Name(), pkgSuffix)
	fmt.Fprint(w, "import (\n")
	fmt.Fprint(w, "\t// fill in manually if needed, or run 'goimports'\n")
	fmt.Fprint(w, ")\n\n")

	// put into a deterministic order
	sort.Slice(functions, func(i, j int) bool {
		return functions[i].TypesFunc.String() < functions[j].TypesFunc.String()
	})

	for _, function := range functions {
		err := createWrapper(w, function, qualifyAll)
		if err != nil {
			return fmt.Errorf("error processing %s: %v", function.FuncName, err)
		}
	}
	return nil
}

func createWrapper(w io.Writer, function fuzz.Func, qualifyAll bool) error {
	f := function.TypesFunc
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return fmt.Errorf("function %s is not *types.Signature (%+v)", function, f)
	}

	localPkg := f.Pkg()
	localQualifier := func(pkg *types.Package) string {
		if pkg == localPkg {
			return ""
		}
		return pkg.Name()
	}
	qualifier := localQualifier
	if qualifyAll {
		qualifier = externalQualifier
	}

	var paramsWithRecv []*types.Var

	recv := sig.Recv()
	if recv != nil {
		if recv.Name() == "" {
			// this can be an interface method. skip, nothing to do here.
			return nil
		}
		// TODO
		// fmt.Println("rcv:      ", recv)
		// fmt.Println("parm name:", recv.Name())
		paramsWithRecv = append(paramsWithRecv, recv)
		// fmt.Println("qualified:", recvTypeString)
	}

	tuple := sig.Params()
	for i := 0; i < tuple.Len(); i++ {
		v := tuple.At(i)
		paramsWithRecv = append(paramsWithRecv, v)
	}

	if len(paramsWithRecv) == 0 {
		// skip, not useful for fuzzing if no inputs (no receiver, no parameters).
		return nil
	}

	// start emitting the wrapper function!
	var wrapperName string
	if recv == nil {
		wrapperName = fmt.Sprintf("Fuzz_%s", f.Name())
	} else {
		recvTypeShortName := types.TypeString(recv.Type(), localQualifier)
		recvTypeShortName = strings.TrimLeft(recvTypeShortName, "*")
		wrapperName = fmt.Sprintf("Fuzz_%s_%s", recvTypeShortName, f.Name())
	}

	// if the parameters include interfaces or funcs, emit a comment saying we are skipping.
	// Could try to handle certain interfaces like io.Reader, but right now google/gofuzz
	// I think will panic if asked to fuzz an interface with "panic: Can't handle <nil>".
	// Could translate at least io.Reader/io.Writer to []byte or *bytes.Buffer or similar.
	for _, v := range paramsWithRecv {
		// basic checking for interfaces, funcs, or pointers or slices of interfaces or funcs.
		var t types.Type
		switch u := v.Type().Underlying().(type) {
		case *types.Pointer:
			t = u.Elem()
		case *types.Slice:
			t = u.Elem()
		default:
			t = v.Type()
		}

		switch t.Underlying().(type) {
		case *types.Interface, *types.Signature:
			fmt.Fprintf(w, "// skipping %s because parameters include interfaces or funcs: %v\n\n", wrapperName, v.Type())
			// alternative could be to check for nil interface, and workaround google/gofuzz panicing on interfaces.
			return nil
		}
	}

	// TODO: decide if useful to have a comment. Things like lint will be complaining anyway about the '_'.
	// fmt.Fprintf(w, "// %s is an automatically generated wrapper function.\n", wrapperName)
	fmt.Fprintf(w, "func %s(", wrapperName)

	renameCollisions := func(v *types.Var, i int) string {
		// handle corner case of using the package name as a parameter name (e.g., flag.UnquoteUsage(flag *Flag))
		paramName := v.Name()
		if paramName == localPkg.Name() {
			paramName = fmt.Sprintf("%s%d", string([]rune(paramName)[0]), i+1)
		}
		return paramName
	}
	// iterate over the receiver (if any) and parameters, emitting the wrapper function as we go.
	for i, v := range paramsWithRecv {
		// want: foo string, bar int
		if i > 0 {
			// need a comma if something has already been emitted
			fmt.Fprint(w, ", ")
		}
		paramName := renameCollisions(v, i)
		typeStringWithSelector := types.TypeString(v.Type(), qualifier)
		fmt.Fprintf(w, "%s %s", paramName, typeStringWithSelector)
	}
	fmt.Fprint(w, ") {\n")

	for i, v := range paramsWithRecv {
		// always crashing on a nil receiver is not particularly interesting, so emit the code to avoid.
		// also check if we have any other pointer parameters.
		// a user can decide to delete if they want to test nil recivers or nil parameters.
		// also, could have a flag to disable.
		_, ok := v.Type().(*types.Pointer)
		if ok {
			paramName := renameCollisions(v, i)
			fmt.Fprintf(w, "\tif %s == nil {\n", paramName)
			fmt.Fprint(w, "\t\treturn\n")
			fmt.Fprint(w, "\t}\n")
		}
	}

	// emit the call to the wrapped function.
	// this currently assumes it runs in the local package (that is, unqualified name)
	if recv == nil {
		if qualifyAll {
			fmt.Fprintf(w, "\t%s.%s(", localPkg.Name(), f.Name())
		} else {
			fmt.Fprintf(w, "\t%s(", f.Name())
		}
	} else {
		recvName := renameCollisions(recv, 0)
		fmt.Fprintf(w, "\t%s.%s(", recvName, f.Name())
	}

	// emit the arguments to the wrapped function.
	// (the receiver was emitted above, if needed).
	var names []string
	for i := 0; i < tuple.Len(); i++ {
		v := tuple.At(i)
		paramName := renameCollisions(v, i)
		names = append(names, paramName)
	}
	fmt.Fprintf(w, "%s", strings.Join(names, ", "))
	if sig.Variadic() {
		// last argument should include an elipsis
		fmt.Fprint(w, "...")
	}
	fmt.Fprint(w, ")\n}\n\n")

	return nil
}

// externalQualifier can be used as types.Qualifier in calls to types.TypeString and similar.
func externalQualifier(p *types.Package) string {
	// always return the package name, which
	// should give us things like pkgname.SomeType
	return p.Name()
}

func isExportedFunc(f *types.Func) bool {
	if !f.Exported() {
		return false
	}
	// the function itself is exported, but it might be a method on an exported type.
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false
	}
	recv := sig.Recv()
	if recv == nil {
		return true
	}

	var n *types.Named
	switch v := recv.Type().(type) {
	case *types.Pointer:
		n, ok = v.Elem().(*types.Named)
		if !ok {
			return false
		}
	case *types.Named:
		n = v
	default:
		return false
	}

	return n.Obj().Exported()
}

// TODO: currently this is a temporary fork from fuzz.FindFunc

// FindFuncFlag describes bitwise flags for FindFunc
type FindFuncFlag uint

const (
	flagAllowMultiFuzz FindFuncFlag = 1 << iota
	flagRequireFuzzPrefix
	flagExcludeFuzzPrefix
	flagRequireExported
	flagVerbose
)

// FindFunc searches for requested functions matching a package pattern and func pattern.
func FindFunc(pkgPattern, funcPattern string, env []string, flags FindFuncFlag) ([]fuzz.Func, error) {
	report := func(err error) error {
		return fmt.Errorf("error while loading packages for pattern %v: %v", pkgPattern, err)
	}
	var result []fuzz.Func

	// load packages based on our package pattern
	// build tags example: https://groups.google.com/d/msg/golang-tools/Adwr7jEyDmw/wQZ5qi8ZGAAJ
	cfg := &packages.Config{
		Mode: packages.LoadSyntax,
		// TODO: BuildFlags: []string{buildTagsArg},
	}
	if len(env) > 0 {
		cfg.Env = env
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

				// TODO: merge back to fuzz.FindFunc?
				if flags&flagExcludeFuzzPrefix != 0 && strings.HasPrefix(id.Name, "Fuzz") {
					// skip any function that already starts with Fuzz
					continue
				}
				if flags&flagRequireFuzzPrefix != 0 && !strings.HasPrefix(id.Name, "Fuzz") {
					// skip any function that does not start with Fuzz
					continue
				}
				if flags&flagRequireExported != 0 {
					if !isExportedFunc(f) {
						continue
					}
				}

				matchedPattern, err := regexp.MatchString(funcPattern, id.Name)
				if err != nil {
					return nil, report(err)
				}
				if matchedPattern {
					// found a match.
					// check if we already found a match in a prior iteration our of loops.
					if len(result) > 0 && flags&flagAllowMultiFuzz == 0 {
						return nil, fmt.Errorf("multiple matches not allowed. multiple matches for pattern %v and func %v: %v.%v and %v.%v",
							pkgPattern, funcPattern, pkg.PkgPath, id.Name, result[0].PkgPath, result[0].FuncName)
					}
					pkgDir, err := goListDir(pkg.PkgPath, env)
					if err != nil {
						return nil, report(err)
					}

					function := fuzz.Func{
						FuncName: id.Name, PkgName: pkg.Name, PkgPath: pkg.PkgPath, PkgDir: pkgDir,
						TypesFunc: f,
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

// TODO: forked from fzgo/fuzz
// goListDir returns the dir for a package import path
func goListDir(pkgPath string, env []string) (string, error) {
	if len(env) == 0 {
		env = os.Environ()
	}

	// TODO: cmd := exec.Command("go", "list", "-f", "{{.Dir}}", buildTagsArg, pkgPath)
	cmd := exec.Command("go", "list", "-f", "{{.Dir}}", pkgPath)
	cmd.Env = env

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to find directory of %v: %v", pkgPath, err)
	}
	result := strings.TrimSpace(string(out))
	if strings.Contains(result, "\n") {
		return "", fmt.Errorf("multiple directory results for package %v", pkgPath)
	}
	return result, nil
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "genfuzzfuncs: error: %v\n", err)
	os.Exit(1)
}
