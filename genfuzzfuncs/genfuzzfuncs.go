package main

import (
	"bytes"
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
	"golang.org/x/tools/imports"
)

type wrapperOptions struct {
	qualifyAll         bool   // qualify all variables with package name
	insertConstructors bool   // attempt to insert suitable constructors when wrapping methods
	constructorPattern string // regexp for searching for candidate constructors
}

// createWrappers emits fuzzing wrappers where possible for the list of functions passed in.
// It might skip a function if it has no input parameters, or if it has a non-fuzzable parameter
// type such as interface{}.
// See package comment in main.go for more details.
func createWrappers(pkgPattern string, functions []fuzz.Func, options wrapperOptions) ([]byte, error) {
	if len(functions) == 0 {
		return nil, fmt.Errorf("no matching functions found")
	}

	// start by hunting for possible constructors in the same package if requested.
	var possibleConstructors []fuzz.Func
	if options.insertConstructors {
		// We default to the pattern ^New, but allow user-specified patterns.
		// We don't check the err here because it can be expected to not find anything if there
		// are no functions that start with New (and this is our second call to FindFunc, so
		// other problems should have been reported earlier).
		// TODO: consider related tweak to error reporting in FindFunc?
		possibleConstructors, _ = FindFunc(pkgPattern, options.constructorPattern, nil,
			flagExcludeFuzzPrefix|flagAllowMultiFuzz|flagRequireExported)
		// put possibleConstructors into a semi-deterministic order.
		// TODO: for now, we'll prefer simpler constructors as approximated by length (so 'New' before 'NewSomething').
		sort.Slice(possibleConstructors, func(i, j int) bool {
			return len(possibleConstructors[i].FuncName) < len(possibleConstructors[j].FuncName)
		})
	}

	// emit the intro material
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	var pkgSuffix string
	if options.qualifyAll {
		pkgSuffix = "fuzz // rename if needed"
	}
	fmt.Fprintf(w, "package %s%s\n\n", functions[0].TypesFunc.Pkg().Name(), pkgSuffix)
	fmt.Fprint(w, "// if needed, fill in imports or run 'goimports'\n")
	fmt.Fprint(w, "import (\n)\n\n")

	// put our functions we want to wrap into a deterministic order
	sort.Slice(functions, func(i, j int) bool {
		// types.Func.String outputs strings like:
		//   func (github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection.A).ValMethodWithArg(i int) bool
		// works ok for clustering results, though pointer receiver and non-pointer receiver methods don't cluster.
		// could strip '*' or sort another way, but probably ok, at least for now.
		return functions[i].TypesFunc.String() < functions[j].TypesFunc.String()
	})
	// loop over our the functions we are wrapping, emitting a wrapper where possible.
	for _, function := range functions {
		err := createWrapper(w, function, possibleConstructors, options.qualifyAll)
		if err != nil {
			return nil, fmt.Errorf("error processing %s: %v", function.FuncName, err)
		}
	}

	// fix up any needed imports.
	out, err := imports.Process("autogeneratedfuzz.go", buf.Bytes(), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genfuzzfuncs: warning: continuing after failing to automatically adjust imports:", err)
		return buf.Bytes(), nil
	}
	return out, nil
}

// createWrapper emits one fuzzing wrapper if possible.
// It takes a list of possible constructors to insert into the wrapper body if the
// constructor is suitable for creating the receiver of a wrapped method.
// qualifyAll indicates if all variables should be qualified with their package.
func createWrapper(w io.Writer, function fuzz.Func, possibleConstructors []fuzz.Func, qualifyAll bool) error {
	var err error
	f := function.TypesFunc
	wrappedSig, ok := f.Type().(*types.Signature)
	if !ok {
		return fmt.Errorf("function %s is not *types.Signature (%+v)", function, f)
	}
	localPkg := f.Pkg()

	// set up types.Qualifier funcs we can use with the types package
	// to scope variables by a package or not.
	defaultQualifier, localQualifier := qualifiers(localPkg, qualifyAll)

	// TODO: rename allParams to namespace? or possibleCollisions
	// start building up our list of parameters we will use in input
	// parameters to the new wrapper func we are about to emit.
	var allParams []*types.Var

	// check if we have a receiver for the function under test, (i.e., testing a method)
	// and then see if we can replace the receiver by finding
	// a suitable constructor and "promoting" the constructor's arguments up into the wrapper's parameter list.
	//
	// The end result is rather than emitting a wrapper like so for strings.Replacer.Replace:
	// 		func Fuzz_Replacer_Replace(r strings.Replacer, s string) {
	// 			r.Replace(s)
	// 		}
	//
	// Instead of that, if we find a suitable constructor for the wrapped method's receiver 'r',
	// we can instead insert a call to the constructor,
	// and "promote" up the constructor's args into the fuzz wrapper's parameters:
	// 		func Fuzz_Replacer_Replace(oldnew []string, s string) {
	// 			r := strings.NewReplacer(oldnew...)
	// 			r.Replace(s)
	// 		}
	recv := wrappedSig.Recv()
	var ctorReplace ctorReplacement
	if recv != nil {
		if recv.Name() == "" {
			// this can be an interface method. skip, nothing to do here.
			return nil
		}
		var paramsToAdd []*types.Var
		ctorReplace, paramsToAdd, err = constructorReplace(recv, possibleConstructors)
		if err != nil {
			return err
		}
		allParams = append(allParams, paramsToAdd...)
	}

	// add in the parameters for the function under test.
	for i := 0; i < wrappedSig.Params().Len(); i++ {
		v := wrappedSig.Params().At(i)
		allParams = append(allParams, v)
	}

	// determine our wrapper name, which includes the receiver's type if we are wrapping a method.
	var wrapperName string
	if recv == nil {
		wrapperName = fmt.Sprintf("Fuzz_%s", f.Name())
	} else {
		n, err := findReceiverNamedType(recv)
		if err != nil {
			// output to stderr, but don't treat as fatal error.
			fmt.Fprintf(os.Stderr, "genfuzzfuncs: warning: createWrapper: failed to determine receiver type: %v: %v\n", recv, err)
			return nil
		}
		recvNamedTypeLocalName := types.TypeString(n.Obj().Type(), localQualifier)
		wrapperName = fmt.Sprintf("Fuzz_%s_%s", recvNamedTypeLocalName, f.Name())
	}

	// check if we have an interface or function pointer in our desired parameters,
	// we can't fill in with values during fuzzing.
	if disallowedParams(w, allParams, wrapperName) {
		// skip this wrapper, disallowedParams emitted a comment with more details.
		return nil
	}
	if len(allParams) == 0 {
		// skip this wrapper, not useful for fuzzing if no inputs (no receiver, no parameters).
		return nil
	}

	// start emitting the wrapper function!
	// start the func declartion
	fmt.Fprintf(w, "func %s(", wrapperName)

	// iterate over the our input parameters and emit.
	// If we are a method, this includes either an object that is wrapped receiver's type,
	// or it includes the parameters for a constructor if we found a suitable one.
	for i, v := range allParams {
		// want: foo string, bar int
		if i > 0 {
			// need a comma if something has already been emitted
			fmt.Fprint(w, ", ")
		}
		paramName := avoidCollision(v, i, localPkg, allParams)
		typeStringWithSelector := types.TypeString(v.Type(), defaultQualifier)
		fmt.Fprintf(w, "%s %s", paramName, typeStringWithSelector)
	}
	fmt.Fprint(w, ") {\n")

	// Always crashing on a nil receiver is not particularly interesting, so emit the code to avoid.
	// Also check if we have any other pointer parameters.
	emitNilChecks(w, allParams, localPkg)

	// emit a constructor if we have one.
	// collisionOffset tracks how far we are into the parameters of the final fuzz function signature.
	// (For a constructor call, it will be zero because for the final fuzz function,
	// the signature starts with any constructor parameters. For the function under test,
	// the offset will by the length of the signature of constructor, if any, or zero if no constructor.
	// This is because the parameters for the function under test follow any constructor parameters
	// in the final fuzz function signature.
	// TODO: collisionOffset is a bit quick & dirty. Probably should track a more direct
	// (original name, provenance) -> new name mapping, or perhaps simplify the logic
	// so that we never use original names.
	collisionOffset := 0
	if ctorReplace.Sig != nil && recv != nil {
		// insert our constructor!
		fmt.Fprintf(w, "\t%s := ", avoidCollision(recv, 0, localPkg, allParams))
		if qualifyAll {
			fmt.Fprintf(w, "%s.%s(", localPkg.Name(), ctorReplace.Func.Name())
		} else {
			fmt.Fprintf(w, "%s(", ctorReplace.Func.Name())
		}
		emitArgs(w, ctorReplace.Sig, 0, localPkg, allParams)
		fmt.Fprintf(w, ")\n")
		collisionOffset = ctorReplace.Sig.Params().Len()
	}

	// emit the call to the wrapped function.
	emitWrappedFunc(w, f, wrappedSig, collisionOffset, qualifyAll, allParams, localPkg)

	fmt.Fprint(w, "}\n\n")

	return nil
}

// qualifiers sets up a types.Qualifier func we can use with the types package,
// paying attention to whether we are qualifying everything or not.
func qualifiers(localPkg *types.Package, qualifyAll bool) (defaultQualifier, localQualifier types.Qualifier) {

	localQualifier = func(pkg *types.Package) string {
		if pkg == localPkg {
			return ""
		}
		return pkg.Name()
	}
	if qualifyAll {
		defaultQualifier = externalQualifier
	} else {
		defaultQualifier = localQualifier
	}
	return defaultQualifier, localQualifier
}

// externalQualifier can be used as types.Qualifier in calls to types.TypeString and similar.
func externalQualifier(p *types.Package) string {
	// always return the package name, which
	// should give us things like pkgname.SomeType
	return p.Name()
}

// avoidCollision takes a variable (which might correpsond to a parameter or argument),
// and returns a non-colliding name, or the original name, based on
// whether or not it collided with package name or other with parameters.
func avoidCollision(v *types.Var, i int, localPkg *types.Package, allWrapperParams []*types.Var) string {
	// handle corner case of using the package name as a parameter name (e.g., flag.UnquoteUsage(flag *Flag)),
	// or two parameters of the same name (e.g., if one was from a constructor and the other from the func under test).
	paramName := v.Name()

	if paramName == "_" {
		// treat all underscore identifiers as colliding, and use something like "x1" or "x2" in their place.
		// this avoids 'cannot use _ as value' errors for things like 'NotNilFilter(_ string, v reflect.Value)' stdlib ast package.
		// an alternative would be to elide them when possible, but easier to retain, at least for now.
		return fmt.Sprintf("x%d", i+1)
	}

	collision := false
	if paramName == localPkg.Name() {
		collision = true
	}
	for _, p := range allWrapperParams {
		if v != p && paramName == p.Name() {
			collision = true
		}
	}
	if collision {
		paramName = fmt.Sprintf("%s%d", string([]rune(paramName)[0]), i+1)
	}
	return paramName
}

// emitNilChecks emits checks for nil for our input parameters.
// Always crashing on a nil receiver is not particularly interesting, so emit the code to avoid.
// Also check if we have any other pointer parameters.
// A user can decide to delete if they want to test nil recivers or nil parameters.
// Also, could have a flag to disable.
func emitNilChecks(w io.Writer, allParams []*types.Var, localPkg *types.Package) {

	for i, v := range allParams {
		_, ok := v.Type().(*types.Pointer)
		if ok {
			paramName := avoidCollision(v, i, localPkg, allParams)
			fmt.Fprintf(w, "\tif %s == nil {\n", paramName)
			fmt.Fprint(w, "\t\treturn\n")
			fmt.Fprint(w, "\t}\n")
		}
	}
}

// emitWrappedFunc emits the call to the function under test.
func emitWrappedFunc(w io.Writer, f *types.Func, wrappedSig *types.Signature, collisionOffset int, qualifyAll bool, allParams []*types.Var, localPkg *types.Package) {
	recv := wrappedSig.Recv()
	if recv != nil {
		recvName := avoidCollision(recv, 0, localPkg, allParams)
		fmt.Fprintf(w, "\t%s.%s(", recvName, f.Name())
	} else {
		if qualifyAll {
			fmt.Fprintf(w, "\t%s.%s(", localPkg.Name(), f.Name())
		} else {
			fmt.Fprintf(w, "\t%s(", f.Name())
		}
	}
	// emit the arguments to the wrapped function.
	emitArgs(w, wrappedSig, collisionOffset, localPkg, allParams)
	fmt.Fprint(w, ")\n")
}

// emitArgs emits the arguments needed to call a signature, including handling renaming arguments
// based on collisions with package name or other parameters.
func emitArgs(w io.Writer, sig *types.Signature, collisionOffset int, localPkg *types.Package, allWrapperParams []*types.Var) {
	for i := 0; i < sig.Params().Len(); i++ {
		v := sig.Params().At(i)
		paramName := avoidCollision(v, i+collisionOffset, localPkg, allWrapperParams)
		if i > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprint(w, paramName)
	}
	if sig.Variadic() {
		// last argument needs an elipsis
		fmt.Fprint(w, "...")
	}
}

// disallowedParams reports if the parameters include interfaces or funcs, and emits
// a comment saying we are skipping if found.
// We could try to handle certain interfaces like io.Reader, but right now google/gofuzz
// I think will panic if asked to fuzz an interface with "panic: Can't handle <nil>".
// Could translate at least io.Reader/io.Writer to []byte or *bytes.Buffer or similar.
func disallowedParams(w io.Writer, allWrapperParams []*types.Var, wrapperName string) bool {
	for _, v := range allWrapperParams {
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
		case *types.Interface:
			_, ok := fuzz.InterfaceImpl[v.Type().String()]
			if !ok {
				// TODO: leaving old output for now.
				fmt.Fprintf(w, "// skipping %s because parameters include interfaces or funcs: %v\n\n",
					wrapperName, v.Type())
				// fmt.Fprintf(w, "// skipping %s because parameters include unsupported interface: %v\n\n",
				// 	wrapperName, v.Type())
				return true
			}
		case *types.Signature:
			fmt.Fprintf(w, "// skipping %s because parameters include interfaces or funcs: %v\n\n",
				wrapperName, v.Type())
			return true
		}
	}
	return false
}

// ctorReplacement holds the signature of a suitable constructor if we found one.
// We use the signature to "promote" the needed arguments from the constructor
// parameter list up to the wrapper function parameter list.
// Sig is nil if a suitable constructor was not found.
type ctorReplacement struct {
	Sig  *types.Signature
	Func *types.Func
}

// constructorReplace determines if there is a constructor we can replace,
// and returns that constructor along with the related parameters we need to
// add to the main wrapper method. They will either be the parameters
// needed to pass into the constructor, or it will be a single parameter
// corresponding to the wrapped method receiver if we didn't find a usable constructor.
func constructorReplace(recv *types.Var, possibleConstructors []fuzz.Func) (ctorReplacement, []*types.Var, error) {
	var ctorReplace ctorReplacement
	var paramsToAdd []*types.Var
	for _, possibleConstructor := range possibleConstructors {
		ctorSig, ok := possibleConstructor.TypesFunc.Type().(*types.Signature)
		if !ok {
			return ctorReplace, paramsToAdd, fmt.Errorf("function %s is not *types.Signature (%+v)",
				possibleConstructor, possibleConstructor.TypesFunc)
		}

		if ctorSig.Params().Len() == 0 {
			// constructors are mainly useful for fuzzing if they take at least one argument.
			// if not, better off keep looking for another constructor (and if later no constructor can be found at all,
			// than it is better to not use a constructor if the struct has public members; if there is no constructor found
			// that has at least one arg, and there are no public members on the struct, then not much we can do).
			continue
		}

		ctorResults := ctorSig.Results()
		if ctorResults.Len() != 1 {
			// only handle single result constructors. could try to handle error as well, or more.
			continue
		}
		ctorResult := ctorResults.At(0)

		recvN, err := findReceiverNamedType(recv)
		if err != nil {
			// output to stderr, but don't treat as fatal error.
			fmt.Fprintf(os.Stderr, "genfuzzfuncs: warning: constructorReplace: failed to determine receiver type when looking for constructors: %v: %v\n", recv, err)
			continue
		}

		ctorResultN, err := findReceiverNamedType(ctorResult)
		if err != nil {
			// findReceiverNamedType returns a types.Named if the passed in
			// types.Var is a types.Pointer or already types.Named.
			// This candidate constructor is neither of those, which means we can't
			// use it to give us the type we need for the receiver for this method we are trying to fuzz.
			// This is not an error. It just means it didn't match.
			continue
		}

		// TODO: types.Identical wasn't working as expected. Imperfect fall back for now.
		// types.TypeString(recvN, nil) returns a fullly exanded string that includes the import path, e.g.,:
		//   github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection.A
		if types.TypeString(recvN, nil) == types.TypeString(ctorResultN, nil) {
			// we found a match between this constructor's return type and the receiver type
			// we need for the method we are trying to fuzz! (ignoring a pointer, which we stripped off above).
			ctorReplace.Sig = ctorSig
			ctorReplace.Func = possibleConstructor.TypesFunc
			break
		}
	}
	if ctorReplace.Sig == nil {
		// we didn't find a matching constructor,
		// so the method receiver will be added to the wrapper function's parameters.
		paramsToAdd = append(paramsToAdd, recv)
	} else {
		// insert our constructor's arguments.
		for i := 0; i < ctorReplace.Sig.Params().Len(); i++ {
			v := ctorReplace.Sig.Params().At(i)
			paramsToAdd = append(paramsToAdd, v)
		}
	}
	return ctorReplace, paramsToAdd, nil
}

// TODO: would be good to find some canonical documentation or example of this.
func isExportedFunc(f *types.Func) bool {
	if !f.Exported() {
		return false
	}
	// the function itself is exported, but it might be a method on an unexported type.
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false
	}
	recv := sig.Recv()
	if recv == nil {
		// not a method, and the func itself is exported.
		return true
	}

	n, err := findReceiverNamedType(recv)
	if err != nil {
		// don't treat as fatal error.
		fmt.Fprintf(os.Stderr, "genfuzzfuncs: warning: failed to determine if exported for receiver %v for func %v: %v\n",
			recv, f, err)
		return false
	}

	return n.Obj().Exported()
}

// isInterfaceRecv helps filter out interface receivers such as 'func (interface).Is(error) bool'
// from errors.Is:
//    x, ok := err.(interface{ Is(error) bool }); ok && x.Is(target)
func isInterfaceRecv(f *types.Func) bool {
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false
	}
	recv := sig.Recv()
	if recv == nil {
		// not a method
		return false
	}
	_, ok = recv.Type().(*types.Interface)
	return ok
}

// findReceiverNamedType returns a types.Named if the passed in
// types.Var is a types.Pointer or already types.Named.
func findReceiverNamedType(recv *types.Var) (*types.Named, error) {
	reportErr := func() (*types.Named, error) {
		return nil, fmt.Errorf("expected pointer or named type: %+v", recv.Type())
	}

	switch t := recv.Type().(type) {
	case *types.Pointer:
		if t.Elem() == nil {
			return reportErr()
		}
		n, ok := t.Elem().(*types.Named)
		if ok {
			return n, nil
		}
	case *types.Named:
		return t, nil
	}
	return reportErr()
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
// TODO: this is a temporary fork from fzgo/fuzz.FindFunc.
// TODO: maybe change flags to a predicate function?
func FindFunc(pkgPattern, funcPattern string, env []string, flags FindFuncFlag) ([]fuzz.Func, error) {
	report := func(err error) error {
		return fmt.Errorf("error while loading packages for pattern %v: %v", pkgPattern, err)
	}
	var result []fuzz.Func

	// load packages based on our package pattern
	// build tags example: https://groups.google.com/d/msg/golang-tools/Adwr7jEyDmw/wQZ5qi8ZGAAJ
	cfg := &packages.Config{
		Mode: packages.LoadSyntax,
		// TODO: BuildFlags: []string{buildTagsArg},  retain? probably doesn't matter.
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
		// TODO: consider alternative: "from a Package, look at Syntax.Scope.Objects and filter with ast.IsExported."
		for id, obj := range pkg.TypesInfo.Defs {
			// check if we have a func
			f, ok := obj.(*types.Func)
			if ok {
				// TODO: merge back to fuzz.FindFunc?
				if isInterfaceRecv(f) {
					continue
				}
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

// goListDir returns the dir for a package import path
// TODO: this is a temporary fork from fzgo/fuzz
func goListDir(pkgPath string, env []string) (string, error) {
	if len(env) == 0 {
		env = os.Environ()
	}

	// TODO: use build tags, or not?
	// cmd := exec.Command("go", "list", "-f", "{{.Dir}}", buildTagsArg, pkgPath)
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
