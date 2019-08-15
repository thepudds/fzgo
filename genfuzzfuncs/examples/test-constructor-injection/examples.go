package fuzzwrapexamples

// ---- Constructor injection examples/tests ----

// When fuzzing am metho, by default genfuzzfuncs puts the receiver's
// type into the parameter list of the wrapper function.
// This works reasonably well if the receiver's type has public
// member variables -- we can set and mutate public member variables while fuzzing.
// However, that works less well if there are no public member variables,
// such as for regex.Regexp.
// If asked, we can inject constructors like so:
//   * we determine the type of the receiver for the method we want to fuzz.
//   * we look for a constructor capable of creating the receiver's type.
//   * we "promote" the parameters from the constructor into the params for the wrapper function.
//   * we insert a call to the constructor using those params.
//   * we use the result of the constructor to call method we want to fuzz.

type A struct{ c int }

func NewAPtr(c int) *A                   { return &A{c} }
func (r *A) PtrMethodWithArg(i int) bool { return r.c == i }
func (r *A) PtrMethodNoArg() bool        { return r.c == 0 }
func (r A) ValMethodWithArg(i int) bool  { return r.c == i }
func (r A) ValMethodNoArg() bool         { return r.c == 0 }

type B struct{ c int }

func NewBVal(c int) B                    { return B{c} }
func (r *B) PtrMethodWithArg(i int) bool { return r.c == i }
func (r *B) PtrMethodNoArg() bool        { return r.c == 0 }
func (r B) ValMethodWithArg(i int) bool  { return r.c == i }
func (r B) ValMethodNoArg() bool         { return r.c == 0 }
