package core

// Version is the running 1-SEC build version. The CLI assigns its ldflag-
// injected version before constructing the engine so API and cloud surfaces
// report the same value as `1sec version`.
var Version = "dev"
