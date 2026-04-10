package main

// ResponseBuilder builds clean HTTP response bodies.
// TODO: Implement this to replace the obfuscated pipeline in main.go
type ResponseBuilder interface {
    // BuildGreeting returns a clean ASCII greeting for the given name.
    // Expected output format: "hello, <name>"
    BuildGreeting(name string) string
}

// CleanResponseBuilder replaces the obfuscated response logic.
type CleanResponseBuilder struct{}

// TODO: Implement BuildGreeting — must produce clean ASCII output
func (c *CleanResponseBuilder) BuildGreeting(name string) string {
    panic("not implemented")
}

// Resolve takes encoded data and a padding string, returns the decoded result.
// TODO: Implement this to understand and reverse the encoding pipeline in main.go
func Resolve(encoded, pad string) (string, error) {
    panic("not implemented")
}
