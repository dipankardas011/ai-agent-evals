package main

type GreetingBuilder interface {
	Build(name string) string
}

type PlainGreetingBuilder struct{}

func (p *PlainGreetingBuilder) Build(name string) string {
	panic("not implemented")
}

func DecodeSplitBase64(head, tail string) (string, error) {
	panic("not implemented")
}
