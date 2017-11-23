package main

var (
	debug = false
)

func handleError(err error) {
	if debug {
		panic(err)
	}
}
