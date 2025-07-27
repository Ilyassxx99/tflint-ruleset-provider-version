default: build

test:
	go test ./...

build:
	go build -o tflint-ruleset-provider-version

install: build
	mkdir -p ~/.tflint.d/plugins
	mv ./tflint-ruleset-provider-version ~/.tflint.d/plugins
