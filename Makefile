build:
	go mod tidy
	go build -o passed .

clean:
	rm -f passed go.sum
