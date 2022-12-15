
all: clean build run


build:
	go build -o server

run:
	CERT=cert.pem KEY=key.pem PORT=4567 ./server

clean:
	rm -f server
