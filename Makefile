test:
	cc -Wall -g test.c ./lib/bcrypt.a ./lib/crypt_blowfish.a -o test

clean:
	rm -f test
