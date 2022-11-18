all: app
app: app.o libgost.o
	gcc -g -W -std=c99 -o app.out build/app.o build/libgost.o
app.o: app.c libs/libgost.h
	gcc -g -W -std=c99 -c -o build/app.o app.c
libgost.o: libs/libgost.h libs/libgost.c
	gcc -g -W -std=c99 -c -o build/libgost.o libs/libgost.c
clean:
	rm -f build/*.o
	rm -f *.out