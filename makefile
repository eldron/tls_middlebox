all:mb
	echo 'built mb'

mb:mb.c
	gcc mb.c -lpthread -o mb

clean:
	rm -f mb
