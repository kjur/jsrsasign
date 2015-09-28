all: join-main

join-minify: *min.js ext/*min.js npm/lib/header.js npm/lib/footer.js
	cat *min.js $(shell find ext/ -name "*min.js") | sed "s/\/*! /\n\/*! /g" > jsrsasign-4.9.0-mdcone-all-min.js
	cp jsrsasign-4.9.0-mdcone-all-min.js jsrsasign-latest-all-min.js

#min-js: *.js
#	for i in `ls *.js | grep -v "min.js"` ; do java -jar ~/src/yuicompressor/build/yuicompressor-2.4.8.jar $i -o `echo $i | sed 's/.js/-min.js/g'` ; done

join-main: join-minify
	cat \
        npm/lib/header.js \
        jsrsasign-latest-all-min.js \
        npm/lib/footer.js \
        > npm/lib/jsrsasign.js
