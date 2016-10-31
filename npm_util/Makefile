.PHONY: all aaa

all:
	@echo aaa

aaa: lib/jsrsasign-util.js

lib/jsrsasign-util.js: lib/header.js ../min/nodeutil-1.0.min.js lib/footer.js
	cat $^ > $@

