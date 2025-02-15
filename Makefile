engine: src/ config/
	cp config.yaml config/
	cd config; python3 config.py; mv config.h ../src/config.h
	cd src; gcc engine.c utils.c checks.c html.c -o engine -lcrypto -s
	cd src; upx engine; mv engine ../
	rm config/config.yaml

clean:
	rm -rf engine
