default:
ifdef name
	@cd challenge; \
		python3.12 source.py; \
		mkdir crypto_$(name); \
		cp source.py tales.txt ./crypto_$(name); \
		cp tales.txt ../htb/; \
		mv ./crypto_$(name) ../release/;

	@cd release; \
		zip -9 -r ./crypto_$(name).zip ./crypto_$(name); \
		unzip -l ./crypto_$(name).zip;

	@echo [+] Challenge was built successfully.
else
	@echo [-] Please define the challenge name. For example, \"make name=cool_chall_name\"
endif

flag:
	@echo [+] Flag : $$(cd challenge; python3 -c 'print(open("flag.txt").read())')
solver:
	@cd htb; \
	python3.12 solver.py;

test: clean default flag solver

clean:
	@rm -rf release/*
	@rm -rf htb/*.txt
	@rm -rf challenge/tales.txt
	@find . -name "*.sage.py" -type f -delete
	@echo [+] Challenge release deleted successfully.
