default:
ifdef name
	@cd challenge/src; \
		cp ../vm/code.bin .; \
		./build.sh; \
		cp heart.png.malakar code.bin ../../htb/; \
		mkdir -p ../../release/rev_$(name); \
		cp heart.png.malakar code.bin bin/heart_protector_with_symbols_packed.exe ../../release/rev_$(name);
	
	@cd release; \
		mv rev_$(name)/heart_protector_with_symbols_packed.exe rev_$(name)/heart_protector.exe; \
		zip -9 -r ./rev_$(name).zip ./rev_$(name); \
		unzip -l ./rev_$(name).zip;
		
	@echo [+] Challenge compiled successfully.
else
	@echo [-] Please define the challenge name. For example, \"make name=cool_chall_name\"
endif

solve:
	@echo [!] Running the solver...
	
	@cd htb; \
		python3 recover_key.py; \
		nim c -r --opt:size --verbosity:0 decryptor.nim
clean:
	@rm -rf htb/decryptor htb/*.png* htb/code.bin
	@rm -rf release/*
	@rm -rf challenge/src/bin/*
	@echo [+] Old data deleted successfully.

prepare: clean default solve