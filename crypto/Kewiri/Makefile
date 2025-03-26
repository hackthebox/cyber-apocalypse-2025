flag:
	@echo [+] Flag : $$(cd challenge; python3.12 -c 'print(open("flag.txt").read());')

solver:
	@echo [+] Running remote solver
	./build-docker.sh
	sage -python3 htb/solver.py localhost:1337

test: clean flag solver

clean:
	@rm -rf release/*
	@find . -name "*.sage.py" -type f -delete
	@echo [+] Challenge release deleted successfully.
