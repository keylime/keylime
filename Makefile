.PHONY: check check-rebuild
check:
	tox -vv -epylint

check-rebuild:
	tox -r -vv -epylint
