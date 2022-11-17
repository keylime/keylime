.PHONY: check check-rebuild
check:
	tox -vv -epylint -epyright

check-rebuild:
	tox -r -vv -epylint -epyright
