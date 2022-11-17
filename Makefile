.PHONY: check check-rebuild
check:
	tox -vv -epylint -epyright -eblack

check-rebuild:
	tox -r -vv -epylint -epyright -eblack
