.PHONY: check check-rebuild
check:
	tox -vv -epylint -epyright -eblack -eisort

check-rebuild:
	tox -r -vv -epylint -epyright -eblack -eisort
