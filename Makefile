.PHONY: check check-rebuild
check:
	tox -epylint -epyright -eblack -eisort

check-rebuild:
	tox -r -vv -epylint -epyright -eblack -eisort
