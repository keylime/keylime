.PHONY: check check-rebuild
check:
	tox -epylint -epyright -emypy -eblack -eisort

check-rebuild:
	tox -r -vv -epylint -epyright -emypy -eblack -eisort
