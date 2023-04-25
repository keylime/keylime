.PHONY: check check-rebuild
check:
	tox -e pylint,pyright,mypy,black,isort

check-rebuild:
	tox -r -vv -e pylint,pyright,mypy,black,isort
