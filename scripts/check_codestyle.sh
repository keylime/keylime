#!/usr/bin/env bash

for PYLINT in pylint pylint-3; do
	if [ -n "$(type -P ${PYLINT})" ]; then
		break
	fi
done

if [ -z "$(type -P ${PYLINT})" ]; then
	echo "pylint or pylint-3 is required"
	exit 1
fi

${PYLINT} --version

# Run pylint on non-test files with standard configuration
PYTHONPATH="$(pwd)" ${PYLINT} \
	*.py \
	$(find ./keylime ./scripts -name '*.py' ! -path './keylime/da/examples/*.py')

MAIN_EXIT=$?

# Run pylint on test files with test-specific configuration (test/.pylintrc)
# This configuration disables R0401 (cyclic-import) for test files
PYTHONPATH="$(pwd)" ${PYLINT} --rcfile=test/.pylintrc \
	$(find ./test -name '*.py' ! -name 'oldtest.py')

TEST_EXIT=$?

# Exit with failure if either check failed
if [ $MAIN_EXIT -ne 0 ] || [ $TEST_EXIT -ne 0 ]; then
	exit 1
fi

exit 0
