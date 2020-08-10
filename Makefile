BUILDDIR := build

help:
	@echo "Usage: make TARGET"
	@echo
	@echo "Target can be one of the following:"
	@echo "  build          Compile pcapFS."
	@echo "  dependencies   Install dependencies."
	@echo "  help           Show this message and exit."
	@echo "  release        Merge dev into master and create a new release."
	@echo "  systemtests    Run the system tests."
	@echo "  tests          Run all tests."
	@echo "  unittests      Run the unit tests."

unittests: build
	@echo
	@printf '%80s\n' | sed 's/ /#/g'
	@echo 'Running unit tests'
	@printf '%80s\n' | sed 's/ /#/g'
	@echo
	@cd ${BUILDDIR} && make test

systemtests: build
	@echo
	@printf '%80s\n' | sed 's/ /#/g'
	@echo "Running system tests"
	@printf '%80s\n' | sed 's/ /#/g'
	@echo
	@./tests/system/run-system-tests.sh

tests: unittests systemtests

build: dependencies
	@echo
	@printf '%80s\n' | sed 's/ /#/g'
	@echo "Building pcapFS"
	@printf '%80s\n' | sed 's/ /#/g'
	@echo
	@mkdir -p ${BUILDDIR}
	@cd ${BUILDDIR} && \
		cmake -DBUILD_TESTING=on .. && \
		make -j2

dependencies:
	@echo
	@printf '%80s\n' | sed 's/ /#/g'
	@echo "Building pcapFS dependencies"
	@printf '%80s\n' | sed 's/ /#/g'
	@echo
	@./scripts/dependencies/install-all-dependencies.sh
	@./scripts/dependencies/install-catch2.sh

release: tests
	@./scripts/github-release.sh

.PHONY: build help release systemtests tests unittests
