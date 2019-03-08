BUILDDIR := build

help:
	@echo "Usage: make TARGET"
	@echo
	@echo "Target can be one of the following:"
	@echo "  build          Compile pcapFS."
	@echo "  help           Show this message and exit."
	@echo "  systemtests    Run the system tests."
	@echo "  tests          Run all tests."
	@echo "  unittests      Run the unit tests."

unittests: build
	@echo
	@printf '#%.0s' {1..120}
	@echo -e "\n Running unit tests"
	@printf '#%.0s' {1..120}
	@echo -e '\n'
	@cd ${BUILDDIR} && make test

systemtests: build
	@echo
	@printf '#%.0s' {1..120}
	@echo -e "\n Running system tests"
	@printf '#%.0s' {1..120}
	@echo -e '\n'
	@./tests/system/run-system-tests.sh

tests: unittests systemtests

build:
	@echo
	@printf '#%.0s' {1..120}
	@echo -e "\n Building pcapFS"
	@printf '#%.0s' {1..120}
	@echo -e '\n'
	@mkdir -p ${BUILDDIR}
	@cd ${BUILDDIR} && \
		cmake -DBUILD_TESTING=on .. && \
		make -j2

.PHONY: build help systemtests tests unittests
