# Tests

Level-IP test suites consist currently of end-to-end tests, where the Linux host's applications are used to test traffic flow.

In the future, a separate unit/packet flow test framework could be integrated into the stack.

# Usage

In the project's root folder, run

    make test

Or a specific test-suite

    ./suites/arp/suite-arp

Root privileges are required.
