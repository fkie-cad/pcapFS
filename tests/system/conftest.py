import pytest


def pytest_addoption(parser):
    parser.addoption("--testpcap")

def pytest_generate_tests(metafunc):
    option_value = metafunc.config.option.testpcap
    if 'testpcap' in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("testpcap", [option_value])
