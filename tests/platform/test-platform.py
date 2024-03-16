#!/usr/bin/env python3
import argparse
import datetime
import json
import subprocess
import sys
from contextlib import contextmanager

import colorful
from tabulate import tabulate

PLATFORMS = {
    "all": "[All platforms]",
    "fedora-37": "Fedora 37",
    "fedora-38": "Fedora 38",
    "fedora-39": "Fedora 39",
    "ubuntu-18.04": "Ubuntu 18.04",
    "ubuntu-20.04": "Ubuntu 20.04",
    "ubuntu-22.04": "Ubuntu 22.04",
    "kali": "Kali",
    "centos-7": "CentOS 7",
}

LOG_FILE_NAME_PREFIX = "platform-tests"

STATUS_FAIL_STRING = colorful.red("fail")
STATUS_PASS_STRING = colorful.green("pass")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = parse_command_line(argv)
    if args.list_platforms:
        list_platforms()
        return 0
    if args.platform:
        platforms = _sanitize_platform_arguments(args.platform)
        run_platform_tests(platforms)


def parse_command_line(argv):
    parser = argparse.ArgumentParser(description="Run the pcapFS platform tests")
    parser.add_argument("platform", help="the platform to run the tests for", nargs="*")
    parser.add_argument(
        "-l",
        "--list",
        help="list the supported platforms",
        action="store_true",
        dest="list_platforms",
    )
    args = parser.parse_args(argv)
    if not args.list_platforms and not args.platform:
        parser.print_help()
    return args


def list_platforms():
    print("Supported platforms are:")
    print(tabulate(PLATFORMS.items()))


def _sanitize_platform_arguments(platforms):
    platforms = set(platforms)
    if "all" in platforms:
        return tuple(PLATFORMS.keys())
    return tuple(p for p in platforms if p in PLATFORMS.keys())


def run_platform_tests(platforms):
    for platform in platforms:
        run_platform_test(platform)


def run_platform_test(platform):
    results = dict()
    logfile = f"{LOG_FILE_NAME_PREFIX}-{platform}.log"
    resultsfile = f"{LOG_FILE_NAME_PREFIX}-{platform}.results"
    with open(logfile, "w") as log:
        with virtual_machine(platform, log):
            results["build"] = run_build_test(platform, log)
            results["unit"] = run_unit_tests(platform, log)
            results["system"] = run_system_tests(platform, log)
            results["crypto"] = run_crypto_tests(platform, log)
    with open(resultsfile, "w") as f:
        json.dump(results, f)


def run_build_test(platform, log):
    test_command = [
        "vagrant",
        "ssh",
        platform,
        "-c",
        "/home/vagrant/pcapfs/tests/build/build-pcapfs.sh",
    ]
    return _run_test(platform, log, test_command, test_name="build")


def run_system_tests(platform, log):
    if platform == "centos-7":
        package_manager = "yum"
    elif platform.startswith("fedora"):
        package_manager = "dnf"
    else:
        package_manager = "apt"
    try:
        subprocess.check_call(
            [
                "vagrant",
                "ssh",
                platform,
                "-c",
                "sudo " + package_manager + " -y install python3-pip",
            ],
            stdout=log,
            stderr=log,
        )
        subprocess.check_call(
            ["vagrant", "ssh", platform, "-c", "pip install pytest virtualenv"],
            stdout=log,
            stderr=log,
        )
    except subprocess.CalledProcessError:
        pass
    test_command = [
        "vagrant",
        "ssh",
        platform,
        "-c",
        "/home/vagrant/pcapfs/tests/system/run-system-tests.sh vagrant",
    ]
    return _run_test(platform, log, test_command, test_name="system")


def run_crypto_tests(platform, log):
    test_command = [
        "vagrant",
        "ssh",
        platform,
        "-c",
        "/home/vagrant/pcapfs/tests/crypto/run-crypto-tests.sh vagrant",
    ]
    return _run_test(platform, log, test_command, test_name="crypto")


def run_unit_tests(platform, log):
    test_command = [
        "vagrant",
        "ssh",
        platform,
        "-c",
        "make -C /home/vagrant/pcapfs/ unittests",
    ]
    return _run_test(platform, log, test_command, test_name="unit")


def _run_test(platform, log, command, test_name):
    start_time = datetime.datetime.now()
    passed = False
    try:
        subprocess.check_call(command, stdout=log, stderr=log)
        passed = True
    except subprocess.CalledProcessError:
        pass
    test_time = _format_test_time(datetime.datetime.now() - start_time)
    now = datetime.datetime.now().strftime("%F %T")
    print(
        f"[{now} | {platform} | {test_name:6s} | {test_time} | {_get_status_string(passed)}]"
    )
    return {"passed": passed, "time": test_time}


def _get_status_string(passed):
    if passed:
        return STATUS_PASS_STRING
    else:
        return STATUS_FAIL_STRING


def _format_test_time(delta):
    delta += datetime.timedelta(seconds=round(delta.microseconds / 1e6))
    return str(delta).split(".")[0]


@contextmanager
def virtual_machine(platform, log):
    print(
        f'[{datetime.datetime.now().strftime("%F %T")} | {platform} | test initialization]'
    )
    try:
        subprocess.check_call(["vagrant", "up", platform], stdout=log, stderr=log)
        yield
    finally:
        print(
            f'[{datetime.datetime.now().strftime("%F %T")} | {platform} | test cleanup]'
        )
        subprocess.check_call(
            ["vagrant", "destroy", "-f", platform], stdout=log, stderr=log
        )


if __name__ == "__main__":
    sys.exit(main())
