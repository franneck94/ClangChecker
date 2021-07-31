"""
A script that runs clang-format on all C/C++ files.
"""

import argparse
import asyncio
import os
import re
import subprocess
import sys
from typing import List, Sequence
from typing import Set


CLANG_FORMAT_EXE = "clang-format"

CPP_FILE_REGEX = re.compile(".*\\.(h|hh|hpp|hxx|c|cc|cpp|cxx)$")


def get_whitelisted_files(paths: List[str]) -> Set[str]:
    """
    Resolve all directories. Returns the set of whitelist cpp source files.
    """
    matches = []
    for dir in paths:
        for root, _, filenames in os.walk(dir):
            for filename in filenames:
                if CPP_FILE_REGEX.match(filename):
                    matches.append(os.path.join(root, filename))
    return set(matches)


async def run_clang_format_on_file(
    filename: str, semaphore: asyncio.Semaphore, verbose: bool = False
) -> None:
    """
    Run clang-format on the provided file.
    """
    cmd = f"{CLANG_FORMAT_EXE} -style=file -i {filename}"
    async with semaphore:
        proc = await asyncio.create_subprocess_shell(cmd)
        _ = await proc.wait()
    if verbose:
        print(f"Formatted {filename}")


async def file_clang_formatted_correctly(
    filename: str, semaphore: asyncio.Semaphore, verbose: bool = False
) -> bool:
    """
    Checks if a file is formatted correctly and returns True if so.
    """
    ok = True
    # -style=file picks up the closest .clang-format
    cmd = f"{CLANG_FORMAT_EXE} -style=file {filename}"

    async with semaphore:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE
        )
        # Read back the formatted file.
        stdout, _ = await proc.communicate()

    formatted_contents = stdout.decode()
    # Compare the formatted file to the original file.
    with open(filename) as orig:
        orig_contents = orig.read()
        if formatted_contents != orig_contents:
            ok = False
            if verbose:
                print(f"{filename} is not formatted correctly")

    return ok


async def run_clang_format(
    paths: List[str],
    max_processes: int,
    diff: bool = False,
    verbose: bool = False,
) -> bool:
    """
    Run clang-format to all files.
    """
    # Check to make sure the clang-format binary exists.
    return_code = subprocess.run(
        f'{CLANG_FORMAT_EXE} --help', stdout=subprocess.DEVNULL
    )
    if not return_code:
        print("clang-format binary not found")
        return False

    # Gather command-line options for clang-format.
    args = [CLANG_FORMAT_EXE, "-style=file"]

    if not diff:
        args.append("-i")

    ok = True

    # Semaphore to bound the number of subprocesses that can be created at once
    semaphore = asyncio.Semaphore(max_processes)

    # Format files in parallel.
    if diff:
        for f in asyncio.as_completed(
            [
                file_clang_formatted_correctly(f, semaphore, verbose)
                for f in get_whitelisted_files(paths)
            ]
        ):
            ok &= await f

        if ok:
            print("All files formatted correctly")
        else:
            print("Some files not formatted correctly")
    else:
        await asyncio.gather(
            *[
                run_clang_format_on_file(f, semaphore, verbose)
                for f in get_whitelisted_files(paths)
            ]
        )
    return ok


def parse_args(args: Sequence[str]) -> argparse.Namespace:
    """
    Parse and return command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Execute clang-format on your working copy changes."
    )
    parser.add_argument(
        "-d",
        "--diff",
        default=False,
        help="Determine whether running clang-format would produce changes",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        default=False,
        help="Determine whether running clang-format would produce stdout",
    )
    parser.add_argument(
        "--max-processes",
        type=int,
        default=4,
        help="Maximum number of subprocesses to format files in parallel",
    )
    parser.add_argument(
        "-p",
        "--paths",
        nargs="+",
        default=["."],
        help="Format only the given paths (recursively)",
    )

    return parser.parse_args(args)


def main(args: Sequence[str]) -> int:
    # Parse arguments.
    options = parse_args(args)
    # Invoke clang-format on all files in the directories in the whitelist.
    ok = asyncio.run(
        run_clang_format(
            options.paths, options.max_processes, options.diff, options.verbose
        )
    )
    # We have to invert because False -> 0, which is the code to be returned
    return not ok


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
