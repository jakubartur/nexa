#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import shutil
PROJECT_NAME = "rostrum"
GIT_REPO = "https://gitlab.com/BitcoinUnlimited/{}.git".format(PROJECT_NAME)
# When released put a tag here 'v2.0.0'
# When in development, put 'master' here.
GIT_BRANCH = "master"
# When released put a hash here: "aa95d64d050c286356dadb78d19c2e687dec85cf"
# When in development, put 'None' here
EXPECT_HEAD = None

ROOT_DIR = os.path.realpath(
        os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
ROSTRUM_DIR = os.path.join(ROOT_DIR, PROJECT_NAME)
ROSTRUM_BIN = "rostrum"

parser = argparse.ArgumentParser()
parser.add_argument('--allow-modified', help='Allow building modified/dirty repo',
        action = "store_true")
parser.add_argument('--verbose', help='Sets log level to DEBUG',
        action = "store_true")
parser.add_argument('--dst', help='Where to copy produced binary',
    default=os.path.join(ROOT_DIR, "src"))
parser.add_argument('--target', help='Target platform (e.g. x86_64-pc-linux-gnu)',
    default="x86_64-unknown-linux-gnu")
parser.add_argument('--debug', help="Do a debug build", action = "store_true")
parser.add_argument('--builddir', help="Out of source build directory", default=None)
args = parser.parse_args()

level = logging.DEBUG if args.verbose else logging.INFO

logging.basicConfig(format = '%(asctime)s.%(levelname)s: %(message)s',
        level=level,
        stream=sys.stdout)

def bail(*args):
    logging.error(*args)
    sys.exit(1)

def check_dependencies():
    v = sys.version_info
    if v[0] < 3 or (v[0] == 3 and v[1] < 3):
        bail("python >= 3.3 required");

    try:
        import git
    except Exception as e:
        logging.error("Failed to 'import git'")
        logging.error("Tip: Install with: python3 -m pip install gitpython")
        logging.error("Tip: On Debian/Ubuntu you can install python3-git")
        bail(str(e))

    import shutil
    if shutil.which("cargo") is None:
        logging.error("Cannot find 'cargo', will not be able to build {}".format(PROJECT_NAME))
        logging.error("You need to install rust (1.38+) https://rustup.rs/")
        logging.error("Tip: On Debian/Ubuntu you need to install cargo")
        bail("rust not found")

    if shutil.which("clang") is None:
        logging.error("Cannot find 'clang', will not be able to build {}".format(PROJECT_NAME))
        logging.error("Tip: On Debian/Ubuntu you need to install clang")
        bail("clang not found")

    if not os.path.isdir(args.dst):
        bail("--dst provided '%s' is not a directory", args.dst)

def clone_repo():
    import git
    logging.info("Cloning %s to %s", GIT_REPO, ROSTRUM_DIR)
    repo = git.Repo.clone_from(GIT_REPO, ROSTRUM_DIR, branch=GIT_BRANCH)

def verify_repo(allow_modified):
    import git
    repo = git.Repo(ROSTRUM_DIR)
    if repo.is_dirty():
        logging.error("Validation failed - %s has local modifications. Use `--allow-modified` if you wanted to build from a dirty repository", ROSTRUM_DIR)
        allow_modified or bail("Bailing")

    if EXPECT_HEAD == None:
        logging.warning("Rostrum is not fixed to a specific revision.  Please assign the EXPECT_HEAD variable in build_rostrum.py before releasing.")
    if EXPECT_HEAD != None and repo.head.object.hexsha != EXPECT_HEAD:
        # TODO: Add command line option to reset HEAD to GIT_BRANCH at EXPECT_HEAD
        logging.error("Validation failed - %s HEAD differs from expected (%s vs %s)",
                PROJECT_NAME, repo.head.object.hexsha, EXPECT_HEAD)
        allow_modified or bail("Bailing")

def output_reader(pipe, queue):
    try:
        with pipe:
            for l in iter(pipe.readline, b''):
                queue.put(l)
    finally:
        queue.put(None)

def cargo_run(args):
    import subprocess
    from threading import Thread
    from queue import Queue

    cargo = shutil.which("cargo")
    args = [cargo] + args
    logging.info("Running %s", args)
    assert cargo is not None

    cargo_env = os.environ.copy()
    if 'CARGO_HOME' in cargo_env:
        logging.info("CARGO_HOME is set to {}".format(cargo_env['CARGO_HOME']))

    p = subprocess.Popen(args, cwd = ROSTRUM_DIR,
        stdout = subprocess.PIPE, stderr = subprocess.PIPE,
        env = cargo_env)

    q = Queue()
    Thread(target = output_reader, args = [p.stdout, q]).start()
    Thread(target = output_reader, args = [p.stderr, q]).start()

    for line in iter(q.get, None):
        logging.info(line.decode('utf-8').rstrip())

    p.wait()
    rc = p.returncode
    assert rc is not None
    if rc != 0:
        bail("cargo failed with return code %s", rc)

def get_target(makefile_target):
    # Try to map target passed from makefile to the equalent in rust
    # To see supported targets, run: rustc --print target-list

    # Trim away darwin version number
    if makefile_target.startswith('x86_64-apple-darwin'):
        makefile_target = 'x86_64-apple-darwin'

    target_map = {
            'x86_64-pc-linux-gnu' : 'x86_64-unknown-linux-gnu',
            'i686-pc-linux-gnu' : 'i686-unknown-linux-gnu',
            'x86_64-apple-darwin': 'x86_64-apple-darwin'
    }

    if makefile_target in target_map:
        return target_map[makefile_target]

    if makefile_target in target_map.values():
        return makefile_target

    logging.warn("Target %s is not mapped, passing it rust and hoping it works"
            % makefile_target)
    return makefile_target


check_dependencies()

if not os.path.exists(ROSTRUM_DIR):
    clone_repo()
verify_repo(args.allow_modified)

def build_flags(debug, target, builddir):
    flags = ["--target={}".format(get_target(target))]
    if builddir is not None:
        flags.append("--target-dir={}".format(os.path.abspath(builddir)))
    if debug:
        return flags
    return flags + ["--release"]

cargo_run(["build", "--verbose", "--locked", "--features=nexa"] + build_flags(args.debug, args.target, args.builddir))
cargo_run(["test", "--verbose", "--locked", "--features=nexa"] + build_flags(args.debug, args.target, args.builddir))

def build_type_dir(debug):
    if debug:
        return "debug"
    return "release"

def binary_dir(target, debug, builddir):
    """
    The directory where the rostrum binaries are built.
    """
    root = builddir if builddir is not None else os.path.join(ROSTRUM_DIR, "target")
    return os.path.join(root, get_target(target), build_type_dir(debug))

src = os.path.join(binary_dir(args.target, args.debug, args.builddir), ROSTRUM_BIN)
logging.info("Copying %s to %s", src, args.dst)
shutil.copy(src, args.dst)

logging.info("Done")
