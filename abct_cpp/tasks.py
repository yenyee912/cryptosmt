import invoke
import os
import shutil
import glob


def print_banner(msg):
    print("==================================================")
    print("= {} ".format(msg))


@invoke.task
def clean(c):
    """Remove any built objects"""
    for file_pattern in (
        "*.o",
        "*.so",
        "*.obj",
        "*.dll",
        "*.exp",
        "*.lib",
        "*.pyd",
    ):
        for file in glob.glob(file_pattern):
            os.remove(file)
    for dir_pattern in "Release":
        for dir in glob.glob(dir_pattern):
            shutil.rmtree(dir)


@invoke.task()
def test_abct(c):
    print_banner("run the python call cpp script...")
    invoke.run("python3 call_abct.py", pty=True)


@invoke.task()
def build_abct(c):
    print_banner("building C++ abct code")
    invoke.run(
        "g++ -O3 -Wall -Werror -shared -std=c++14 -fPIC abct_prob.cpp -o abct_prob.o "
    )
    print("build complete, abct code updated.")


@invoke.task(
    clean,
    build_abct,
    test_abct,
)
def all(c):
    pass
