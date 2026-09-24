#!/usr/bin/env python3
"""Fail on a thread_local whose type has a non-trivial destructor (spec 088).

A thread_local object is destroyed when its thread ends. On MinGW (winpthreads' emulated TLS) that
destructor ran on storage already freed: a DuckDB worker thread joined by ~DatabaseInstance crashed in
~deque, about one run in thirty, and only on that platform (2026-09-22, 2026-09-24). The rule is
mechanical, so a machine enforces it: a thread_local is a pointer, a flag, a number or a char buffer -
a heap object it points to is the owner's to free.
"""
import glob
import re
import sys

TRIVIAL = {"bool", "char", "int", "unsigned", "long", "size_t", "idx_t", "int8_t", "int16_t", "int32_t",
           "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "double", "float"}
DECL = re.compile(r"\bthread_local\s+([^;={(]+?)\s*(?:=[^;]*)?;")

bad = []
for path in sorted(glob.glob("src/**/*.cpp", recursive=True) + glob.glob("src/**/*.hpp", recursive=True)):
    for number, line in enumerate(open(path, encoding="utf-8"), 1):
        code = line.split("//", 1)[0]
        match = DECL.search(code)
        if not match:
            continue
        decl = match.group(1)  # the type and the name, e.g. `std::deque<X> *pending` or `char buf[32]`
        if "*" in decl:
            continue  # a pointer: nothing to destroy
        decl_no_array = re.sub(r"\[[^\]]*\]", "", decl)  # `char buf[32]` -> `char buf`
        words = [w for w in decl_no_array.replace("static", " ").replace("const", " ").split() if w]
        type_words = words[:-1]  # the last word is the name
        if type_words and all(w in TRIVIAL or w.isdigit() for w in type_words):
            continue
        bad.append(f"{path}:{number}: thread_local `{decl.strip()}` has a non-trivial destructor")

if bad:
    print("\n".join(bad))
    print("A thread_local must be a pointer, a flag, a number or a char buffer (spec 088: MinGW destroys it "
          "on freed storage at thread exit).")
    sys.exit(1)
print("thread_local: every one is trivially destructible")
