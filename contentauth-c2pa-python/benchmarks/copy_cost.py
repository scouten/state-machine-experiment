"""Measures what the copies cost, to decide whether lease-backed buffers are worth having.

    .venv/bin/python benchmarks/copy_cost.py [--megabytes 128] [--rounds 25]

It signs a large JPEG file (the fixture with many large COM segments inserted) and
compares, interleaved and in shuffled order each round so that ordering and filesystem
noise cannot favour a variant:

* the shipped blocking driver (`drive_build` over `FileBuildHost`);
* a hand-written loop over the raw C API with **no** leases: the control, showing what the
  Python driver itself costs;
* the same loop with read leases (`preadv` straight into engine-owned storage), write
  leases (`pwrite` straight from engine-owned storage), and both.

The raw loops use private modules and exist only to measure; they are not an API. Numbers
depend on the machine, the filesystem and a warm page cache, so compare variants within
one run, never across runs.
"""

import argparse
import gc
import os
from pathlib import Path
import random
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

import contentauth_c2pa as c2pa  # noqa: E402
from contentauth_c2pa import build as build_module  # noqa: E402
from contentauth_c2pa._native import ffi, lib  # noqa: E402
from contentauth_c2pa._support import check  # noqa: E402
from support import CERTIFICATE, JPEG, baseline_definition, es256_sign  # noqa: E402


def large_jpeg(megabytes: int) -> bytes:
    """The fixture JPEG with many 64 KiB COM segments inserted after SOI: valid and large."""
    segment = b"\xff\xfe" + (65535).to_bytes(2, "big") + os.urandom(65533)
    return JPEG[:2] + segment * (megabytes * 1024 * 1024 // 65535) + JPEG[2:]


def raw_loop(source: Path, destination: Path, *, read_leases: bool, write_leases: bool) -> None:
    session = c2pa.BuildSession(baseline_definition(), "image/jpeg", "es256", [CERTIFICATE])
    host = c2pa.FileBuildHost(source, destination, signer=lambda a, data: es256_sign(data))
    try:
        with session._resource.use() as raw:
            done = ffi.new("int *")
            count = ffi.new("uintptr_t *")
            error = ffi.new("C2paSmError **")
            while True:
                check(lib.c2pa_sm_build_session_advance(raw, done, count, error), error)
                if done[0]:
                    break
                views = []
                for index in range(int(count[0])):
                    view = ffi.new("C2paSmBuildRequest *")
                    check(lib.c2pa_sm_build_session_request(raw, index, view, error), error)
                    views.append(view)
                for view in views:
                    kind, request_id = int(view.kind), int(view.id)
                    if kind == lib.C2PA_SM_BUILD_REQUEST_READ and read_leases:
                        descriptor = host._descriptor(build_module.stream_of(int(view.stream)))
                        length, offset = int(view.len), int(view.offset)
                        lease = ffi.new("C2paSmReadBuffer **")
                        writable = ffi.new("C2paSmMutableBytes *")
                        check(lib.c2pa_sm_build_read_acquire(raw, request_id, lease, writable, error), error)
                        target = memoryview(ffi.buffer(writable.data, writable.len))
                        got = 0
                        while got < length:
                            got += os.preadv(descriptor, [target[got:]], offset + got)
                        completed = ffi.new("C2paSmCompletedRead **")
                        check(lib.c2pa_sm_read_seal(lease, length, completed, error), error)
                        check(lib.c2pa_sm_build_fulfill_read(raw, request_id, completed, error), error)
                    elif kind == lib.C2PA_SM_BUILD_REQUEST_WRITE and write_leases:
                        lease = ffi.new("C2paSmWriteBuffer **")
                        readable = ffi.new("C2paSmBuffer *")
                        check(lib.c2pa_sm_build_write_acquire(raw, request_id, lease, readable, error), error)
                        payload = memoryview(ffi.buffer(readable.data, readable.len))
                        put = 0
                        while put < len(payload):
                            put += os.pwrite(host._output_fd, payload[put:], int(view.offset) + put)
                        reply, keep = build_module.encode_reply(request_id, c2pa.Written())
                        check(lib.c2pa_sm_build_session_fulfill(raw, reply, error), error)
                        check(lib.c2pa_sm_write_buffer_free(lease, error), error)
                    else:
                        reply, keep = build_module.encode_reply(
                            request_id, c2pa.answer_build(host, build_module.describe(view))
                        )
                        check(lib.c2pa_sm_build_session_fulfill(raw, reply, error), error)
        session._resource.close()
        host.publish()
    finally:
        host.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--megabytes", type=int, default=128)
    parser.add_argument("--rounds", type=int, default=25)
    arguments = parser.parse_args()

    data = large_jpeg(arguments.megabytes)
    directory = Path(tempfile.mkdtemp())
    source = directory / "in.jpg"
    source.write_bytes(data)
    signer = lambda algorithm, payload: es256_sign(payload)  # noqa: E731

    def driver() -> None:
        session = c2pa.BuildSession(baseline_definition(), "image/jpeg", "es256", [CERTIFICATE])
        with c2pa.FileBuildHost(source, directory / "driver.jpg", signer=signer) as host:
            c2pa.drive_build(session, host)
            host.publish()

    variants = {
        "shipped driver": driver,
        "raw loop, no leases (control)": lambda: raw_loop(source, directory / "a.jpg", read_leases=False, write_leases=False),
        "raw loop, read leases": lambda: raw_loop(source, directory / "b.jpg", read_leases=True, write_leases=False),
        "raw loop, write leases": lambda: raw_loop(source, directory / "c.jpg", read_leases=False, write_leases=True),
        "raw loop, both leases": lambda: raw_loop(source, directory / "d.jpg", read_leases=True, write_leases=True),
    }
    for variant in variants.values():  # also proves each variant works, and warms the cache
        variant()
    outputs = {(directory / name).read_bytes() for name in ("driver.jpg", "a.jpg", "b.jpg", "c.jpg", "d.jpg")}
    assert len(outputs) == 1, "every variant must produce the same signed asset"

    times: dict[str, list[float]] = {name: [] for name in variants}
    random.seed(1)
    for _ in range(arguments.rounds):
        order = list(variants)
        random.shuffle(order)
        for name in order:
            gc.collect()
            started = time.perf_counter()
            variants[name]()
            times[name].append((time.perf_counter() - started) * 1e3)

    control = statistics.median(times["raw loop, no leases (control)"])
    print(f"signing a {len(data) / 1e6:.0f} MB file, {arguments.rounds} interleaved rounds")
    print(f"{'variant':32}{'median':>10}{'p25':>9}{'p75':>9}{'vs control':>12}")
    for name, samples in times.items():
        p25, _, p75 = statistics.quantiles(samples, n=4)
        median = statistics.median(samples)
        print(f"{name:32}{median:9.1f}ms{p25:7.1f}ms{p75:7.1f}ms{median / control * 100 - 100:+11.1f}%")


if __name__ == "__main__":
    main()
