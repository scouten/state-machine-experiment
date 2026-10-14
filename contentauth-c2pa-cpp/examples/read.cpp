// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// The simplest use: read one file, blocking, and print what was found.
//
//   c2pa_sm_read photo.jpg [image/jpeg]

#include <cstdio>
#include <string>

#include "contentauth/c2pa_sm.hpp"

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s FILE [MIME-TYPE]\n", argv[0]);
        return 2;
    }
    try {
        c2pa::sm::FileHost host(argv[1]);
        auto reader = c2pa::sm::read(c2pa::sm::Session(argc > 2 ? argv[2] : "image/jpeg"), host);
        if (!reader) {
            std::printf("no Content Credentials\n");
            return 1;
        }
        std::printf("active manifest: %s\n", reader->active_label().value_or("(none)").c_str());
        std::printf("%s\n", reader->json().c_str());
        return 0;
    } catch (const c2pa::sm::Exception &e) {
        std::fprintf(stderr, "%s (%s)\n", e.what(), e.name().c_str());
        return 2;
    }
}
