#ifndef HOLY_ARTIFACT_H
#define HOLY_ARTIFACT_H

#include <stddef.h>

/* one verified foreign artifact that becomes a native package. a manifest names the
   artifact with an address and a SHA-256, and the file that carries those bytes sits
   beside the manifest: nothing fetches it, unpacks it or executes it. */

struct holy_artifact {
    /* what the manifest calls itself, and the converter record it keeps */
    const char *family, *converter;
    const char *name, *version;
    const char *url, *hash;
    /* the directory the manifest places the program in, and the program itself */
    const char *directory, *program;
    /* a list of dependencies the manifest names, and what one of them is */
    const char *depends, *dependency_note;
    const char *summary, *homepage, *license;
    /* what the manifest asks Windows for, and what maintains the upstream version */
    size_t installers, integrations, updates, unknown_keys;
    const char *catalog;
};

/* the artifact path beside the manifest, or NULL when the manifest names no file */
char *holy_artifact_beside(const char *input, const char *url);
/* a lowercase sha256 the manifest pins, or NULL when the value is not one */
char *holy_artifact_digest(const char *value);

/* writes a conversion directory holding the original manifest, one native package
   and the package report. returns 0 when the package was written. */
int holy_artifact_package(const char *input, const char *source, const char *output,
                          const struct holy_artifact *fields);

#endif
