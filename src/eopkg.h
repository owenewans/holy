#ifndef HOLY_EOPKG_H
#define HOLY_EOPKG_H

/* converts one Solus eopkg into a native package. the artifact is a ZIP carrying
   metadata.xml, files.xml and an install tar; the metadata is read as XML text, the
   tar is read with libarchive, and nothing in it is executed: a Solus package also
   ships a COMAR lifecycle and an install batch this manager does not run. */
int holy_import_eopkg(const char *input, const char *source, const char *output);

#endif
