#include "fuse_prv.h"
#include "fuse_id_hash.h"

size_t id_hash( struct fuse *f, fuse_ino_t ino )
{
    uint64_t hash = ((uint32_t) ino * 2654435761U) % f->id_table.size;
    uint64_t oldhash = hash % (f->id_table.size / 2);

    if (oldhash >= f->id_table.split)
        return oldhash;
    else
        return hash;
}
