#pragma once
static void fuse_do_release(struct fuse *f, fuse_ino_t ino, const char *path,
struct fuse_file_info *fi)
{
    struct node *node;
    int unlink_hidden = 0;

    fuse_fs_release(f->fs, path, fi);

    pthread_mutex_lock(&f->lock);
    node = get_node(f, ino);
    assert(node->open_count > 0);
    --node->open_count;
    if (node->is_hidden && !node->open_count) {
        unlink_hidden = 1;
        node->is_hidden = 0;
    }
    pthread_mutex_unlock(&f->lock);

    if(unlink_hidden) {
        if (path) {
            fuse_fs_unlink(f->fs, path);
        } else if (f->conf.nopath) {
            char *unlinkpath;

            if (get_path(f, ino, &unlinkpath) == 0)
                fuse_fs_unlink(f->fs, unlinkpath);

            free_path(f, ino, unlinkpath);
        }
    }
}

