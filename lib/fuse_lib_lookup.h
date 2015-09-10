/*/////////////////////////////////////////////////////////////////////////
    do_lookup state machine
state       CREATED  FGETS_SENT  GETS_SENT SUCCEDED FAILED     
cmd_send
cmd_accpted

/////////////////////////////////////////////////////////////////////////*/

static int lookup_path1(struct fuse *f, fuse_ino_t nodeid,
                        const char *name, const char *path,
                        struct fuse_entry_param *e, struct fuse_file_info *fi)
{
    int res;

    memset(e, 0, sizeof(struct fuse_entry_param));
    if (fi)
        res = fuse_fs_fgetattr(f->fs, path, &e->attr, fi);
    else
        res = fuse_fs_getattr(f->fs, path, &e->attr);
    if (res == 0) {
        res = do_lookup(f, nodeid, name, e);
        if (res == 0 && f->conf.debug) {
            fprintf(stderr, "   NODEID: %llu\n",
                (unsigned long long) e->ino);
        }
    }
    return res;
}

static void fuse_lib_lookup(fuse_req_t req, fuse_ino_t parent,
                            const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *path;
    int err;
    struct node *dot = NULL;

    if (name[0] == '.' ) {
        int len = strlen(name);
        if (len == 1 || (name[1] == '.' && len == 2)) {
            pthread_mutex_lock(&f->lock);
            if (len == 1) {
                if (f->conf.debug)
                    fprintf(stderr, "LOOKUP-DOT\n");
                dot = get_node_nocheck(f, parent);
                if (dot == NULL) {
                    pthread_mutex_unlock(&f->lock);
                    reply_entry(req, &e, -ESTALE);
                    return;
                }
                dot->refctr++;
            } else {
                if (f->conf.debug)
                    fprintf(stderr, "LOOKUP-DOTDOT\n");
                parent = get_node(f, parent)->parent->nodeid;
            }
            pthread_mutex_unlock(&f->lock);
            name = NULL;
        }
    }

    err = get_path_name(f, parent, name, &path);
    if (!err) {
        struct fuse_intr_data d;
        if (f->conf.debug)
            fprintf(stderr, "LOOKUP %s\n", path);
        fuse_prepare_interrupt(f, req, &d);
        err = lookup_path1(f, parent, name, path, &e, NULL);


        if (err == -ENOENT && f->conf.negative_timeout != 0.0) {
            e.ino = 0;
            e.entry_timeout = f->conf.negative_timeout;
            err = 0;
        }
        fuse_finish_interrupt(f, req, &d);
        free_path(f, parent, path);
    }
    if (dot) {
        pthread_mutex_lock(&f->lock);
        unref_node(f, dot);
        pthread_mutex_unlock(&f->lock);
    }
    reply_entry(req, &e, err);
}
