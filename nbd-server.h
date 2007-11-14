/*
 * nbd-server.h -- stuff that needs to be accessible from all nbd-server source files
 */
extern void myseek(int handl, off_t a);
extern inline void writeit(int f, void *buf, size_t len);
extern ssize_t backend_send(int fh, int net, off_t offset, size_t len);
