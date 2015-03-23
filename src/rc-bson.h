#ifndef RC_BSON_H
#define RC_BSON_H

#define RC_BSON_MAGIC 0x1234
#define RC_BSON_VERSION 1

struct bufferevent;

void rc_bson_read(struct bufferevent *bev);

#endif // RC_BSON_H



