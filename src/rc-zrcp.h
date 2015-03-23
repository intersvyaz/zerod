#ifndef RC_ZRCP_H
#define RC_ZRCP_H

#define RC_ZRCP_MAGIC     0x5a52 // 'ZR'

struct bufferevent;

void rc_zrcp_read(struct bufferevent *bev);

#endif // RC_ZRCP_H
