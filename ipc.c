#include "ipc.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

int get_sock_path_for_user(char *dest, int dest_len) {
  int len =
      snprintf(dest, dest_len, "/var/run/user/%u/encrypted-shadow", getuid());
  if (len >= dest_len) {
    errno = ENOMEM;
    return -1;
  }
  return 0;
}

static const msg_info_t INVALID_MSG = {MSG_INVALID, 0};

int msg_content_length(msg_info_t info) {
  switch (info.kind) {
  case MSG_HASH_FINALIZE:
  case MSG_CLEAR_SECRET:
  case MSG_NOT_AUTHENTICATED:
  case MSG_AUTHENTICATED:
    return 0;
  case MSG_AUTHENTICATE:
  case MSG_HASH_FINALIZED:
  case MSG_HASH_DATA:
    return 1;
  case MSG_PEER_EOF:
  case MSG_INVALID:
    break;
    break;
  }
  errno = EINVAL;
  return -1;
}

int recv_peer_msg(int sock, msg_info_t *info, msg_context_t data[2]) {
  struct msghdr msg = {0};
  struct iovec iov[1];

  ssize_t nbytes;
  int i, *p;
  char buf[CMSG_SPACE(sizeof(msg_context_t) * 3)] = {
      0x0d}; // TODO: WTF is this magic number?
  struct cmsghdr *cmsghdr = (struct cmsghdr *)buf;

  msg_info_t msgs[1] = {0};

  iov[0].iov_base = msgs;
  iov[0].iov_len = sizeof(msgs);

  msg.msg_iov = iov;
  msg.msg_iovlen = ARR_LEN(iov);
  msg.msg_control = cmsghdr;
  msg.msg_controllen = CMSG_LEN(sizeof(msg_context_t) * 3);
  msg.msg_flags = 0;

  {
    auto hdr = CMSG_FIRSTHDR(&msg);
    while (true) {
      hdr->cmsg_len = CMSG_LEN(sizeof(msg_context_t));
      hdr->cmsg_level = SOL_SOCKET;
      hdr->cmsg_type = SCM_RIGHTS;
      if (!(hdr = CMSG_NXTHDR(&msg, hdr))) {
          break;
      }
    }
  }

  PROP_ERR(nbytes = recvmsg(sock, &msg, 0));
  msg_info_t msg_kind = msgs[0];
  if (nbytes == 0) {
      return 0;
  } else if (nbytes < sizeof(msg_info_t)) {
      errno = EINVAL;
      return -1;
  } else if (msg_kind.kind == 0) {
      errno = EINVAL;
      return -1;
  }
  auto hdr = CMSG_FIRSTHDR(&msg);
  msg_context_t *hdr_fst = (msg_context_t *)CMSG_DATA(hdr);
  int context_len;
  PROP_ERR(context_len = msg_content_length(msg_kind));
  for (int i = 0; i < context_len; ++i) {
    if (hdr == NULL) {
      errno = EINVAL;
      return -1;
    }
    msg_context_t *pkg = (msg_context_t *)CMSG_DATA(hdr);
    (data[i]) = *pkg;
    hdr = CMSG_NXTHDR(&msg, hdr);
  }

  *info = msg_kind;
  return 1;
}

int send_peer_msg(int sock, msg_info_t info, msg_context_t context[],
                  int context_len, int options) {
  struct msghdr msg = {0};
  struct iovec iov[1];

  assert(context_len == msg_content_length(info));

  ssize_t nbytes;
  int i, *p;
  char buf[CMSG_SPACE(sizeof(msg_context_t) * 3)] = {
      0x0d}; // TODO: WTF is this magic number?
  struct cmsghdr *cmsghdr = (struct cmsghdr *)buf;

  msg_info_t msgs[1] = {info};

  iov[0].iov_base = msgs;
  iov[0].iov_len = sizeof(msgs);

  msg.msg_iov = iov;
  msg.msg_iovlen = ARR_LEN(iov);
  if (context_len > 0) {
  msg.msg_control = cmsghdr;
  msg.msg_controllen = CMSG_LEN(sizeof(msg_context_t) * context_len);
  } else {
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  }
  msg.msg_flags = 0;
  {
    auto hdr = CMSG_FIRSTHDR(&msg);
    for (int i = 0; i < context_len; ++i) {
        msg_context_t *m = (msg_context_t *)CMSG_DATA(hdr);
        hdr->cmsg_len = CMSG_LEN(sizeof(msg_context_t));
        hdr->cmsg_level = SOL_SOCKET;
        hdr->cmsg_type = SCM_RIGHTS;
        *m = context[i];
        if (!(hdr = CMSG_NXTHDR(&msg, hdr))) {
            break;
        }
    }
  }

  PROP_ERR(nbytes = sendmsg(sock, &msg, options));
  return nbytes;
}

// int recv_peer_msg(int sock, peer_request_t *request) {}
