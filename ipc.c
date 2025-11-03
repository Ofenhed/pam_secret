#include "ipc.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

inline const char *get_socket_name() { return "encrypted-shadow"; }

int msg_has_fd(msg_info_t info) {
  switch (info.kind) {
  case MSG_HASH_FINALIZE:
  case MSG_CLEAR_SECRET:
  case MSG_NOT_AUTHENTICATED:
  case MSG_UNKNOWN_ERROR:
#ifdef DEBUG_QUERY_SECRETS
  case MSG_DUMP_SECRET:
#endif
    return 0;
  case MSG_AUTHENTICATE:
  case MSG_AUTHENTICATED:
  case MSG_HASH_FINALIZED:
  case MSG_HASH_DATA:
  case MSG_UPDATE_PASSWORD_SUCCESS:
  case MSG_UPDATE_PASSWORD:
    return 1;
  case MSG_PEER_EOF:
  case MSG_INVALID:
    break;
  }
  errno = EINVAL;
  return -1;
}

int recv_peer_msg(int sock, msg_info_t *info, int *_Nullable fd) {
  struct msghdr msg = {0};
  struct iovec iov[1];

  ssize_t nbytes;
  char buf[CMSG_SPACE(sizeof(int))] = {0x0d}; // TODO: WTF is this magic number?
  struct cmsghdr *cmsghdr = (struct cmsghdr *)buf;

  msg_info_t msgs[1] = {0};

  iov[0].iov_base = msgs;
  iov[0].iov_len = sizeof(msgs);

  msg.msg_iov = iov;
  msg.msg_iovlen = ARR_LEN(iov);
  msg.msg_control = cmsghdr;
  msg.msg_controllen = CMSG_LEN(sizeof(int));
  msg.msg_flags = 0;

  {
    auto hdr = CMSG_FIRSTHDR(&msg);
    while (true) {
      hdr->cmsg_len = CMSG_LEN(sizeof(int));
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
  } else if (nbytes < 0 || (size_t)nbytes < sizeof(msg_info_t)) {
    errno = EINVAL;
    return -1;
  } else if (msg_kind.kind == MSG_PEER_EOF) {
    errno = EINVAL;
    return -1;
  }

  if (fd != NULL)
    *fd = -1;

  auto hdr = CMSG_FIRSTHDR(&msg);
  if (hdr != NULL) {
    if (hdr->cmsg_type != SCM_RIGHTS) {
      log_warning("Illegal package type %i", hdr->cmsg_type);
    } else {
      int *m = (int *)CMSG_DATA(hdr);
      if (fd == NULL) {
        close(*m);
      } else {
        *fd = *m;
      }
    }
  }

  *info = msg_kind;
  return 1;
}

int send_peer_msg(int sock, msg_info_t info, int *_Nullable fd, int options) {
  struct msghdr msg = {0};
  struct iovec iov[1];

  if ((fd == NULL || *fd == -1) != !msg_has_fd(info)) {
    exit(EXIT_FAILURE);
  }

  ssize_t nbytes;
  char buf[CMSG_SPACE(sizeof(int))] = {0x0d}; // TODO: WTF is this magic number?
  struct cmsghdr *cmsghdr = (struct cmsghdr *)buf;

  msg_info_t msgs[1] = {info};

  iov[0].iov_base = msgs;
  iov[0].iov_len = sizeof(msgs);

  msg.msg_iov = iov;
  msg.msg_iovlen = ARR_LEN(iov);
  if (fd && *fd != -1) {
    msg.msg_control = cmsghdr;
    msg.msg_controllen = CMSG_LEN(sizeof(int));
  } else {
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
  }
  msg.msg_flags = 0;
  {
    auto hdr = CMSG_FIRSTHDR(&msg);
    if (fd && *fd != -1) {
      int *m = (int *)CMSG_DATA(hdr);
      hdr->cmsg_len = CMSG_LEN(sizeof(int));
      hdr->cmsg_level = SOL_SOCKET;
      hdr->cmsg_type = SCM_RIGHTS;
      *m = *fd;
    }
  }

  PROP_ERR(nbytes = sendmsg(sock, &msg, options | MSG_NOSIGNAL));
  return nbytes;
}
