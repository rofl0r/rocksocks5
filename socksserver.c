/*
    Copyright (C) 2011-4ever  rofl0r

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
 */

#include <stdio.h>
#include <unistd.h>
#include <grp.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "../rocksock/rocksockserver.h"

// only needed for struct rs_hostInfo
#include "../rocksock/rocksock.h"

#include "../rocksock/endianness.h"

#include "../lib/include/stringptr.h"
#include "../lib/include/strlib.h"
#include "../lib/include/optparser.h"
#include "../lib/include/logger.h"

#ifndef USER_BUFSIZE_KB
#define USER_BUFSIZE_KB 4
#endif

#ifndef USER_MAX_CONN
#define USER_MAX_CONN 32
#endif

#define CLIENT_BUFSIZE (USER_BUFSIZE_KB * 1024)

typedef enum {
	AM_NO_AUTH = 0,
        AM_GSSAPI = 1,
        AM_USERNAME = 2,
	AM_INVALID = 0xFF
} rfc1928_authmethod;

typedef enum {
	EC_SUCCESS = 0,
	EC_GENERAL_FAILURE = 1,
	EC_NOT_ALLOWED = 2,
	EC_NET_UNREACHABLE = 3,
	EC_HOST_UNREACHABLE = 4,
	EC_CONN_REFUSED = 5,
	EC_TTL_EXPIRED = 6,
	EC_COMMAND_NOT_SUPPORTED = 7,
	EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
} rfc1928_errorcode;

typedef enum {
	AT_IPV4 = 1,
	AT_DOMAINNAME = 3,
	AT_IPV6 = 4,
} rfc1928_atyp;

typedef enum {
	BS_UNUSED = 0,
	BS_IDLE,
	BS_READING,
	BS_WRITING
} bufstate;

typedef enum {
	SS_DISCONNECTED = 0,
	SS_SOCKSTARGET,
	SS_CONNECTED,
	SS_AWAITING_AUTH_PACKET,
	SS_AWAITING_DISCONNECT,
	SS_AUTHED,
	SS_AWAITING_PIPE,
	SS_WIRED
} socksstate;

typedef struct {
	size_t start;
	size_t used;
	unsigned char buf[CLIENT_BUFSIZE];
	bufstate state;
} socksbuffer;

typedef struct {
	int target_fd;
	socksbuffer* data;
	socksstate state;
} fdinfo;

typedef struct {
	rocksockserver serva;
	stringptr username;
	stringptr password;
	char _username[256];
	char _password[256];
	socksbuffer clientbuffers[USER_MAX_CONN];
	fdinfo clients[USER_MAX_CONN * 2];
	rfc1928_authmethod accepted_authmethod;
	int log;
} socksserver;

// dont waste buffers for stdin, out, err
#define MAX_FD (3 + (USER_MAX_CONN * 2))
#define fdindex(a) (a - 3)

static void printfd(int fd) {
	log_puts(1, SPLITERAL("["));
	log_putd(1, fd, 1);
	log_puts(1, SPLITERAL("]"));
}

static inline socksbuffer* find_free_buffer(socksserver* srv) {
	size_t i;
	for(i = 0; i < USER_MAX_CONN; i++) {
		if(srv->clientbuffers[i].state == BS_UNUSED) return &srv->clientbuffers[i];
	}
	return NULL;
}

int socksserver_write(socksserver* srv, int fd);

// forced == 1
void socksserver_disconnect_client(socksserver* srv, int fd, int forced) {
	fdinfo* client = &srv->clients[fdindex(fd)];
	int fdflag = 0;
	if(srv->log) {
		printfd(fd);
		log_put(1, VARISL(" disconnect, forced: "), VARII(forced), NULL);
	}
	
	if(forced) rocksockserver_disconnect_client(&srv->serva, fd);
	client->state = SS_DISCONNECTED;
	if(client->data) {
		client->data->state = BS_UNUSED;
		client->data->start = 0;
		client->data->used = 0;
	}
	
	if(client->target_fd != -1) fdflag = 1;
	fd = client->target_fd;
	client->target_fd = -1;
	
	if(fdflag) {
		srv->clients[fdindex(fd)].target_fd = -1;
		socksserver_disconnect_client(srv, fd, 1);
	}
}

int socksserver_on_clientdisconnect (void* userdata, int fd) {
	socksserver* srv = (socksserver*) userdata;
//	fdinfo* client = &srv->clients[fdindex(fd)];
	//if(client->target_fd != -1) socksserver_disconnect_client(srv, client->target_fd, 0);
	socksserver_disconnect_client(srv, fd, 0);
	return 0;
}

static char* get_client_ip(struct sockaddr_storage* ip, char* buffer, size_t bufsize) {
#ifndef IPV4_ONLY
	if(ip->ss_family == PF_INET)
	return (char*) inet_ntop(PF_INET, &((struct sockaddr_in*) ip)->sin_addr, buffer, bufsize);
	else return (char*) inet_ntop(PF_INET6, &((struct sockaddr_in6*) ip)->sin6_addr, buffer, bufsize);
#else
	if(ulz_snprintf(buffer, bufsize, "%d.%d.%d.%d", 
		     ((unsigned char*)(&((struct sockaddr_in*)ip)->sin_addr))[0],
		     ((unsigned char*)(&((struct sockaddr_in*)ip)->sin_addr))[1],
		     ((unsigned char*)(&((struct sockaddr_in*)ip)->sin_addr))[2],
		     ((unsigned char*)(&((struct sockaddr_in*)ip)->sin_addr))[3]))
	return buffer;
	return NULL;	
#endif
}


int socksserver_on_clientconnect (void* userdata, struct sockaddr_storage* clientaddr, int fd) {
	socksserver* srv = (socksserver*) userdata;
	char buffer[256];
	if(srv->log && clientaddr) {
		printfd(fd);
		log_put(1, VARISL(" connect from: "), VARIC(get_client_ip(clientaddr, buffer, sizeof(buffer))), NULL);
	}
	
	if(fd < 3 || fd >= MAX_FD) {
		rocksockserver_disconnect_client(&srv->serva, fd);
		return -2;
	}	
	
	fdinfo* client = &srv->clients[fdindex(fd)];
	
	// put into nonblocking mode, so that writes will not block the server
	int flags = fcntl(fd, F_GETFL); 
	if(flags == -1) return -1;
	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -2;
	
	client->data = find_free_buffer(srv);
	if (!client->data) {
		log_puts(1, SPL("warning: couldnt find free buffer\n"));
		rocksockserver_disconnect_client(&srv->serva, fd);
		return -2;
	}
	
	client->state = SS_CONNECTED;
	client->data->state = BS_IDLE;
	client->data->start = 0;
	client->target_fd = -1;
	
	return 0;
}

int socksserver_on_clientwantsdata (void* userdata, int fd) {
	socksserver* srv = (socksserver*) userdata;

	fdinfo* client = &srv->clients[fdindex(fd)];

	if(client->target_fd >= 0 && srv->clients[fdindex(client->target_fd)].state == SS_AWAITING_PIPE)
		srv->clients[fdindex(client->target_fd)].state = SS_WIRED;

	if(client->data->state == BS_WRITING)
		socksserver_write(srv, fd);
	
	return 0;
}

// returns either the one authmethod supported by the server or AM_INVALID.
rfc1928_authmethod socksserver_parse_authpacket(socksserver* srv, int fd) {
	fdinfo* client = &srv->clients[fdindex(fd)];
	unsigned char numMethods;
	unsigned char i;

	if(client->data->start < 3) return AM_INVALID;
	if(client->data->buf[0] != 5) return AM_INVALID;
	numMethods = client->data->buf[1];
	for(i = 0; i < numMethods && (2U + i) < client->data->start; i++) {
		if(client->data->buf[2 + i] == (unsigned char) srv->accepted_authmethod)
			return srv->accepted_authmethod;
	}
	return AM_INVALID;
}

int socksserver_read_client(socksserver* srv, int fd) {
	fdinfo* client = &srv->clients[fdindex(fd)];
	ssize_t nbytes;
	
	if ((nbytes = recv(fd, client->data->buf + client->data->start, CLIENT_BUFSIZE - client->data->start, 0)) <= 0) {
		socksserver_on_clientdisconnect(srv, fd);
		rocksockserver_disconnect_client(&srv->serva, fd);
		return -1;
	}
	client->data->start += nbytes;
	client->data->used += nbytes;
	return 0;
}

int socksserver_write(socksserver* srv, int fd) {
	fdinfo* client = &srv->clients[fdindex(fd)];
	client->data->state = BS_WRITING;
	ssize_t written = write(fd, client->data->buf + client->data->start, client->data->used - client->data->start);
	int err;
	
	if (written < 0) {
		err = errno;
		if(err == EAGAIN || err == EWOULDBLOCK) return 0;
		else {
			//if(err == EBADF) 
			log_perror("writing");
			socksserver_disconnect_client(srv, fd, 1);
			rocksockserver_disconnect_client(&srv->serva, fd);
			return 3;
		}
	} else if ((size_t) written == client->data->used - client->data->start)
		client->data->state = BS_IDLE;
	return 0;
}

/*
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
*/        
int socksserver_send_error(socksserver* srv, int fd, rfc1928_errorcode ec) {
	fdinfo* client = &srv->clients[fdindex(fd)];
	size_t i = 0;
	client->data->buf[i++] = 5;
	client->data->buf[i++] = ec;
	client->data->buf[i++] = 0;
	
	client->data->buf[i++] = AT_IPV4;
	client->data->buf[i++] = 0;
	client->data->buf[i++] = 0;
	client->data->buf[i++] = 0;
	client->data->buf[i++] = 0;

	client->data->buf[i++] = 0;
	client->data->buf[i++] = 0;
	
	client->data->used = i;
	client->data->start = 0;
	client->data->state = BS_WRITING;
	return socksserver_write(srv, fd);
}

int socksserver_send_auth_response(socksserver* srv, int fd, rfc1928_authmethod meth) {
	fdinfo* client = &srv->clients[fdindex(fd)];
	client->data->buf[0] = 5;
	client->data->buf[1] = meth;
	client->data->state = BS_WRITING;
	client->data->start = 0;
	client->data->used = 2;
	return socksserver_write(srv, fd);
}

/*
 * rfc 1929
  Once the SOCKS V5 server has started, and the client has selected the
   Username/Password Authentication protocol, the Username/Password
   subnegotiation begins.  This begins with the client producing a
   Username/Password request:

           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+

   The VER field contains the current version of the subnegotiation,
   which is X'01'. The ULEN field contains the length of the UNAME field
   that follows. The UNAME field contains the username as known to the
   source operating system. The PLEN field contains the length of the
   PASSWD field that follows. The PASSWD field contains the password
   association with the given UNAME.

   The server verifies the supplied UNAME and PASSWD, and sends the
   following response:

                        +----+--------+
                        |VER | STATUS |
                        +----+--------+
                        | 1  |   1    |
                        +----+--------+

   A STATUS field of X'00' indicates success. If the server returns a
   `failure' (STATUS value other than X'00') status, it MUST close the
   connection.
 * */

// return 0 when packet is not complete, 1 if successfull, -1 if not
int socksserver_check_credentials(socksserver* srv, int fd) {
	fdinfo* client = &srv->clients[fdindex(fd)];
	size_t i = 0;
	unsigned char ulen, plen;
	unsigned char* buf = client->data->buf;
	if(client->data->start < 5) return 0;
	if(buf[i++] != 1) return -1;
	ulen = buf[i++];
	if(client->data->start < i + ulen + 2) return 0; // passwd must be at least 1 char long
	if(ulen != srv->username.size || memcmp(buf + i, srv->username.ptr, ulen)) return -1;
	i += ulen;
	plen = buf[i++];
	if(client->data->start < i + plen) return 0;
	if(plen != srv->password.size || memcmp(buf + i, srv->password.ptr, plen)) return -1;
	return 1;
}

static inline uint16_t my_ntohs (unsigned char* port) {
#ifdef IS_LITTLE_ENDIAN
	return (port[0] * 256) + port[1];
#else
	return port[0] + (port[1] * 256);
#endif
}
#ifndef NO_DNS_SUPPORT
int resolve_host(rs_hostInfo* hostinfo) {
	if (!hostinfo || !hostinfo->host || !hostinfo->port) return -1;
#ifndef IPV4_ONLY
	int ret;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(hostinfo->host, NULL, &hints, &hostinfo->hostaddr);
	if(!ret) {
		if(hostinfo->hostaddr->ai_addr->sa_family == PF_INET)
			((struct sockaddr_in*) hostinfo->hostaddr->ai_addr)->sin_port = htons(hostinfo->port);
		else
			((struct sockaddr_in6*) hostinfo->hostaddr->ai_addr)->sin6_port = htons(hostinfo->port);
		return 0;
	} else
		return ret;
#else
	struct hostent* he;
	if (!(he = gethostbyname(hostinfo->host)) || !he->h_addr_list[0] || he->h_addrtype != AF_INET) return -2;
	hostinfo->hostaddr->ai_family = AF_INET;
	hostinfo->hostaddr->ai_addr->sa_family = AF_INET;
	hostinfo->hostaddr->ai_addrlen = sizeof(struct sockaddr_in);
	memcpy(&((struct sockaddr_in*) hostinfo->hostaddr->ai_addr)->sin_addr, he->h_addr_list[0], 4);
	((struct sockaddr_in*) hostinfo->hostaddr->ai_addr)->sin_port = htons(hostinfo->port);
	return 0;
#endif
}
#endif
/*
 The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order

   The SOCKS server will typically evaluate the request based on source
   and destination addresses, and return one or more reply messages, as
   appropriate for the request type.
   
   In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
   the type of address contained within the field:

          o  X'01'

   the address is a version-4 IP address, with a length of 4 octets

          o  X'03'

   the address field contains a fully-qualified domain name.  The first
   octet of the address field contains the number of octets of name that
   follow, there is no terminating NUL octet.

          o  X'04'

   the address is a version-6 IP address, with a length of 16 octets.
   
   
*/

// parses the connect request and tries to establish the requested connection.
// returns -1 if packet is not complete

int socksserver_connect_request(socksserver* srv, int fd) {
	fdinfo* client = &srv->clients[fdindex(fd)];
	size_t i = 0;
#ifndef NO_DNS_SUPPORT
	unsigned char dlen = 0;
#endif
	unsigned char* buf = client->data->buf;
	int flags, ret;
	rs_hostInfo addr;
	
	struct addrinfo addrbuf;
	struct sockaddr sockbuf;
	
	memset(&addr, 0, sizeof(addr));
	memset(&addrbuf, 0, sizeof(addrbuf));
	memset(&sockbuf, 0, sizeof(sockbuf));
	
	addrbuf.ai_addr = &sockbuf;
	addr.hostaddr = &addrbuf;
	
	
	if(!client->data->start) return -1;
	if(buf[i++] != 5) return EC_NOT_ALLOWED; // check first byte whenever the message length is > 0 to not waste resources on maldoers
	if(client->data->start < 1+1+1+1+4+2) return -1;
	
	if(buf[i++] != 1) return EC_COMMAND_NOT_SUPPORTED; // we support only the connect method.
	if(buf[i++] != 0) return EC_GENERAL_FAILURE;
	switch(buf[i++]) {
		case 1:
			//ipv4
			memcpy(&((struct sockaddr_in*) addr.hostaddr->ai_addr)->sin_addr, buf + 4, 4);
			memcpy(&((struct sockaddr_in*) addr.hostaddr->ai_addr)->sin_port, buf + 8, 2);
			((struct sockaddr_in*) addr.hostaddr->ai_addr)->sin_family = PF_INET;
			addr.hostaddr->ai_addr->sa_family = PF_INET;
			addr.hostaddr->ai_addrlen = sizeof(struct sockaddr_in);
			break;
#ifndef NO_DNS_SUPPORT
		case 3:
			//dns
			dlen = buf[i++];
			if(client->data->start < 1U+1U+1U+1U+1U+dlen+2U) return -1;
			addr.port = my_ntohs(buf + i + dlen);
			buf[i + dlen] = 0;
			addr.host = (char*) (buf + i);
#ifndef IPV4_ONLY
			addr.hostaddr = NULL;
#endif
			if(!resolve_host(&addr)) {
#ifndef IPV4_ONLY
				memcpy(&addrbuf, addr.hostaddr, sizeof(struct addrinfo));
				freeaddrinfo(addr.hostaddr);
				addr.hostaddr = &addrbuf;
#endif
			} else return EC_ADDRESSTYPE_NOT_SUPPORTED;
			break;
#endif
			
#ifndef IPV4_ONLY
		case 4: //ipv6
			if(client->data->start < 1+1+1+1+16+2) return -1;
			memcpy(&((struct sockaddr_in6*) addr.hostaddr->ai_addr)->sin6_addr, buf + 4, 16);
			memcpy(&((struct sockaddr_in6*) addr.hostaddr->ai_addr)->sin6_port, buf + 20, 2);
			((struct sockaddr_in6*) addr.hostaddr->ai_addr)->sin6_family = PF_INET6;
			addr.hostaddr->ai_addr->sa_family = PF_INET6;
			addr.hostaddr->ai_addrlen = sizeof(struct sockaddr_in6);
			break;
#endif
		default:
			return EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	client->target_fd = socket(addr.hostaddr->ai_addr->sa_family, SOCK_STREAM, 0);
	if(client->target_fd == -1) {
		neterror:
		switch(errno) {
			case ENETDOWN: case ENETUNREACH: case ENETRESET:
				return EC_NET_UNREACHABLE;
			case EHOSTUNREACH: case EHOSTDOWN:
				return EC_HOST_UNREACHABLE;
			case ECONNREFUSED:
				return EC_CONN_REFUSED;
			default:
				return EC_GENERAL_FAILURE;
		}
	}
	
	if(client->target_fd >= MAX_FD) {
		close(client->target_fd);
		return EC_GENERAL_FAILURE;
	}
	
	flags = fcntl(client->target_fd, F_GETFL); 
	if(flags == -1) return EC_GENERAL_FAILURE;
	
	if(fcntl(client->target_fd, F_SETFL, flags | O_NONBLOCK) == -1) return EC_GENERAL_FAILURE;
	
	ret = connect(client->target_fd, addr.hostaddr->ai_addr, addr.hostaddr->ai_addrlen);
	if(ret == -1) {
		ret = errno;
		if (!(ret == EINPROGRESS || ret == EWOULDBLOCK)) 
			goto neterror;
	}
	
	srv->clients[fdindex(client->target_fd)].state = SS_SOCKSTARGET;
	srv->clients[fdindex(client->target_fd)].data = client->data;
	srv->clients[fdindex(client->target_fd)].target_fd = fd;
	rocksockserver_watch_fd(&srv->serva, client->target_fd);
	
	if(srv->log) {
		if(get_client_ip((struct sockaddr_storage*) addr.hostaddr->ai_addr, (char*) buf, CLIENT_BUFSIZE)) {
			printfd(fd);
			log_puts(1, SPLITERAL(" -> "));
			printfd(client->target_fd);
			log_put(1, VARISL(" <"), VARIC((char*)buf), VARISL(">"), NULL);
		}
	}
	
	return EC_SUCCESS;
}

/*
  The client connects to the server, and sends a version
   identifier/method selection message:

                   +----+----------+----------+
                   |VER | NMETHODS | METHODS  |
                   +----+----------+----------+
                   | 1  |    1     | 1 to 255 |
                   +----+----------+----------+

   The VER field is set to X'05' for this version of the protocol.  The
   NMETHODS field contains the number of method identifier octets that
   appear in the METHODS field.

   The server selects from one of the methods given in METHODS, and
   sends a METHOD selection message:

                         +----+--------+
                         |VER | METHOD |
                         +----+--------+
                         | 1  |   1    |
                         +----+--------+

   If the selected METHOD is X'FF', none of the methods listed by the
   client are acceptable, and the client MUST close the connection.
*/
int socksserver_on_clientread (void* userdata, int fd, size_t dummy) {
	socksserver* srv = (socksserver*) userdata;
	fdinfo* client = &srv->clients[fdindex(fd)];
	rfc1928_authmethod authmethod;
	char buf[4];
	ssize_t readv;
	int ret;
	
	(void) dummy;
	
	if(client->state == SS_AWAITING_PIPE || (client->data->state != BS_IDLE && client->data->state != BS_READING)) {
		if((readv = recvfrom(fd, buf, 4, MSG_PEEK, NULL, NULL)) <= 0) {
			if (!readv)
				socksserver_on_clientdisconnect(userdata, fd);
			else 
				log_perror("recvfrom");
			rocksockserver_disconnect_client(&srv->serva, fd);
		}
		return 1;
	}
	
	if(client->state == SS_WIRED || client->state == SS_SOCKSTARGET) {
		client->data->start = 0;
		client->data->used = 0;
	}
	
	if(socksserver_read_client(srv, fd)) 
		return 2;
	     
	switch(client->state) {
		case SS_AWAITING_DISCONNECT:
			socksserver_disconnect_client(srv, fd, 1);
			break;
		case SS_CONNECTED:
			if((authmethod = socksserver_parse_authpacket(srv, fd)) != AM_INVALID) {
				if(authmethod == AM_USERNAME)
					client->state = SS_AWAITING_AUTH_PACKET;
				else 
					client->state = SS_AUTHED;
			} else {
				client->state = SS_AWAITING_DISCONNECT;
			}
			socksserver_send_auth_response(srv, fd, authmethod);
			break;
		case SS_AWAITING_AUTH_PACKET:
			ret = socksserver_check_credentials(srv, fd);
			if (!ret) return 3;
			if (ret == -1) {
				client->state = SS_AWAITING_DISCONNECT;
				socksserver_send_auth_response(srv, fd, AM_INVALID);
			} else {
				client->state = SS_AUTHED;
				socksserver_send_auth_response(srv, fd, 0); // abusing the func here.. 0 indicates success, 0xFF fail
			}
			break;
		case SS_AUTHED:
			ret = socksserver_connect_request(srv, fd);
			if(ret == -1) return 4;
			if(ret) {
				client->state = SS_AWAITING_DISCONNECT;
			} else {
				client->state = SS_AWAITING_PIPE;
			}
			socksserver_send_error(srv, fd, ret);			
			break;
		case SS_SOCKSTARGET:
			if(srv->clients[fdindex(client->target_fd)].state == SS_AWAITING_PIPE)
				srv->clients[fdindex(client->target_fd)].state = SS_WIRED;
			client->data->start = 0;
			socksserver_write(srv, client->target_fd);
			break;
		case SS_WIRED:
			client->data->start = 0;
			socksserver_write(srv, client->target_fd);
			break;
		default:
			break;
	}
	return 0;
}

int socksserver_init(socksserver* srv, char* listenip, int port, int log, stringptr* username, stringptr* pass, int uid, int gid) {
	memset(srv, 0, sizeof(socksserver));
	srv->log = log;
	if(rocksockserver_init(&srv->serva, listenip, port, (void*) srv)) return -1;
	
	//dropping privs after bind()
	if(gid != -1 && setgid(gid) == -1)
		log_perror("setgid");
	if(gid != -1 && setgroups(0, NULL) == -1)
		log_perror("setgroups");
	if(uid != -1 && setuid(uid) == -1) 
		log_perror("setuid");
	
	if(username->size) {
		memcpy(srv->_username, username->ptr, username->size);
		srv->username.ptr = srv->_username;
		srv->username.size = username->size;
		memset(username->ptr, 0, username->size);
	}

	if(pass->size) {
		memcpy(srv->_password, pass->ptr, pass->size);
		srv->password.ptr = srv->_password;
		srv->password.size = pass->size;
		memset(pass->ptr, 0, pass->size);
	}
	
	srv->accepted_authmethod = username->size ? AM_USERNAME : AM_NO_AUTH;
	
	if(rocksockserver_loop(&srv->serva, NULL, 0, &socksserver_on_clientconnect, &socksserver_on_clientread, &socksserver_on_clientwantsdata, &socksserver_on_clientdisconnect)) return -2;
	return 0;
}

__attribute__ ((noreturn))
void syntax(op_state* opt) {
	log_puts(1, SPL("progname -listenip=0.0.0.0 -port=1080 -log=0 -uid=0 -gid=0 -user=foo -pass=bar\n"));
	log_puts(1, SPL("user and pass are regarding socks authentication\n"));
	log_puts(1, SPL("passed options were:\n"));
	op_printall(opt);
	exit(1);
}

int main(int argc, char** argv) {
	socksserver srv;
	static const char defaultip[] = "127.0.0.1";
	op_state opt_storage, *opt = &opt_storage;
	op_init(opt, argc, argv);
	SPDECLAREC(o_port, op_get(opt, SPL("port")));
	SPDECLAREC(o_listenip, op_get(opt, SPL("listenip")));
	SPDECLAREC(o_log, op_get(opt, SPL("log")));
	SPDECLAREC(o_uid, op_get(opt, SPL("uid")));
	SPDECLAREC(o_gid, op_get(opt, SPL("gid")));
	SPDECLAREC(o_user, op_get(opt, SPL("user")));
	SPDECLAREC(o_pass, op_get(opt, SPL("pass")));
	
	int log = o_log->size ? atoi(o_log->ptr) : 1;
	char* ip = o_listenip->size ? o_listenip->ptr : (char*) defaultip;
	int port = o_port->size ? atoi(o_port->ptr) : 1080;
	
	if(op_hasflag(opt, SPLITERAL("-help"))) syntax(opt);
	if((o_user->size && (!o_pass->size || o_user->size > 255)) || (o_pass->size && (!o_user->size || o_pass->size > 255))) {
		log_puts(1, SPL("fatal: username or password exceeding 255 chars, or only one of both set\n"));
		exit(1);
	}
	
	socksserver_init(&srv, ip, port, log, o_user, o_pass, o_uid->size ? atoi(o_uid->ptr) : -1, o_gid->size ? atoi(o_gid->ptr) : -1);

	return 0;
}

