/* listener.h
   Mathieu Stefani, 12 August 2015

  A TCP Listener
*/

#pragma once

#include <pistache/tcp.h>
#include <pistache/net.h>
#include <pistache/os.h>
#include <pistache/flags.h>
#include <pistache/async.h>
#include <pistache/reactor.h>
#include <pistache/config.h>

#include <sys/resource.h>

#include <vector>
#include <memory>
#include <thread>


#ifdef PISTACHE_USE_SSL
#include <openssl/ssl.h>
#endif /* PISTACHE_USE_SSL */

#ifdef PISTACHE_SSL_GNUTLS
#include <gnutls/gnutls.h>
#endif // PISTACHE_SSL_GNUTLS

namespace Pistache {
namespace Tcp {

class Peer;
class Transport;

void setSocketOptions(Fd fd, Flags<Options> options);

class Listener {
public:

    struct Load {
        using TimePoint = std::chrono::system_clock::time_point;
        double global;
        std::vector<double> workers;

        std::vector<rusage> raw;
        TimePoint tick;
    };

    Listener();
    ~Listener();

    explicit Listener(const Address& address);
    void init(
            size_t workers,
            Flags<Options> options = Options::None,
            int backlog = Const::MaxBacklog);
    void setHandler(const std::shared_ptr<Handler>& handler);

    void bind();
    void bind(const Address& address);

    bool isBound() const;
    Port getPort() const;

    void run();
    void runThreaded();

    void shutdown();

    Async::Promise<Load> requestLoad(const Load& old);

    Options options() const;
    Address address() const;

    void pinWorker(size_t worker, const CpuSet& set);

    void setupSSL(const std::string &cert_path, const std::string &key_path, bool use_compression);
    void setupSSLAuth(const std::string &ca_file, const std::string &ca_path, int (*cb)(int, void *));

private:
    Address addr_;
    int listen_fd;
    int backlog_;
    NotifyFd shutdownFd;
    Polling::Epoll poller;

    Flags<Options> options_;
    std::thread acceptThread;

    size_t workers_;
    std::shared_ptr<Handler> handler_;

    Aio::Reactor reactor_;
    Aio::Reactor::Key transportKey;

#ifdef PISTACHE_SSL_GNUTLS
    gnutls_priority_t priority_cache;
    gnutls_srp_server_credentials_t srp_cred;
    gnutls_certificate_credentials_t x509_cred;
#endif // PISTACHE_SSL_GNUTLS

    void handleNewConnection();
    int acceptConnection(struct sockaddr_in& peer_addr) const;
    void dispatchPeer(const std::shared_ptr<Peer>& peer);

    bool useSSL_;
    void *ssl_ctx_;
};

} // namespace Tcp
} // namespace Pistache
