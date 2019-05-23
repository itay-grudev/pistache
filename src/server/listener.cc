/* listener.cc
   Mathieu Stefani, 12 August 2015

*/

#include <pistache/listener.h>
#include <pistache/peer.h>
#include <pistache/common.h>
#include <pistache/os.h>
#include <pistache/transport.h>
#include <pistache/errors.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <chrono>
#include <memory>
#include <vector>

#include <cerrno>
#include <signal.h>

#ifdef PISTACHE_USE_SSL

#include <openssl/ssl.h>
#include <openssl/err.h>

#endif /* PISTACHE_USE_SSL */

#ifdef PISTACHE_SSL_GNUTLS
#define CHECK(cmd, message) if( cmd < 0 ) throw SocketError( message );
#define REQUIRED(cmd, message) if( cmd < 0 ) throw ServerError( message );
#endif /* PISTACHE_SSL_GNUTLS */


// Defined in credentials_lookup.cpp
// TODO: custom callback support
int credentials_lookup( gnutls_session_t, const char*, gnutls_datum_t*, gnutls_datum_t*, gnutls_datum_t*, gnutls_datum_t* );

namespace Pistache {
namespace Tcp {

namespace {
    volatile sig_atomic_t g_listen_fd = -1;

    void closeListener() {
        if (g_listen_fd != -1) {
            ::close(g_listen_fd);
            g_listen_fd = -1;
        }
    }

    void handle_sigint(int) {
        closeListener();
    }
}

void setSocketOptions(Fd fd, Flags<Options> options) {
    if (options.hasFlag(Options::ReuseAddr)) {
        int one = 1;
        TRY(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one)));
    }

    if (options.hasFlag(Options::Linger)) {
        struct linger opt;
        opt.l_onoff = 1;
        opt.l_linger = 1;
        TRY(::setsockopt(fd, SOL_SOCKET, SO_LINGER, &opt, sizeof (opt)));
    }

    if (options.hasFlag(Options::FastOpen)) {
        int hint = 5;
        TRY(::setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &hint, sizeof (hint)));
    }
    if (options.hasFlag(Options::NoDelay)) {
        int one = 1;
        TRY(::setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof (one)));
    }

}

Listener::Listener()
    : addr_()
    , listen_fd(-1)
    , backlog_(Const::MaxBacklog)
    , shutdownFd()
    , poller()
    , options_()
    , workers_(Const::DefaultWorkers)
    , reactor_()
    , transportKey()
    , useSSL_(true)
{ }

Listener::Listener(const Address& address)
    : addr_(address)
    , listen_fd(-1)
    , backlog_(Const::MaxBacklog)
    , shutdownFd()
    , poller()
    , options_()
    , workers_(Const::DefaultWorkers)
    , reactor_()
    , transportKey()
    , useSSL_(true)
{
}

Listener::~Listener() {
    if (isBound())
        shutdown();
    if (acceptThread.joinable())
        acceptThread.join();
#ifdef PISTACHE_USE_SSL
    if (this->useSSL_)
    {
        SSL_CTX_free((SSL_CTX *)this->ssl_ctx_);
        EVP_cleanup();
    }
#endif /* PISTACHE_USE_SSL */

#ifdef PISTACHE_SSL_GNUTLS
    if( this->useSSL_ ){
        gnutls_srp_free_server_credentials( srp_cred );
        gnutls_certificate_free_credentials( x509_cred );
        gnutls_priority_deinit( priority_cache );
    }
#endif // PISTACHE_SSL_GNUTLS
}

void
Listener::init(
    size_t workers,
    Flags<Options> options, int backlog)
{
    if (workers > hardware_concurrency()) {
        // Log::warning() << "More workers than available cores"
    }

    options_ = options;
    backlog_ = backlog;
    useSSL_ = false;

    if (options_.hasFlag(Options::InstallSignalHandler)) {
        if (signal(SIGINT, handle_sigint) == SIG_ERR) {
            throw std::runtime_error("Could not install signal handler");
        }
    }

    workers_ = workers;

}

void
Listener::setHandler(const std::shared_ptr<Handler>& handler) {
    handler_ = handler;
}

void
Listener::pinWorker(size_t worker, const CpuSet& set)
{
    UNUSED(worker)
    UNUSED(set)
#if 0
    if (ioGroup.empty()) {
        throw std::domain_error("Invalid operation, did you call init() before ?");
    }
    if (worker > ioGroup.size()) {
        throw std::invalid_argument("Trying to pin invalid worker");
    }

    auto &wrk = ioGroup[worker];
    wrk->pin(set);
#endif
}

void
Listener::bind() {
    bind(addr_);
}

void
Listener::bind(const Address& address) {
    if (!handler_)
        throw std::runtime_error("Call setHandler before calling bind()");
    addr_ = address;

    struct addrinfo hints;
    hints.ai_family = address.family();
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    const auto& host = addr_.host();
    const auto& port = addr_.port().toString();
    AddrInfo addr_info;

    TRY(addr_info.invoke(host.c_str(), port.c_str(), &hints));

    int fd = -1;

    const addrinfo * addr = nullptr;
    for (addr = addr_info.get_info_ptr(); addr; addr = addr->ai_next) {
        fd = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (fd < 0) continue;

        setSocketOptions(fd, options_);

        if (::bind(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
            close(fd);
            continue;
        }

        TRY(::listen(fd, backlog_));
        break;
    }

    // At this point, it is still possible that we couldn't bind any socket. If it is the case, the previous
    // loop would have exited naturally and addr will be null.
    if (addr == nullptr) {
        throw std::runtime_error(strerror(errno));
    }

    make_non_blocking(fd);
    poller.addFd(fd, Polling::NotifyOn::Read, Polling::Tag(fd));
    listen_fd = fd;
    g_listen_fd = fd;

    auto transport = std::make_shared<Transport>(handler_);

    reactor_.init(Aio::AsyncContext(workers_));
    transportKey = reactor_.addHandler(transport);
}

bool
Listener::isBound() const {
    return listen_fd != -1;
}

// Return actual TCP port Listener is on, or 0 on error / no port.
// Notes:
// 1) Default constructor for 'Port()' sets value to 0.
// 2) Socket is created inside 'Listener::run()', which is called from
//    'Endpoint::serve()' and 'Endpoint::serveThreaded()'.  So getting the
//    port is only useful if you attempt to do so from a _different_ thread
//    than the one running 'Listener::run()'.  So for a traditional single-
//    threaded program this method is of little value.
Port
Listener::getPort() const {
    if (listen_fd == -1) {
        return Port();
    }

    struct sockaddr_in sock_addr = {0};
    socklen_t addrlen = sizeof(sock_addr);
    auto sock_addr_alias = reinterpret_cast<struct sockaddr*>(&sock_addr);

    if (-1 == getsockname(listen_fd, sock_addr_alias, &addrlen)) {
        return Port();
    }

    return Port(ntohs(sock_addr.sin_port));
}

void
Listener::run() {
    shutdownFd.bind(poller);
    reactor_.run();

    for (;;) {
        std::vector<Polling::Event> events;
        int ready_fds = poller.poll(events);

        if (ready_fds == -1) {
            if (errno == EINTR && g_listen_fd == -1) return;
            throw Error::system("Polling");
        }
        for (const auto& event: events) {
            if (event.tag == shutdownFd.tag())
                return;

            if (event.flags.hasFlag(Polling::NotifyOn::Read)) {
                auto fd = event.tag.value();
                if (static_cast<ssize_t>(fd) == listen_fd) {
                    try {
                        handleNewConnection();
                    }
                    catch (SocketError& ex) {
                        std::cerr << "Server: " << ex.what() << std::endl;
                    }
                    catch (ServerError& ex) {
                        std::cerr << "Server: " << ex.what() << std::endl;
                        throw;
                    }
                }
            }
        }
    }
}

void
Listener::runThreaded() {
    acceptThread = std::thread([=]() { this->run(); });
}

void
Listener::shutdown() {
    if (shutdownFd.isBound()) shutdownFd.notify();
    reactor_.shutdown();
}

Async::Promise<Listener::Load>
Listener::requestLoad(const Listener::Load& old) {
    auto handlers = reactor_.handlers(transportKey);

    std::vector<Async::Promise<rusage>> loads;
    for (const auto& handler: handlers) {
        auto transport = std::static_pointer_cast<Transport>(handler);
        loads.push_back(transport->load());
    }

    return Async::whenAll(std::begin(loads), std::end(loads)).then([=](const std::vector<rusage>& usages) {

        Load res;
        res.raw = usages;

        if (old.raw.empty()) {
            res.global = 0.0;
            for (size_t i = 0; i < handlers.size(); ++i) res.workers.push_back(0.0);
        } else {

            auto totalElapsed = [](rusage usage) {
                return (usage.ru_stime.tv_sec * 1e6 + usage.ru_stime.tv_usec)
                     + (usage.ru_utime.tv_sec * 1e6 + usage.ru_utime.tv_usec);
            };

            auto now = std::chrono::system_clock::now();
            auto diff = now - old.tick;
            auto tick = std::chrono::duration_cast<std::chrono::microseconds>(diff);
            res.tick = now;

            for (size_t i = 0; i < usages.size(); ++i) {
                auto last = old.raw[i];
                const auto& usage = usages[i];

                auto nowElapsed = totalElapsed(usage);
                auto timeElapsed = nowElapsed - totalElapsed(last);

                auto loadPct = (timeElapsed * 100.0) / tick.count();
                res.workers.push_back(loadPct);
                res.global += loadPct;

            }

            res.global /= usages.size();
        }

        return res;

     }, Async::Throw);
}

Address
Listener::address() const {
    return addr_;
}

Options
Listener::options() const {
    return options_;
}

void Listener::handleNewConnection()
{
    struct sockaddr_in peer_addr;
    int client_fd = acceptConnection(peer_addr);
    auto peer = std::make_shared<Peer>(Address::fromUnix((struct sockaddr *)&peer_addr));

#ifdef PISTACHE_SSL_GNUTLS
    if( this->useSSL_ ){
        printf("handleNewConnection using gnutls\n");
        // Initialise the TLS session
        CHECK(
            gnutls_init( &peer->session, GNUTLS_SERVER ),
            "Unable to initialize TLS session"
        )
        printf("gnutls_init\n");
        // CHECK(
        //     gnutls_priority_set( session, priority_cache ),
        //     "Unable to set session priority"
        // )
        CHECK(
            gnutls_priority_set_direct(
                peer->session,
                "NORMAL:-KX-ALL:+SRP:+SRP-DSS:+SRP-RSA",
                NULL
            ),
            "Unable to set session priority"
        )
        // "NORMAL:-KX-ALL:+SRP:+SRP-DSS:+SRP-RSA",
        printf("gnutls_priority_set\n");
        CHECK(
            gnutls_credentials_set( peer->session, GNUTLS_CRD_CERTIFICATE, &x509_cred ),
            "Unable to set certificate credentials"
        )
        printf("gnutls_credentials_set x509\n");
        CHECK(
            gnutls_credentials_set( peer->session, GNUTLS_CRD_SRP, &srp_cred ),
            "Unable to set SRP credentials"
        )
        printf("gnutls_credentials_set srp\n");
        // TODO: Add support for requesting a certificate from the client
        // But for now disable it
        gnutls_certificate_server_set_request( peer->session, GNUTLS_CERT_IGNORE );
        printf("gnutls_certificate_server_set_request\n");
        // gnutls_handshake_set_timeout( peer->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT );
        printf("gnutls_handshake_set_timeout\n");

        gnutls_transport_set_int( peer->session, client_fd );
        printf("gnutls_transport_set_int\n");

        printf( "Handshake start\n" );
        printf("%d",peer->session);

        int ret;
        do {
            printf("%d",peer->session);
            ret = gnutls_handshake( peer->session );
        } while( ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED );
        if( ret < 0 ){
            printf( "fuck %d\n", ret );
            close( client_fd );
            gnutls_deinit( peer->session );
            peer->session = NULL;
            throw SocketError(
                "Handshake has failed."
            );
        }

        // TODO: Drop this logging. Only used for debugging the SRP connection
        // establishment
        printf( "Handshake completed\n" );
        printf(
            "    User connected: %s\n",
            gnutls_srp_server_get_username( peer->session )
        );

        peer->associateSSL( &peer->session );
    }
#endif // PISTACHE_SSL_GNUTLS
    printf("ssl = %d\n", useSSL_ );

#ifdef PISTACHE_USE_SSL
    SSL *ssl = nullptr;

    if (this->useSSL_) {

        ssl = SSL_new((SSL_CTX *)this->ssl_ctx_);
        if (ssl == NULL)
            throw std::runtime_error("Cannot create SSL connection");

        SSL_set_fd(ssl, client_fd);
        SSL_set_accept_state(ssl);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            return ;
        }
    }
#endif /* PISTACHE_USE_SSL */

    make_non_blocking(client_fd);
    peer->associateFd(client_fd);

#ifdef PISTACHE_USE_SSL
    if (this->useSSL_)
        peer->associateSSL(ssl);
#endif /* PISTACHE_USE_SSL */

    dispatchPeer(peer);
}

int Listener::acceptConnection(struct sockaddr_in& peer_addr) const
{
    socklen_t peer_addr_len = sizeof(peer_addr);
    int client_fd = ::accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
    if (client_fd < 0) {
        if (errno == EBADF || errno == ENOTSOCK)
            throw ServerError(strerror(errno));
        else
            throw SocketError(strerror(errno));
    }
    return client_fd;
}

void
Listener::dispatchPeer(const std::shared_ptr<Peer>& peer) {
    auto handlers = reactor_.handlers(transportKey);
    auto idx = peer->fd() % handlers.size();
    auto transport = std::static_pointer_cast<Transport>(handlers[idx]);

    transport->handleNewPeer(peer);

}

#ifdef PISTACHE_USE_SSL

static SSL_CTX *ssl_create_context(const std::string &cert, const std::string &key, bool use_compression)
{
    const SSL_METHOD    *method;
    SSL_CTX             *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Cannot setup SSL context");
    }

    if (!use_compression) {
        /* Disable compression to prevent BREACH and CRIME vulnerabilities. */
        if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Cannot disable compression");
        }
    }

    /* Function introduced in 1.0.2 */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_CTX_set_ecdh_auto(ctx, 1);
#endif /* OPENSSL_VERSION_NUMBER */

    if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Cannot load SSL certificate");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Cannot load SSL private key");
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Private key does not match public key in the certificate");
    }

    return ctx;
}

void
Listener::setupSSLAuth(const std::string &ca_file, const std::string &ca_path, int (*cb)(int, void *) = NULL)
{
    const char *__ca_file = NULL;
    const char *__ca_path = NULL;

    if (this->ssl_ctx_ == NULL)
        throw std::runtime_error("SSL Context is not initialized");

    if (!ca_file.empty())
        __ca_file = ca_file.c_str();
    if (!ca_path.empty())
        __ca_path = ca_path.c_str();

    if (SSL_CTX_load_verify_locations((SSL_CTX *)this->ssl_ctx_, __ca_file, __ca_path) <= 0) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Cannot verify SSL locations");
    }

    SSL_CTX_set_verify((SSL_CTX *)this->ssl_ctx_,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE,
        /* Callback type did change in 1.0.1 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        (int (*)(int, X509_STORE_CTX *))cb
#else
        (SSL_verify_cb)cb
#endif /* OPENSSL_VERSION_NUMBER */
    );
}
#endif // PISTACHE_USE_SSL

void
Listener::setupSSL(const std::string &cert_path, const std::string &key_path, bool use_compression)
{
    this->useSSL_ = true;
#ifdef PISTACHE_USE_SSL
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();

    this->ssl_ctx_ = ssl_create_context(cert_path, key_path, use_compression);
#endif // PISTACHE_USE_SSL
#ifdef PISTACHE_SSL_GNUTLS
    printf("Listener ssl on\n" );
    printf("ssl = %d\n", useSSL_ );
    printf("ssl = %d\n", this->useSSL_ );
    // Verify an apropriate GnuTLS version is available with SRP support
    if( gnutls_check_version( "3.6.0" ) == NULL )
        throw std::runtime_error( "GnuTLS 3.6.0 or later is required." );

    // Set SRP credentials
    gnutls_srp_allocate_server_credentials( &srp_cred );
    gnutls_srp_set_server_credentials_file( srp_cred, "tpasswd", "tpasswd.conf" );
    gnutls_srp_set_server_credentials_function( srp_cred, credentials_lookup );

    // Set the certificate key pair
    gnutls_certificate_allocate_credentials( &x509_cred );
    // gnutls_certificate_set_x509_trust_file( x509_cred, CAFILE, GNUTLS_X509_FMT_PEM );
    REQUIRED(
        gnutls_certificate_set_x509_key_file( x509_cred, cert_path.c_str(), key_path.c_str(), GNUTLS_X509_FMT_PEM ),
        "Unable to load SSL certificate/keypair!"
    )

    // Initialise the Priority Cache
    // TODO: Allow setting custom priorities for a universal SSL implementation
    REQUIRED(
        gnutls_priority_init( &priority_cache, NULL, NULL ),
        "Unable to initialize priority cache!"
    )
    // gnutls_priority_set_direct(
    //     session,
    //     "NORMAL",
    //     NULL
    // );
    // "NORMAL:-KX-ALL:+SRP:+SRP-DSS:+SRP-RSA",
#endif // PISTACHE_SSL_GNUTLS
}

} // namespace Tcp
} // namespace Pistache
