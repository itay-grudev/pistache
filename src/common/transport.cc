/* traqnsport.cc
   Mathieu Stefani, 02 July 2017

   TCP transport handling

*/

#include <sys/sendfile.h>
#include <sys/timerfd.h>

#include <pistache/transport.h>
#include <pistache/peer.h>
#include <pistache/tcp.h>
#include <pistache/os.h>
#include <pistache/errors.h>

#ifdef PISTACHE_USE_SSL
#include <openssl/err.h>
#endif /* PISTACHE_USE_SSL */

namespace Pistache {

using namespace Polling;

namespace Tcp {

Transport::Transport(const std::shared_ptr<Tcp::Handler>& handler) {
    init(handler);
}

void
Transport::init(const std::shared_ptr<Tcp::Handler>& handler) {
    handler_ = handler;
    handler_->associateTransport(this);
}

std::shared_ptr<Aio::Handler>
Transport::clone() const {
    return std::make_shared<Transport>(handler_->clone());
}

void
Transport::registerPoller(Polling::Epoll& poller) {
    writesQueue.bind(poller);
    timersQueue.bind(poller);
    peersQueue.bind(poller);
    notifier.bind(poller);
}

void
Transport::handleNewPeer(const std::shared_ptr<Tcp::Peer>& peer) {
    auto ctx = context();
    const bool isInRightThread = std::this_thread::get_id() == ctx.thread();
    if (!isInRightThread) {
        PeerEntry entry(peer);
        peersQueue.push(std::move(entry));
    } else {
        handlePeer(peer);
    }
    int fd = peer->fd();
    {
        Guard guard(toWriteLock);
        toWrite.emplace(fd, std::deque<WriteEntry>{});
    }
}

void
Transport::onReady(const Aio::FdSet& fds) {
    for (const auto& entry: fds) {
        if (entry.getTag() == writesQueue.tag()) {
            handleWriteQueue();
        }
        else if (entry.getTag() == timersQueue.tag()) {
            handleTimerQueue();
        }
        else if (entry.getTag() == peersQueue.tag()) {
            handlePeerQueue();
        }
        else if (entry.getTag() == notifier.tag()) {
            handleNotify();
        }

        else if (entry.isReadable()) {
            auto tag = entry.getTag();
            if (isPeerFd(tag)) {
                auto& peer = getPeer(tag);
                handleIncoming(peer);
            } else if (isTimerFd(tag)) {
                auto it = timers.find(tag.value());
                auto& entry = it->second;
                handleTimer(std::move(entry));
                timers.erase(it->first);
            }
            else {
                throw std::runtime_error("Unknown fd");
            }

        }
        else if (entry.isWritable()) {
            auto tag = entry.getTag();
            auto fd = tag.value();

            {
                Guard guard(toWriteLock);
                auto it = toWrite.find(fd);
                if (it == std::end(toWrite)) {
                    throw std::runtime_error("Assertion Error: could not find write data");
                }
            }

            reactor()->modifyFd(key(), fd, NotifyOn::Read, Polling::Mode::Edge);

            // Try to drain the queue
            asyncWriteImpl(fd);
        }
    }
}

void
Transport::disarmTimer(Fd fd) {
    auto it = timers.find(fd);
    if (it == std::end(timers))
        throw std::runtime_error("Timer has not been armed");

    auto &entry = it->second;
    entry.disable();
}

void
Transport::handleIncoming(const std::shared_ptr<Peer>& peer) {
    char buffer[Const::MaxBuffer] = {0};
    int fd = peer->fd();

    for (;;) {

        ssize_t bytes;

        if (peer->ssl() != NULL) {
#ifdef PISTACHE_USE_SSL
            bytes = SSL_read( (SSL*)peer->ssl(), buffer, Const::MaxBuffer );
#endif // PISTACHE_USE_SSL
#ifdef PISTACHE_SSL_GNUTLS
            bytes = gnutls_record_recv( *(gnutls_session_t*)peer->ssl(), buffer, Const::MaxBuffer );
#endif // PISTACHE_SSL_GNUTLS
        } else {
            bytes = recv( fd, buffer, Const::MaxBuffer, 0 );
        }

        if( bytes == 0 ){ // EOF / disconnect
            handlePeerDisconnection( peer );
            break;
        } else if( bytes < 0 ) { // Error
            if (peer->ssl() != NULL) {
#ifdef PISTACHE_SSL_GNUTLS
                // Check if the error is non-fatal
                if( gnutls_error_is_fatal( bytes ) == 0 ){
                    continue;
                } else {
                    // Fatal GnuTLS error that requres the session to be terminated
                    throw SocketError( gnutls_strerror( bytes ) );
                }
#endif // PISTACHE_SSL_GNUTLS
#ifdef PISTACHE_USE_SSL
                int ssl_error = SSL_get_error( (SSL*)peer->ssl(), bytes );
                if( // Recoverable error. Should be called again
                    ssl_error == SSL_ERROR_WANT_READ ||
                    ssl_error == SSL_ERROR_WANT_WRITE ||
                    ssl_error == SSL_ERROR_WANT_CONNECT ||
                    ssl_error == SSL_ERROR_WANT_ACCEPT
                ) continue;
                else {
                    throw SocketError( ERR_error_string( ERR_get_error(), NULL ) );
                }
#endif // PISTACHE_USE_SSL
            }
#if !defined PISTACHE_USE_SSL && !defined PISTACHE_SSL_GNUTLS
            if( errno == EAGAIN || errno == EWOULDBLOCK ){
                break;
            } else if( errno == ECONNRESET ){
                handlePeerDisconnection( peer );
            } else {
                throw std::runtime_error( strerror( errno ));
            }
#endif // !defined PISTACHE_USE_SSL && !defined PISTACHE_SSL_GNUTLS
            break;
        } else { // Bytes received
            handler_->onInput( buffer, bytes, peer );
        }
    }
}

void
Transport::handlePeerDisconnection(const std::shared_ptr<Peer>& peer) {
    handler_->onDisconnection(peer);

    int fd = peer->fd();
    auto it = peers.find(fd);
    if (it == std::end(peers))
        throw std::runtime_error("Could not find peer to erase");

#ifdef PISTACHE_USE_SSL
    if (peer->ssl() != NULL) {
        SSL_free((SSL *)peer->ssl());
        peer->associateSSL(NULL);
    }
#endif /* PISTACHE_USE_SSL */
#ifdef PISTACHE_SSL_GNUTLS
    if( peer->session ){
        gnutls_deinit( peer->session );
        peer->session = NULL;
    }
#endif // PISTACHE_SSL_GNUTLS

    peers.erase(it->first);

    {
        // Clean up buffers
        Guard guard(toWriteLock);
        auto & wq = toWrite[fd];
        while (wq.size() > 0) {
            wq.pop_front();
        }
        toWrite.erase(fd);
    }

    close(fd);
}

void
Transport::asyncWriteImpl(Fd fd)
{
    bool stop = false;
    while (!stop) {
        Guard guard(toWriteLock);

        auto it = toWrite.find(fd);

        // cleanup will have been handled by handlePeerDisconnection
        if (it == std::end(toWrite)) { return; }
        auto & wq = it->second;
        if (wq.size() == 0) {
            break;
        }

        auto & entry = wq.front();
        int flags    = entry.flags;
        BufferHolder &buffer = entry.buffer;
        Async::Deferred<ssize_t> deferred = std::move(entry.deferred);

        auto cleanUp = [&]() {
            wq.pop_front();
            if (wq.size() == 0) {
                toWrite.erase(fd);
                reactor()->modifyFd(key(), fd, NotifyOn::Read, Polling::Mode::Edge);
                stop = true;
            }
        };

        size_t totalWritten = buffer.offset();
        for (;;) {
            ssize_t bytesWritten = 0;
            auto len = buffer.size() - totalWritten;

            if (buffer.isRaw()) {
                auto raw = buffer.raw();
                auto ptr = raw.data().c_str() + totalWritten;

#if defined PISTACHE_USE_SSL || defined PISTACHE_SSL_GNUTLS
                auto it = peers.find(fd);

                if (it == std::end(peers))
                    throw std::runtime_error("No peer found for fd: " + std::to_string(fd));

#endif // defined PISTACHE_USE_SSL || defined PISTACHE_SSL_GNUTLS
#ifdef PISTACHE_USE_SSL
                if (it->second->ssl() != NULL) {
                    bytesWritten = SSL_write((SSL *)it->second->ssl(), ptr, len);
                }
#endif /* PISTACHE_USE_SSL */
#ifdef PISTACHE_SSL_GNUTLS
                if( it->second->session ){
                    int ret;
                    do {
                        ret = gnutls_record_send( it->second->session, ptr, len );
                    } while( ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN );
                    if( ret < 0 ){
                        // Fatal GnuTLS error that requres the session to be terminated
                        if( gnutls_error_is_fatal( ret ) != 0 ){
                            throw std::runtime_error( gnutls_strerror( ret ) );
                        }
                    }
                }
#endif // PISTACHE_SSL_GNUTLS
#if !defined PISTACHE_USE_SSL && !defined PISTACHE_SSL_GNUTLS
                bytesWritten = ::send(fd, ptr, len, flags);
#endif // !defined PISTACHE_USE_SSL && !defined PISTACHE_SSL_GNUTLS
            } else {
                auto file = buffer.fd();
                off_t offset = totalWritten;
                bytesWritten = ::sendfile(fd, file, &offset, len);
            }
            if (bytesWritten < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {

                    auto bufferHolder = buffer.detach(totalWritten);

                    // pop_front kills buffer - so we cannot continue loop or use buffer after this point
                    wq.pop_front();
                    wq.push_front(WriteEntry(std::move(deferred), bufferHolder, flags));
                    reactor()->modifyFd(key(), fd, NotifyOn::Read | NotifyOn::Write, Polling::Mode::Edge);
                }
                else {
                    cleanUp();
                    deferred.reject(Pistache::Error::system("Could not write data"));
                }
                break;
            }
            else {
                totalWritten += bytesWritten;
                if (totalWritten >= buffer.size()) {
                    if (buffer.isFile()) {
                        // done with the file buffer, nothing else knows whether to
                        // close it with the way the code is written.
                        ::close(buffer.fd());
                    }

                    cleanUp();

                    // Cast to match the type of defered template
                    // to avoid a BadType exception
                    deferred.resolve(static_cast<ssize_t>(totalWritten));
                    break;
                }
            }
        }
    }
}

void
Transport::armTimerMs(
        Fd fd, std::chrono::milliseconds value,
        Async::Deferred<uint64_t> deferred) {

    auto ctx = context();
    const bool isInRightThread = std::this_thread::get_id() == ctx.thread();
    TimerEntry entry(fd, value, std::move(deferred));

    if (!isInRightThread) {
        timersQueue.push(std::move(entry));
    } else {
        armTimerMsImpl(std::move(entry));
    }
}

void
Transport::armTimerMsImpl(TimerEntry entry) {

    auto it = timers.find(entry.fd);
    if (it != std::end(timers)) {
        entry.deferred.reject(std::runtime_error("Timer is already armed"));
        return;
    }

    itimerspec spec;
    spec.it_interval.tv_sec = 0;
    spec.it_interval.tv_nsec = 0;

    if (entry.value.count() < 1000) {
        spec.it_value.tv_sec = 0;
        spec.it_value.tv_nsec
            = std::chrono::duration_cast<std::chrono::nanoseconds>(entry.value).count();
    } else {
        spec.it_value.tv_sec
            = std::chrono::duration_cast<std::chrono::seconds>(entry.value).count();
        spec.it_value.tv_nsec = 0;
    }

    int res = timerfd_settime(entry.fd, 0, &spec, 0);
    if (res == -1) {
        entry.deferred.reject(Pistache::Error::system("Could not set timer time"));
        return;
    }

    reactor()->registerFdOneShot(key(), entry.fd, NotifyOn::Read, Polling::Mode::Edge);
    timers.insert(std::make_pair(entry.fd, std::move(entry)));
}

void
Transport::handleWriteQueue() {
    // Let's drain the queue
    for (;;) {
        auto write = writesQueue.popSafe();
        if (!write) break;

        auto fd = write->peerFd;
        if (!isPeerFd(fd)) continue;

        {
            Guard guard(toWriteLock);
            toWrite[fd].push_back(std::move(*write));
        }

        reactor()->modifyFd(key(), fd, NotifyOn::Read | NotifyOn::Write, Polling::Mode::Edge);
    }
}

void
Transport::handleTimerQueue() {
    for (;;) {
        auto timer = timersQueue.popSafe();
        if (!timer) break;

        armTimerMsImpl(std::move(*timer));
    }
}

void
Transport::handlePeerQueue() {
    for (;;) {
        auto data = peersQueue.popSafe();
        if (!data) break;

        handlePeer(data->peer);
    }
}

void
Transport::handlePeer(const std::shared_ptr<Peer>& peer) {
    int fd = peer->fd();
    peers.insert(std::make_pair(fd, peer));

    peer->associateTransport(this);

    handler_->onConnection(peer);
    reactor()->registerFd(key(), fd, NotifyOn::Read | NotifyOn::Shutdown, Polling::Mode::Edge);
}

void
Transport::handleNotify() {
    while (this->notifier.tryRead()) ;

    rusage now;

    auto res = getrusage(RUSAGE_THREAD, &now);
    if (res == -1)
        loadRequest_.reject(std::runtime_error("Could not compute usage"));

    loadRequest_.resolve(now);
    loadRequest_.clear();
}

void
Transport::handleTimer(TimerEntry entry) {
    if (entry.isActive()) {
        uint64_t numWakeups;
        int res = ::read(entry.fd, &numWakeups, sizeof numWakeups);
        if (res == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            else
                entry.deferred.reject(Pistache::Error::system("Could not read timerfd"));
        } else {
            if (res != sizeof(numWakeups)) {
                entry.deferred.reject(Pistache::Error("Read invalid number of bytes for timer fd: "
                            + std::to_string(entry.fd)));
            }
            else {
                entry.deferred.resolve(numWakeups);
            }
        }
    }
}

bool
Transport::isPeerFd(Fd fd) const {
    return peers.find(fd) != std::end(peers);
}

bool
Transport::isTimerFd(Fd fd) const {
    return timers.find(fd) != std::end(timers);
}

bool
Transport::isPeerFd(Polling::Tag tag) const {
    return isPeerFd(tag.value());
}
bool
Transport::isTimerFd(Polling::Tag tag) const {
    return isTimerFd(tag.value());
}

std::shared_ptr<Peer>&
Transport::getPeer(Fd fd)
{
    auto it = peers.find(fd);
    if (it == std::end(peers))
    {
        throw std::runtime_error("No peer found for fd: " + std::to_string(fd));
    }
    return it->second;
}

std::shared_ptr<Peer>&
Transport::getPeer(Polling::Tag tag)
{
    return getPeer(tag.value());
}

} // namespace Tcp
} // namespace Pistache
