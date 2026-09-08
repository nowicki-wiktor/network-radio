#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include <netdb.h>
#include <poll.h>
#include <climits>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <cstring>
#include <cctype>
#include <cerrno>

// kod odpowiedzi OK
#define OK 200

// rozpoznawane stany nagłowka
#define HEADER_TIMEOUT -10
#define HEADER_EOF -11
#define HEADER_QUIT -12
#define HEADER_ERROR -13

// rozpoznawane stany połączenia
#define CONN_EOF -1
#define CONN_ERROR -2
#define CONN_WANT_READ -4
#define CONN_WANT_WRITE -5

// zmienne globalne (początkowo ustawione na wartości domyślne)
std::string g_url; // url z ktorym się łączymy
bool g_request_meta = false; // czy wysyłamy prośbę o multipleksowanie
int g_timeout = 5000; // timeout na odebrania danych od serwera, w milisekundach
int g_ip_version = AF_UNSPEC; // wersja IP ktorej używamy
int g_verbosity = 2; // zakres informacji wypisywanych na stderr
std::string g_stdin_buffer; // bufor na znaki wpisywane przez użytkownika na stdin
bool g_stdin_open = true; // czy stdin jest otwarte

// dwie powyższe zmienne pomagają wykrywać czy użytkownik wpisał "quit"

// stuktura na sparsowany URL
struct ParsedUrl {
    std::string scheme;
    std::string host;
    std::string port;
    std::string path;
};

// reprezentuje jedno połączenie TCP z możliwością nałożenia
// szyfrowania SSL na to połączenie
struct Connection {
    int fd = -1;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    bool use_ssl = false;
};

// możliwe rozpoznawane stany transmisji danych (muzyki)
enum class StreamStatus {
    FINISHED, // serwer zamknął połączenie lub normalny koniec
    RECONNECT, // timeout zamykamy socket i łączymy się ponownie
    ERROR, // błąd krytyczny
    QUIT
};

// rozpoznawane stany czytania z gniazdka
enum class ReadExactStatus {
    OKAY,
    TIMEOUT,
    SERVER_CLOSED,
    ERROR,
    QUIT
};

ssize_t read_with_timeout(Connection& conn, char* buffer, size_t length);

// zwraca string zawierający opis błędu
// spowodowany przez SSL
std::string openssl_error_string()
{
    unsigned long err = ERR_get_error();

    if (err == 0)
        return "unknown OpenSSL error";

    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

// zamyka połączenie TCP. obudowanie funkcji
// close(), rozszerzony o obsługę połączenia szyfrowanego
void close_connection(Connection& conn)
{
    if (conn.ssl != nullptr)
    {
        SSL_shutdown(conn.ssl);
        SSL_free(conn.ssl);
        conn.ssl = nullptr;
    }

    if (conn.ctx != nullptr)
    {
        SSL_CTX_free(conn.ctx);
        conn.ctx = nullptr;
    }

    if (conn.fd != -1)
    {
        // właściwe zamknięcie połączenia
        close(conn.fd);
        conn.fd = -1;
    }

    conn.use_ssl = false;
}

// wypisuje aktualną datę i czas na stderr
void print_current_time(void)
{
    if (g_verbosity >= 1)
    {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::cerr << std::put_time(std::localtime(&time), "%Y.%m.%d %H.%M.%S") << "\n";
    }
}

// wypisuje msg na stderr jeśli tylko priorytet wiadomości (lvl) jest niższy bądź rowny
// podanemu zakresowi informacji
void log_msg(const std::string& msg, int lvl)
{
    if (g_verbosity >= lvl)
    {
        std::cerr << msg << "\n";
    }
}

// Konwertuje napis na liczbę 32-bitową bez znaku
// ktora napis reprezentuje.
// W porownaniu do np. funkcji stoi(), nie tolerujemy
// żadnych innych znakow w napisie oprocz cyfr.
// zatem parse_int_strict("123") = true, 
// parse_int_strict("0") = true, ale już
// parse_int_strict(" 123") = false,
// parse_int_strict("123a") = false,
// parse_int_strict("-123") = false
bool parse_int_strict(const std::string& s, int& out)
{
    if (s.empty())
        return false;

    int value = 0;

    for (char c : s)
    {
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;

        int digit = c - '0';

        if (value > (INT_MAX - digit)/ 10)
            return false;

        value = value * 10 + digit;
    }

    out = value;
    return true;
}

// Dodaje warstwę szyfrowania SSL do instniejącego już połączenia TCP
// i nawiązuje połączenie szyfrowane
bool setup_ssl_if_needed(Connection& conn, const ParsedUrl& url)
{
    // jeśli http to nie mamy co robić
    if (url.scheme == "http")
    {
        conn.use_ssl = false;
        log_msg("using plain HTTP connection", 4);
        return true;
    }

    // nieznany protokoł
    if (url.scheme != "https")
    {
        log_msg("unsupported URL scheme: " + url.scheme, 2);
        return false;
    }

    // używamy SSL do szyfrowania
    conn.use_ssl = true;

    log_msg("starting TLS handshake", 1);

    // kontekst/konfiguracja 
    conn.ctx = SSL_CTX_new(TLS_client_method());
    if (conn.ctx == nullptr)
    {
        log_msg("SSL_CTX_new failed: " + openssl_error_string(), 2);
        return false;
    }
    // wyłącz weryfikację ceryfikatu serwera
    SSL_CTX_set_verify(conn.ctx, SSL_VERIFY_NONE, nullptr);
    log_msg("TLS certificate verification disabled", 4);

    // stworz obiek sesji SSL
    conn.ssl = SSL_new(conn.ctx);
    if (conn.ssl == nullptr)
    {
        log_msg("SSL_new failed: " + openssl_error_string(), 2);
        return false;
    }
    
    // używaj conn.fd jako transport dla TLS
    if (SSL_set_fd(conn.ssl, conn.fd) != 1)
    {
        log_msg("SSL_set_fd failed: " + openssl_error_string(), 2);
        return false;
    }

    if (!url.host.empty())
    {
        SSL_set_tlsext_host_name(conn.ssl, url.host.c_str());
    }

    // wykonaj połączenie TCP+TLS
    int ret = SSL_connect(conn.ssl);
    if (ret != 1)
    {
        int err = SSL_get_error(conn.ssl, ret);
        log_msg("SSL_connect failed, SSL_get_error=" + std::to_string(err) +
                ": " + openssl_error_string(), 2);
        return false;
    }

    // sukces
    log_msg("TLS connection established", 1);
    return true;
}

// Przeczytaj maksymalnie length bajtow z gniazdka
// Zwraca:
// >0 liczba przeczytanych bajtow
// CONN_EOF koniec połączenia
// CONN_ERROR błąd krytyczny
// CONN_WANT_READ sprobuj ponownie, gdy gniazdko będzie gotowe do czytania
// CONN_WANT_WRITE sprobuj ponownie, gdy gniazdko będzie gotowe do pisania
ssize_t connection_read_once(Connection& conn, char* buffer, size_t length)
{
    // jeśli nie używamy połączenia szyfrowanego
    if (!conn.use_ssl)
    {
        ssize_t n = read(conn.fd, buffer, length);

        if (n > 0) return n;

        if (n == 0) return CONN_EOF;

        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        {
            log_msg("temporary socket read failure", 3);
            return CONN_WANT_READ;
        }

        log_msg("socket read failed: " + std::string(strerror(errno)), 2);
        return CONN_ERROR;
    }

    // połączenie szyfrowane
    int requested = static_cast<int>(std::min(length, static_cast<size_t>(INT_MAX)));
    int n = SSL_read(conn.ssl, buffer, requested);

    // sukces
    if (n > 0) return n;

    int err = SSL_get_error(conn.ssl, n);

    if (err == SSL_ERROR_WANT_READ)
        return CONN_WANT_READ;

    if (err == SSL_ERROR_WANT_WRITE)
        return CONN_WANT_WRITE;

    if (err == SSL_ERROR_ZERO_RETURN)
        return CONN_EOF;

    if (err == SSL_ERROR_SYSCALL)
    {
        if (errno != 0)
        {
            log_msg("SSL_read syscall error: " + std::string(strerror(errno)), 2);
            return CONN_ERROR;
        }
        else
        {
            log_msg("SSL_read syscall EOF", 1);
            return CONN_EOF;
        }
    }

    log_msg("SSL_read failed, SSL_get_error=" + std::to_string(err) +
            ": " + openssl_error_string(), 2);

    // nierozpoznawany błąd
    return CONN_ERROR;
}

// Funkcja zamieniająca napis na małe litery.
std::string to_lowercase(const std::string& str)
{
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), 
                   [](unsigned char c){ return std::tolower(c); });
    return lower;
}

// Sprawdza czy host to literał ipv6 i jeśli tak to zapisuje
// ten adres w nawiasach kwadratowych
std::string host_for_display(const std::string& host)
{
    // ipv6, dodajemy nawiasy
    if (host.find(':') != std::string::npos)
        return "[" + host + "]";

    return host;
}

// Czyta co najwyżej 256 bajtow z stdin,
// sprawdza czy stdin jest nadal otwarty
// oraz czy ostatnie wpisane bajty to "quit\n".
// Zwraca true jeśli ostatnie 5 bajtow bufora to "quit\n",
// false wpp.
bool check_stdin_for_quit(void)
{
    char buf[256];

    // tą funkcję wołamy tylko z read_with_timeout() ktora
    // gwarantuje nam że co najmniej 1 bajt
    // będzie do przeczytania
    // a zatem poniższy read() nie jest blokujący

    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));

    // błąd
    if (n < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return false;

        log_msg("read from stdin failed: " + std::string(strerror(errno)), 3);
        g_stdin_open = false;
        return false;
    }

    // EOF
    if (n == 0)
    {
        g_stdin_open = false;
        return false;
    }

    // zapisz bajty jako string
    g_stdin_buffer.append(buf, static_cast<size_t>(n));

    if (g_stdin_buffer.size() >= 5 &&
        g_stdin_buffer.compare(g_stdin_buffer.size() - 5, 5, "quit\n") == 0)
    {
        log_msg("quit command received", 4);
        return true;
    }

    // Do wykrycia "quit\n" przeciętego granicą read() wystarczą
    // ostatnie 4 bajty poprzedniego bufora.
    if (g_stdin_buffer.size() > 4)
        g_stdin_buffer.erase(0, g_stdin_buffer.size() - 4);

    return false;
}

// Dla string url i wskaźnika na strukturę ParsedUrl parsuje url na cztery części:
// - scheme, - host, - port, -path
// jeśli nie można tak sparsować url to zwraca false,
// true wpp
bool parse_url(const std::string& url, ParsedUrl& out)
{
    out = ParsedUrl{};

    // znajdź pierwsze wystąpienie "://"
    size_t scheme_end = url.find("://");
    // jeśli nie ma
    if (scheme_end == std::string::npos)
        return false;

    out.scheme = to_lowercase(url.substr(0, scheme_end));

    if (out.scheme != "http" && out.scheme != "https")
        return false;

    size_t domain_start = scheme_end + 3;

    if (domain_start >= url.length())
        return false;

    // Domena kończy się na pierwszym '/', '?' lub '#'
    size_t domain_end = url.find_first_of("/?#", domain_start);

    std::string domain;
    if (domain_end == std::string::npos)
        domain = url.substr(domain_start);
    else
        domain = url.substr(domain_start, domain_end - domain_start);

    if (domain.empty())
        return false;

    // Ścieżka HTTP

    // brak ścieżki
    if (domain_end == std::string::npos)
    {
        out.path = "/";
    }
    // jest ścieżka podana 
    else
    {
        char middle_symbol = url[domain_end];

        if (middle_symbol == '/')
        {
            out.path = url.substr(domain_end);
        }
        else if (middle_symbol == '?')
        {
            out.path = "/" + url.substr(domain_end);
        }
        else
        {
            out.path = "/";
        }

        // jeśli w ścieżce jest symbol '#'
        size_t fragment_pos = out.path.find('#');

        // wytnijmy fragment do symbolu '#'
        if (fragment_pos != std::string::npos)
            out.path.resize(fragment_pos);

        if (out.path.empty())
            out.path = "/";
    }

    // ipv6 literał
    if (domain[0] == '[')
    {
        size_t close_bracket = domain.find(']');

        // nie ma nawiasu zamykającego
        if (close_bracket == std::string::npos)
            return false;

        // usuwamy nawiasy
        out.host = domain.substr(1, close_bracket - 1);

        if (out.host.empty())
            return false;

        // nie podano portu
        if (close_bracket + 1 == domain.length())
        {
            out.port = (out.scheme == "https") ? "443" : "80";
        }
        // podano port
        else
        {
            if (domain[close_bracket + 1] != ':')
                return false;

            out.port = domain.substr(close_bracket + 2);

            if (out.port.empty())
                return false;
        }
    }
    else
    {
        size_t colon_pos = domain.find(':');

        if (colon_pos == std::string::npos)
        {
            out.host = domain;
            out.port = (out.scheme == "https") ? "443" : "80";
        }
        else
        {
            // jeżeli jest więcej niż jeden dwukropek bez nawiasów
            // to jest to niepoprawny literał ipv6 bez [].
            if (domain.find(':', colon_pos + 1) != std::string::npos)
                return false;

            out.host = domain.substr(0, colon_pos);
            out.port = domain.substr(colon_pos + 1);

            if (out.host.empty() || out.port.empty())
                return false;
        }
    }

    if (out.host.empty() || out.port.empty())
        return false;

    int port_number;
    if (!parse_int_strict(out.port, port_number))
        return false;

    if (port_number <= 0 || port_number > 65535)
        return false;

    return true;
}

// Parsuje dostarczone argumenty i aktualizuje
// zmienne globalne
// Zwraca true jeśli linia argumentow była poprawna
// false wpp.
bool parse_args(int argc, char** argv)
{
    bool force_ipv4 = false;
    bool force_ipv6 = false;
    bool url_provided = false;

    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg.length() < 2 || arg[0] != '-')
            return false;

        for (size_t j = 1; j < arg.length(); j++)
        {
            char c = arg[j];

            if (c == 'm')
            {
                g_request_meta = true;
            }
            else if (c == '4')
            {
                force_ipv4 = true;
            }
            else if (c == '6')
            {
                force_ipv6 = true;
            }
            else if (c == 'q')
            {
                g_verbosity = 0;
            }
            else if (c == 'u' || c == 't' || c == 'v')
            {
                std::string val;

                // Obsługa postaci -uURL, -t5000, -v2
                if (j + 1 < arg.length())
                {
                    val = arg.substr(j + 1);
                    j = arg.length();
                }
                // Obsługa postaci -u URL, -t 5000, -v 2
                else
                {
                    if (i + 1 >= argc)
                        return false;

                    val = argv[++i];

                    // np. "-u -m" jest błędne.
                    if (val.empty() || val[0] == '-')
                        return false;
                }

                if (c == 'u')
                {
                    if (val.empty())
                        return false;

                    g_url = val;
                    url_provided = true;
                }
                else if (c == 't')
                {
                    int parsed_timeout;

                    if (!parse_int_strict(val, parsed_timeout))
                        return false;

                    if (parsed_timeout < 100 || parsed_timeout > 100000)
                        return false;

                    g_timeout = parsed_timeout;
                }
                else // c == 'v'
                {
                    int parsed_verbosity;

                    if (!parse_int_strict(val, parsed_verbosity))
                        return false;

                    if (parsed_verbosity < 0 || parsed_verbosity > 4)
                        return false;

                    g_verbosity = parsed_verbosity;
                }

                break;
            }
            else
            {
                return false;
            }
        }
    }

    if (!url_provided)
        return false;

    if (force_ipv4 && !force_ipv6)
        g_ip_version = AF_INET;
    else if (force_ipv6 && !force_ipv4)
        g_ip_version = AF_INET6;
    else
        g_ip_version = AF_UNSPEC;

    return true;
}

// Nawiąż połączenie TCP z serwerem o danych zapisanych
// w strukturze ParsedUrl
// Zwraca:
// -1 - jeśli nie udało się nawiązać połączenia
// >0 - deskryptor gniazdka, sukces
int connect_to_server(const ParsedUrl& url)
{
    struct addrinfo hints, *res;
    std::memset(&hints, 0, sizeof(hints));
    // użycie IPv4/v6
    hints.ai_family = g_ip_version;
    // TCP
    hints.ai_socktype = SOCK_STREAM;

    // wypisz czas oraz host, z ktorym się łączymy
    print_current_time();
    log_msg("resolving name " + host_for_display(url.host), 1);


    int err = getaddrinfo(url.host.c_str(), url.port.c_str(), &hints, &res);
    if (err != 0)
    {
        log_msg("getaddrinfo: " + std::string(gai_strerror(err)), 2);
        return -1;
    }

    int sockfd = -1;
    // iteruj po możliwych adresach
    for (auto curr = res; curr != nullptr; curr = curr->ai_next)
    {
        // sprobuj stworzyć socket
        sockfd = socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol);
        if (sockfd == -1)
        {
            log_msg("socket failed", 3);
            continue;
        }

        // przygotuj adres IP do wypisania

        // tablica w ktorej zapiszemy adres
        char ipstr[INET6_ADDRSTRLEN];
        void* addr;
        //ipv4
        if (curr->ai_family == AF_INET)
        {
            // zrzutuj adres
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)curr->ai_addr;
            addr = &(ipv4->sin_addr);
        }
        // ipv6
        else if (curr->ai_family == AF_INET6)
        {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)curr->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
        else
        {
            log_msg("unsupported address family returned by getaddrinfo", 3);
            close(sockfd);
            sockfd = -1;
            continue;
        }

        // zamień adres na tekst
        if (inet_ntop(curr->ai_family, addr, ipstr, sizeof(ipstr)) == nullptr)
        {
            log_msg("inet_ntop failed", 3);
            close(sockfd);
            sockfd = -1;
            continue;
        }

        std::string ip_log = std::string(ipstr);
        if (curr->ai_family == AF_INET6)
        {
            ip_log = "[" + ip_log + "]";
        }
        
        log_msg("connecting to server " + ip_log + ":" + url.port, 1);

        // połącz się z serwerem
        if (connect(sockfd, curr->ai_addr, curr->ai_addrlen) == 0)
        {
            log_msg("connected to server " + ip_log + ":" + url.port, 4);
            //sukces
            break;
        }

        log_msg("connect failed: " + std::string(strerror(errno)), 3);

        // szukamy dalej
        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);

    // nie znaleźliśmy żadnego adresu
    if (sockfd == -1)
    {
        log_msg("failed to connect to any address", 2);
    }

    return sockfd;
}

// Zapisuje dokładnie length bajtow z buffer na deskryptor sockfd
// Zwraca:
// true  - jeśli sukces
// false - wpp
bool write_exact_fd(int sockfd, const char* buffer, size_t length)
{
    size_t total = 0;
    while(total < length)
    {
        ssize_t sent = write(sockfd, buffer + total, length - total);

        if (sent == 0)
        {
            log_msg("write returned 0", 2);
            return false;
        }
        if (sent < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            {
                log_msg("temporary write failure", 3);
                continue;
            }
            // zamknięcie potoku
            else if (errno == EPIPE)
            {
                log_msg("output pipe closed", 2);
                return false;
            }
            else 
            {
                log_msg("write failed", 2);
                return false;
            }
        }        

        total += (size_t)sent;
    }

    return true;
}

// Zapisz dokładnie length bajtow z buffera do socketu.
// Obsługuje TCP oraz TCP+TLS
// Zwraca true jeśli sukces
// false wpp.
bool write_exact(Connection& conn, const char* buffer, size_t length)
{
    size_t total = 0;

    while (total < length)
    {
        // bez szyfrowania
        if (!conn.use_ssl)
        {
            ssize_t sent = write(conn.fd, buffer + total, length - total);
            
            // EOF
            if (sent == 0)
            {
                log_msg("socket write returned 0", 2);
                return false;
            }

            // błąd
            if (sent < 0)
            {
                // przerwanie
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    log_msg("temporary socket write failure", 3);
                    continue;
                }
                
                // inny błąd
                log_msg("write failed: " + std::string(strerror(errno)), 2);
                return false;
            }

            total += static_cast<size_t>(sent);
        }
        // szyfrowanie
        else
        {
            // SSL_write przyjmuje liczbę bajtow
            // do przeczytania jako zwykły int
            int to_write = static_cast<int>(
                std::min(length - total, static_cast<size_t>(INT_MAX))
            );

            int sent = SSL_write(conn.ssl, buffer + total, to_write);

            if (sent > 0)
            {
                total += static_cast<size_t>(sent);
                continue;
            }

            int err = SSL_get_error(conn.ssl, sent);

            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                log_msg("SSL_write wants retry, SSL_get_error=" + std::to_string(err), 4);
                continue;
            }

            log_msg("SSL_write failed, SSL_get_error=" + std::to_string(err) +
                    ": " + openssl_error_string(), 2);

            return false;
        }
    }

    return true;
}

// Czyta dokładnie length bajtow najpierw z partial_audio a potem z deskryptora sockfd
// i zapisuje dane do buffer.
// Zwraca jeden ze stanow opisanych w enum ReadExactStatus
ReadExactStatus read_exact(Connection& conn, std::string& partial_audio, char* buffer, size_t length)
{
    size_t total = 0;

    // najpierw czytamy z partial_audio
    if (!partial_audio.empty())
    {
        size_t take = std::min(partial_audio.length(), length);
        std::memcpy(buffer, partial_audio.data(), take);
        partial_audio.erase(0, take);
        total += take;
    }

    while (total < length)
    {
        // przeczytaj bajty z gniazdka
        ssize_t bytes = read_with_timeout(conn, buffer + total, length - total);

        // coś przeczytaliśmy
        if (bytes > 0)
        {
            total += static_cast<size_t>(bytes);
        }
        // timeout
        else if (bytes == 0)
        {
            return ReadExactStatus::TIMEOUT;
        }
        // EOF
        else if (bytes == -1)
        {
            return ReadExactStatus::SERVER_CLOSED;
        }
        // użytkownik wpisał "quit"
        else if (bytes == -3)
        {
            return ReadExactStatus::QUIT;
        }
        // inny błąd krytyczny
        else
        {
            return ReadExactStatus::ERROR;
        }
    }

    return ReadExactStatus::OKAY;
}

// Czyta bajty z połączenia z uwzględnieniem timeoutu.
// Działa zarowno dla samego TCP, jak i z TLS.
// Jednocześnie obserwuje stdin, żeby wykryć komendę "quit".
// Zwraca:
// > 0 - liczba wczytanych bajtow
// 0 - przekroczono timeout
// -1 - serwer zamknął połączenie, EOF
// -2 - błąd krytyczny
// -3 - użytkownik wpisał quit
ssize_t read_with_timeout(Connection& conn, char* buffer, size_t length)
{
    // zaczynamy odliczanie
    auto start = std::chrono::steady_clock::now();

    // na co czekamy? (najpierw na coś do przeczytania)
    short socket_events = POLLIN;

    while (true)
    {
        // obserwujemy dwa desktyptory
        struct pollfd pfds[2];

        // pierwszy to gniazdko sieciowe
        pfds[0].fd = conn.fd;
        pfds[0].events = socket_events;
        pfds[0].revents = 0;

        nfds_t nfds = 1;

        // drugi to stdin ale tylko jeśli jest on dostępny;
        // sprawdzamy czy jest otwarty oraz czy gniazdko sieciowe
        // nie ma numeru deskryptora stdin
        if (g_stdin_open && STDIN_FILENO != conn.fd)
        {
            pfds[1].fd = STDIN_FILENO;
            pfds[1].events = POLLIN;
            pfds[1].revents = 0;
            nfds = 2;
        }

        auto now = std::chrono::steady_clock::now();
        // ile minęło od wywołania tej instancji funkcji
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();

        // do timeoutu pozostało
        int remaining_timeout = g_timeout - static_cast<int>(elapsed);

        if (remaining_timeout <= 0)
        {
            log_msg("data receiving timeout", 1);
            return 0;
        }

        int ret = poll(pfds, nfds, remaining_timeout);

        // błąd
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                log_msg("poll interrupted by signal", 4);
                continue;
            }  

            log_msg("poll failed: " + std::string(strerror(errno)), 2);
            return -2;
        }

        // timeout
        if (ret == 0)
        {
            log_msg("data receiving timeout", 1);
            return 0;
        }

        // jeśli czekaliśmy na stdin
        if (g_stdin_open && nfds == 2)
        {
            if (pfds[1].revents & POLLIN)
            {
                // sprawdzmy czy użytkownik wpisał "quit"
                if (check_stdin_for_quit())
                    return -3;
            }

            // jeśli błąd na deskryptorze...
            if (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL))
            {
                // ...to zamykamy
                g_stdin_open = false;
                log_msg("stdin is no longer available", 3);
            }
        }

        // coś wydarzyło się na gniazdku
        if (pfds[0].revents & (socket_events | POLLERR | POLLHUP | POLLNVAL))
        {
            if (pfds[0].revents & POLLERR)
            {
                log_msg("poll reported socket error", 4);
            }
            if (pfds[0].revents & POLLHUP)
            {
                log_msg("poll reported socket hangup", 4);
            }
            if (pfds[0].revents & POLLNVAL)
            {
                log_msg("poll reported invalid socket descriptor", 2);
                return -2;
            }
            
            // przeczytaj dane z gniazdka
            ssize_t n = connection_read_once(conn, buffer, length);

            if (n > 0) return n;

            // EOF
            if (n == CONN_EOF)
            {
                log_msg("server closed connection", 1);
                return -1;
            }

            // błąd krytyczny
            if (n == CONN_ERROR) return -2;

            // nie jesteśmy gotowi na czytanie (TLS)
            if (n == CONN_WANT_READ)
            {
                socket_events = POLLIN;
                continue;
            }
            
            // nie jesteśmy gotowi na pisanie (TLS)
            if (n == CONN_WANT_WRITE)
            {
                socket_events = POLLOUT;
                continue;
            }

            log_msg("unknown connection read result", 2);
            return -2;
        }
    }
}

// Zwraca nowy string będący msg z usuniętymi spacjami na brzagach
// (o ile takie występują)
std::string trim_whitespace(const std::string& msg)
{
    size_t start = 0;
    while (start < msg.size() && std::isspace(static_cast<unsigned char>(msg[start])))
        start++;

    size_t end = msg.size();
    while (end > start && std::isspace(static_cast<unsigned char>(msg[end - 1])))
        end--;

    return msg.substr(start, end - start);
}

// Dodaje cookie do nagłowka Cookie albo zastępuje poprzednie cookie
// o tej samej nazwie.
void add_or_replace_cookie(std::string& cookie_header, const std::string& new_cookie)
{
    size_t eq_pos = new_cookie.find('=');
    if (eq_pos == std::string::npos || eq_pos == 0)
        return;

    std::string new_name = new_cookie.substr(0, eq_pos);
    std::vector<std::string> cookies;
    bool replaced = false;
    size_t start = 0;

    while (start < cookie_header.size())
    {
        size_t end = cookie_header.find("; ", start);
        std::string current;

        if (end == std::string::npos)
        {
            current = cookie_header.substr(start);
            start = cookie_header.size();
        }
        else
        {
            current = cookie_header.substr(start, end - start);
            start = end + 2;
        }

        size_t current_eq_pos = current.find('=');
        if (current_eq_pos != std::string::npos &&
            current.substr(0, current_eq_pos) == new_name)
        {
            if (!replaced)
            {
                cookies.push_back(new_cookie);
                replaced = true;
            }
        }
        else if (!current.empty())
        {
            cookies.push_back(current);
        }
    }

    if (!replaced)
        cookies.push_back(new_cookie);

    cookie_header.clear();
    for (size_t i = 0; i < cookies.size(); i++)
    {
        if (i > 0)
            cookie_header += "; ";
        cookie_header += cookies[i];
    }
}

// Przetwarza nagłowek odpowiedzi z serwera.
// sockfd to deskryptor gniazdka z ktorego czytamy
// metaint to wartość icy-metaint ktora otrzymujemy od serwera
// location to bufor na nowy url jeśli otrzymamy kod 301 lub 302 (przekierowanie)
// audio_data to bufor na przeczytane audio
// Zwraca:
// >0 - kod odpowiedzi serwera
// < 0 - odpowiedni błąd
int handle_header(Connection& conn, int& metaint, std::string& location, std::string& cookie, std::string& audio_data)
{
    std::string headers;
    char buf[1024];
    size_t end_pos;

    // dopoki nie przeczytaliśmy sekwencji "\r\n\r\n" od nadawcy
    while((end_pos = headers.find("\r\n\r\n")) == std::string::npos)
    {
        // czytaj z gniazdka
        ssize_t bytes = read_with_timeout(conn, buf, sizeof(buf));

        if (bytes == 0)
        {
            log_msg("timeout while reading headers", 3);
            return HEADER_TIMEOUT;
        }
        if (bytes == -1)
        {
            log_msg("server closed connection while reading headers", 1);
            return HEADER_EOF;
        }
        if (bytes == -3)
        {
            log_msg("quit while reading headers", 1);
            return HEADER_QUIT;
        }
        if (bytes == -2)
        {
            log_msg("error while reading headers", 2);
            return HEADER_ERROR;
        }

        headers.append(buf, bytes);

        // dziwny header
        if (headers.size() > 65536)
        {
            log_msg("response headers too large", 2);
            return HEADER_ERROR;
        }
    }

    // ponieważ mogliśmy przeczytać (i zapewne przeczytaliśmy)
    // nie tylko nagłowek, ale także strumień audio
    // to musimy zapisać te bajty
    audio_data = headers.substr(end_pos + 4); // + 4 bo "\r\n\r\n"
    headers.resize(end_pos);

    log_msg(headers + "\n", 1);

    if (!audio_data.empty())
    {
        log_msg("received " + std::to_string(audio_data.size()) +
                " bytes of audio together with headers", 4);
    }

    size_t first_line_end = headers.find("\r\n");
    if (first_line_end == std::string::npos)
    {
        log_msg("missing status line terminator", 2);
        return HEADER_ERROR;
    }

    // weź pierwszą linijkę
    std::string first_line = headers.substr(0, first_line_end);
    size_t space_pos = first_line.find(' ');
    if (space_pos == std::string::npos)
    {
        log_msg("malformed response status line: " + first_line, 2);
        return HEADER_ERROR;
    }

    // wyciągamy kod odpowiedzi (np. z "200 OK" wyciągnie 200)
    int status_code = 0;
    try
    {
        status_code = std::stoi(first_line.substr(space_pos + 1));
    }
    catch (...)
    {
        log_msg("cannot find the response code", 2);
        return HEADER_ERROR;
    }

    log_msg("received response code " + std::to_string(status_code), 4);
    
    // czytamy resztę
    metaint = 0;
    location = "";
    std::istringstream stream(headers);
    std::string line;

    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        
        std::string lower = to_lowercase(line); // zamień całą linijkę na małe litery
        if (lower.find("icy-metaint:") == 0) 
        {
            // nigdy nie chcieliśmy metadanych
            if (!g_request_meta)
            {
                log_msg("ignoring icy-metaint because metadata was not requested", 4);
                continue;
            }

            try
            {
                // "icy-metaint:" to 12 znakow; szukamy od 12 pozycji
                if (!parse_int_strict(trim_whitespace(lower.substr(12)), metaint))
                {
                    log_msg("invalid icy-metaint header: " + line, 2);
                    return HEADER_ERROR;
                }
                log_msg("received icy-metaint: " + std::to_string(metaint), 4);
            }
            catch (...)
            {
                log_msg("invalid icy-metaint header: " + line, 2);
                return HEADER_ERROR;
            }
        }
        else if (lower.find("location:") == 0)
        {
            size_t start = 9; // "location:" to 9 znakow
            // pomiń spacje
            while (start < line.length() && line[start] == ' ') start++;
            // nowa lokalizacja
            location = line.substr(start);
            log_msg("received redirect location: " + location, 4);
        }
        else if (lower.find("set-cookie:") == 0)
        {
            size_t start = 11; // "set-cookie:" to 11 znakow

            while (start < line.length() &&
                std::isspace(static_cast<unsigned char>(line[start])))
            {
                start++;
            }

            size_t end = line.find(';', start);
            std::string new_cookie = line.substr(start, end - start);

            // doklejamy nowy cookie
            if (!new_cookie.empty())
            {
                add_or_replace_cookie(cookie, new_cookie);
                log_msg("received cookie: " + new_cookie, 4);
            }
        }
    }

    return status_code;
}

// Odbiera strumień z serwera i rodziela go na audio oraz ewentualne
// metadane ICY.
// Zwraca StreamStatus
StreamStatus stream_audio_stdout(Connection& conn, const std::string& partial_audio, int metaint)
{
    // najpierw zużywamy partial_audio
    std::string audio_buffer = partial_audio;

    if (!audio_buffer.empty())
    {
        log_msg("initial buffered audio bytes: " + std::to_string(audio_buffer.size()), 4);
    }

    // brak multipleksowania metadanych
    // traktujemy wszystkie dane jak audio
    if (metaint == 0)
    {
        log_msg("metadata multiplexing disabled", 4);

        if (!audio_buffer.empty())
        {
            // wypisz najpierw wszystko z audio_buffer
            if (!write_exact_fd(STDOUT_FILENO, audio_buffer.c_str(), audio_buffer.length()))
            {
                log_msg("failed to write " + std::to_string(audio_buffer.length()) 
                                + " bytes to stdout", 2);
                return StreamStatus::ERROR;
            }     
        }

        char buf[4096];

        while (true)
        {
            // czytaj bajty z gniazdka
            ssize_t bytes = read_with_timeout(conn, buf, sizeof(buf));
            
            // jeśli sukces i coś przeczytaliśmy
            if (bytes > 0)
            {
                log_msg("received " + std::to_string(bytes) + " bytes of audio from the server", 4);
                // wypisz na stdout
                if (!write_exact_fd(STDOUT_FILENO, buf, static_cast<size_t>(bytes)))
                {
                    log_msg("failed to write " + std::to_string(bytes) 
                                + " bytes to stdout", 2);
                    return StreamStatus::ERROR;
                }   
            }
            // jeśli timeout
            else if (bytes == 0)
            {
                log_msg("timeout from the server", 3);
                // łączymy się ponownie
                return StreamStatus::RECONNECT;
            }
            // jeśli EOF
            else if (bytes == -1)
            {
                log_msg("the server sent EOF", 3);
                return StreamStatus::FINISHED;
            }
            // uzytkownik wpisał "quit"
            else if (bytes == -3)
            {
                return StreamStatus::QUIT;
            }
            // inny, krytyczny błąd
            else
            {
                log_msg("unknown error while reading from socket", 2);
                return StreamStatus::ERROR;
            }
        }
    }

    // multipleksowanie

    // audio_bytes_left bajtow audio trzeba jeszcze
    // przeczytać zanim nadejdzie blok metadanych
    size_t audio_bytes_left = static_cast<size_t>(metaint);
    char buf[4096];

    log_msg("metadata multiplexing enabled with interval: " + std::to_string(metaint), 4);

    while (true)
    {
        // otrzymujemy audio
        if (audio_bytes_left > 0)
        {
            // ile czytamy
            size_t to_read = std::min(sizeof(buf), audio_bytes_left);
            size_t actually_read = 0;

            // jeśli jeszcze mamy dane w buforze,
            // bierzemy audio z bufora
            if (!audio_buffer.empty())
            {
                actually_read = std::min(audio_buffer.length(), to_read);
                std::memcpy(buf, audio_buffer.data(), actually_read);
                audio_buffer.erase(0, actually_read);
            }
            else
            {
                // czytaj bajty-audio z gniazdka
                ssize_t bytes = read_with_timeout(conn, buf, to_read);

                // przeczytaliśmy bajty z sukcesem
                if (bytes > 0)
                {
                    log_msg("received " + std::to_string(bytes) + " bytes of audio from the server", 4);
                    actually_read = static_cast<size_t>(bytes);
                }
                // timeout
                else if (bytes == 0)
                {
                    log_msg("timeout from the server", 3);
                    return StreamStatus::RECONNECT;
                }
                // EOF
                else if (bytes == -1)
                {
                    log_msg("the server sent EOF", 3);
                    return StreamStatus::FINISHED;
                }
                // użytkownik wpisał "quit"
                else if (bytes == -3)
                {
                    return StreamStatus::QUIT;
                }
                // błąd krytyczny
                else
                {
                    log_msg("unknown error while reading audio data from socket", 2);
                    return StreamStatus::ERROR;
                }
            }

            // wypisz bajty na stdout
            if (!write_exact_fd(STDOUT_FILENO, buf, actually_read))
            {
                log_msg("failed to write " + std::to_string(actually_read) 
                                + " bytes to stdout", 2);
                return StreamStatus::ERROR;
            }
                
            audio_bytes_left -= actually_read;
        }
        // otrzymujemy metadane
        else
        {
            char len_byte;

            // pierwszy bajt metadanych to liczba
            // bajtow metadanych pozostałych do przeczytania
            ReadExactStatus len_status = read_exact(conn, audio_buffer, &len_byte, 1);

            if (len_status == ReadExactStatus::TIMEOUT)
            {
                log_msg("timeout while reading metadata length byte", 3);
                return StreamStatus::RECONNECT;
            }

            if (len_status == ReadExactStatus::SERVER_CLOSED)
            {
                log_msg("server closed connection while reading metadata length byte", 1);
                return StreamStatus::FINISHED;
            }

            if (len_status == ReadExactStatus::QUIT)
            {
                log_msg("quit command received while reading metadata length byte", 1);
                return StreamStatus::QUIT;
            }

            if (len_status == ReadExactStatus::ERROR)
            {
                log_msg("error while reading metadata length byte", 2);
                return StreamStatus::ERROR;
            }
            // ile bajtow metadanych?
            size_t meta_len = static_cast<unsigned char>(len_byte) << 4;

            if (meta_len > 0)
            {
                std::vector<char> meta_buf(meta_len);

                // czytaj metadane z gniazdka
                ReadExactStatus meta_status = read_exact(conn, audio_buffer, meta_buf.data(), meta_len);

                if (meta_status == ReadExactStatus::TIMEOUT)
                {
                    log_msg("timeout while reading metadata", 3);
                    return StreamStatus::RECONNECT;
                }

                if (meta_status == ReadExactStatus::SERVER_CLOSED)
                {
                    log_msg("server closed connection while reading metadata", 1);
                    return StreamStatus::FINISHED;
                }

                if (meta_status == ReadExactStatus::QUIT)
                {
                    log_msg("quit command received while reading metadata", 1);
                    return StreamStatus::QUIT;
                }

                if (meta_status == ReadExactStatus::ERROR)
                {
                    log_msg("error while reading metadata", 2);
                    return StreamStatus::ERROR;
                }

                std::string meta_str(meta_buf.data(), meta_len);

                size_t null_pos = meta_str.find('\0');

                if (null_pos != std::string::npos)
                    meta_str.resize(null_pos);

                // wypisz metadane
                if (!meta_str.empty())
                {
                    if (!write_exact_fd(STDERR_FILENO, meta_str.data(), meta_str.size()))
                    {
                        log_msg("failed to write " + std::to_string(meta_str.size()) 
                                + " bytes to stderr", 2);
                        return StreamStatus::ERROR;
                    }

                    if (!write_exact_fd(STDERR_FILENO, "\n", 1))
                    {
                        log_msg("failed to write 1 byte to stderr", 2);
                        return StreamStatus::ERROR;
                    }
                }
            }
            // reset licznika
            audio_bytes_left = static_cast<size_t>(metaint);
        }
    }
}

// Wysyła żądanie HTTP do serwera
// Zwraca:
// true jeśli wysłano z sukcesem
// false wpp
bool send_http_request(Connection& conn, const ParsedUrl& url, const std::string& cookie)
{
    std::string request = "GET " + url.path + " HTTP/1.1\r\n";
    request += "Host: " + host_for_display(url.host) + "\r\n";
    request += "Connection: Keep-Alive\r\n";
    
    // jeśli dostaliśmy ciasteczko wcześniej
    if (!cookie.empty()) request += "Cookie: " + cookie + "\r\n";
    
    // jeśli włączono flagę -m
    if (g_request_meta) request += "Icy-MetaData: 1\r\n";
    
    request += "\r\n";
    
    log_msg(request, 1);

    if (!write_exact(conn, request.c_str(), request.length()))
    {
        log_msg("failed to send HTTP request", 2);
        return false;
    }

    log_msg("HTTP request sent", 4);
    return true;
}

int main(int argc, char** argv)
{
    // Jeśli odtwarzacz muzyki zakończy działanie
    // to domyślnie system operacyjny zabiłby proces
    // tego programu. Ustawiamy ignorowanie tej sytuacji
    // aby samodzielnie obsłużyć zamknięcie potoku
    signal(SIGPIPE, SIG_IGN);
    // parsuj argumenty i zapisz w zmiennych globalnych
    if (!parse_args(argc, argv))
    {
        std::cerr << "invalid arguments" << "\n";
        return 1;
    }

    // inicjalizacja bibliotek do obsługi https
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    std::string original_url = g_url;
    std::string current_request_url = original_url;
    std::string cookie = "";

    while (true)
    {
        ParsedUrl current_url;

        // parsuj aktualnie rozważany URL
        if (!parse_url(current_request_url, current_url))
        {
            log_msg("invalid URL format", 2);
            return 1;
        }

        Connection conn;

        // połącz się z serwerem, zwroć deskryptor gniazdka
        conn.fd = connect_to_server(current_url);
        if (conn.fd == -1)
            return 1;

        // jeśli używamy https, opakuj połączenie w TLS (SSL)
        if (!setup_ssl_if_needed(conn, current_url))
        {
            close_connection(conn);
            return 1;
        }

        // wyślij GET request do serwera
        if (!send_http_request(conn, current_url, cookie))
        {
            close_connection(conn);
            return 1;
        }

        int metaint = 0;
        std::string new_loc = "";
        std::string audio_beginning = "";

        // parsuj odpowiedź serwera
        int response = handle_header(conn, metaint, new_loc, cookie, audio_beginning);

        // timeout
        if (response == HEADER_TIMEOUT)
        {
            log_msg("reconnecting after header timeout", 3);
            close_connection(conn);
            current_request_url = original_url;
            cookie.clear();
            continue;
        }

        // zakończenie połączenia przez serwer lub użytkownik wpisał quit
        if (response == HEADER_EOF)
        {
            log_msg("server closed connection before stream started", 1);
            close_connection(conn);
            return 1;
        }
        if (response == HEADER_QUIT)
        {
            log_msg("terminating after quit command", 1);
            close_connection(conn);
            return 0;
        }

        // błąd krytyczny podczas obsługi nagłowka odpowiedzi
        if (response == HEADER_ERROR)
        {
            log_msg("header error", 2);
            close_connection(conn);
            return 1;
        }

        // jeśli otrzymaliśmy nową lokalizację zasobu ktorego szukamy (kody jak poniżej)
        if (response == 301 || response == 302  || response == 303  ||
            response == 307 || response == 308)
        {
            close_connection(conn);

            // brak nowego adresu, z ktorym moglibyśmy się połączyć
            if (new_loc.empty())
            {
                log_msg("redirect without location header", 2);
                return 1;
            }
            
            ParsedUrl temp;

            // sprawdź, czy otrzymany URL jest poprawnym adresem
            if (parse_url(new_loc, temp))
            {
                // jeśli tak, to zapisz go jako nowy g_url i powtorz pętle
                current_request_url = new_loc;
            }
            else
            {
                // jeśli nie, to być może jest tylko nową ścieżką do pliku
                // w tej samej domenie.

                // jeśli zawiera napis "://" to na pewno tak nie jest
                if (new_loc.find("://") != std::string::npos)
                {
                    log_msg("unsupported redirect location", 2);
                    return 1;
                }
                // Kontruujemuy nowy URL i zapisujemy do current_request_url. Jeśli
                // i tak nie jest poprawny, otrzymamy błąd w najbliższej iteracji
                // pętli.

                if (new_loc[0] != '/') new_loc = "/" + new_loc;
                
                current_request_url = current_url.scheme + "://" +
                                    host_for_display(current_url.host) + ":" +
                                    current_url.port + new_loc;
            }
            continue;
        }

        // otrzymaliśmy odpowiedź OK i możemy zacząć wypisywać bajty na wyjście.
        if (response == OK)
        {
            StreamStatus status = stream_audio_stdout(conn, audio_beginning, metaint);
            close_connection(conn);

            // zamknieto połączenie 
            if (status == StreamStatus::FINISHED) 
            {
                log_msg("stream finished", 1);
                return 0;
            }
            // użytkownik wpisał "quit"
            if (status == StreamStatus::QUIT)
            {
                log_msg("stream interrupted by quit command", 1);
                return 0;
            }
            // timeout, trzeba powtorzyć
            if (status == StreamStatus::RECONNECT)
            {
                log_msg("reconnecting after data receiving timeout", 3);
                current_request_url = original_url;
                cookie.clear();
                continue;
            }

            // błąd krytyczny
            log_msg("stream processing failed", 2);
            return 1;
        }

        // otrzymaliśmy kod odpowiedzi od serwera, ktorego nie znamy
        close_connection(conn);
        log_msg("not supported response code received: " + std::to_string(response), 2);
        return 1;
    }
}
