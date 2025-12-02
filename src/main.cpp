// src/main.cpp
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <optional>
#include <iomanip>
#include <sstream>
#include <atomic>
#include <map>
#include <memory>
#include <functional>
#include <regex>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

using json = nlohmann::json;
namespace beast = boost::beast;
namespace http  = beast::http;
namespace websocket = beast::websocket;
namespace asio  = boost::asio;
namespace ssl   = asio::ssl;
using tcp = asio::ip::tcp;

static std::mutex out_mtx;

// ----- Kalshi orderbook maintenance (for delta updates) -----
struct KalshiBook {
    // store in dollars for simplicity
    std::map<double,int, std::greater<double>> yes_bid_qty; // YES bids by price desc
    std::map<double,int, std::greater<double>> no_bid_qty;  // NO  bids by price desc

    void apply_snapshot(const json& snap) {
        yes_bid_qty.clear(); no_bid_qty.clear();

        // Prefer dollars if available
        if (snap.contains("yes_dollars") && snap["yes_dollars"].is_array()) {
            for (const auto& lvl : snap["yes_dollars"]) {
                double p=0; int q=0;
                if (lvl.is_array() && lvl.size() >= 2) {
                    if (lvl[0].is_string()) p = std::stod(lvl[0].get<std::string>());
                    else if (lvl[0].is_number()) p = lvl[0].get<double>();
                    if (lvl[1].is_string()) q = std::stoi(lvl[1].get<std::string>());
                    else if (lvl[1].is_number_integer()) q = lvl[1].get<int>();
                } else if (lvl.is_object()) {
                    if (lvl.contains("price")) {
                        if (lvl["price"].is_string()) p = std::stod(lvl["price"].get<std::string>());
                        else if (lvl["price"].is_number()) p = lvl["price"].get<double>();
                    }
                    if (lvl.contains("quantity")) {
                        if (lvl["quantity"].is_string()) q = std::stoi(lvl["quantity"].get<std::string>());
                        else if (lvl["quantity"].is_number_integer()) q = lvl["quantity"].get<int>();
                    }
                }
                if (q > 0) yes_bid_qty[p] = q;
            }
        } else if (snap.contains("yes") && snap["yes"].is_array()) {
            for (const auto& lvl : snap["yes"]) {
                double p=0; int q=0;
                if (lvl.is_array() && lvl.size() >= 2) {
                    if (lvl[0].is_string()) p = std::stod(lvl[0].get<std::string>()) * 0.01;
                    else if (lvl[0].is_number()) p = lvl[0].get<double>() * 0.01;
                    if (lvl[1].is_string()) q = std::stoi(lvl[1].get<std::string>());
                    else if (lvl[1].is_number_integer()) q = lvl[1].get<int>();
                }
                if (q > 0) yes_bid_qty[p] = q;
            }
        }

        if (snap.contains("no_dollars") && snap["no_dollars"].is_array()) {
            for (const auto& lvl : snap["no_dollars"]) {
                double p=0; int q=0;
                if (lvl.is_array() && lvl.size() >= 2) {
                    if (lvl[0].is_string()) p = std::stod(lvl[0].get<std::string>());
                    else if (lvl[0].is_number()) p = lvl[0].get<double>();
                    if (lvl[1].is_string()) q = std::stoi(lvl[1].get<std::string>());
                    else if (lvl[1].is_number_integer()) q = lvl[1].get<int>();
                }
                if (q > 0) no_bid_qty[p] = q;
            }
        } else if (snap.contains("no") && snap["no"].is_array()) {
            for (const auto& lvl : snap["no"]) {
                double p=0; int q=0;
                if (lvl.is_array() && lvl.size() >= 2) {
                    if (lvl[0].is_string()) p = std::stod(lvl[0].get<std::string>()) * 0.01;
                    else if (lvl[0].is_number()) p = lvl[0].get<double>() * 0.01;
                    if (lvl[1].is_string()) q = std::stoi(lvl[1].get<std::string>());
                    else if (lvl[1].is_number_integer()) q = lvl[1].get<int>();
                }
                if (q > 0) no_bid_qty[p] = q;
            }
        }
    }

    void apply_delta(const json& msg) {
        // Kalshi sends one of:
        // - {"delta":{"book_side":"bid"/"ask","price_cents":1234,"quantity_delta":+10}}
        // - {"side":"bid"/"ask", "price_dollars":1.23, "delta":+10}
        // - {"book_side":"bid"/"ask","price_dollars":"1.23","quantity_delta":+10}
        const json* d = &msg;
        if (msg.contains("delta") && msg["delta"].is_object()) d = &msg["delta"];

        if (!d->contains("quantity_delta") && !d->contains("delta")) return;

        // side/book_side can be "bid"/"ask" or "buy"/"sell"
        std::string side;
        if (d->contains("book_side")) side = (*d)["book_side"].get<std::string>();
        else if (d->contains("side"))  side = (*d)["side"].get<std::string>();
        else return;
        boost::to_lower(side);

        double px = 0.0;
        if (d->contains("price_dollars")) {
            if ((*d)["price_dollars"].is_string())
                px = std::stod((*d)["price_dollars"].get<std::string>());
            else
                px = (*d)["price_dollars"].get<double>();
        } else if (d->contains("price_cents")) {
            if ((*d)["price_cents"].is_string())
                px = std::stod((*d)["price_cents"].get<std::string>()) * 0.01;
            else
                px = (double)(*d)["price_cents"].get<int>() * 0.01;
        } else if (d->contains("price")) {
            if ((*d)["price"].is_string())
                px = std::stod((*d)["price"].get<std::string>());
            else
                px = (*d)["price"].get<double>();
        } else return;

        int dq = 0;
        if (d->contains("quantity_delta")) dq = (*d)["quantity_delta"].get<int>();
        else if (d->contains("delta"))      dq = (*d)["delta"].get<int>();

        // Map into YES/NO books:
        // - "bid" deltas update YES bid book
        // - "ask" deltas update NO bid book (for YES best ask = 1 - best NO bid)
        if (side == "bid" || side == "buy" || side == "b") {
            int new_q = (yes_bid_qty.count(px) ? yes_bid_qty[px] : 0) + dq;
            if (new_q <= 0) yes_bid_qty.erase(px);
            else yes_bid_qty[px] = new_q;
        } else if (side == "ask" || side == "sell" || side == "a") {
            int new_q = (no_bid_qty.count(px) ? no_bid_qty[px] : 0) + dq;
            if (new_q <= 0) no_bid_qty.erase(px);
            else no_bid_qty[px] = new_q;
        }
    }

    // Return YES best bid/ask (ask synthesized via complement: 1 - NO best bid)
    std::pair<std::optional<double>,std::optional<double>> bbo_yes() const {
        std::optional<double> bid, ask;
        if (!yes_bid_qty.empty()) bid = yes_bid_qty.begin()->first;           // max YES bid
        if (!no_bid_qty.empty())  ask = std::max(0.0, std::min(1.0, 1.0 - no_bid_qty.begin()->first));
        return {bid, ask};
    }
};

// ---- RSA-PSS signing for Kalshi (base64) ----
std::string b64_encode(const unsigned char* data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}

EVP_PKEY* load_private_key_pem(const std::string& pem_path) {
    FILE* fp = fopen(pem_path.c_str(), "rb");
    if (!fp) return nullptr;
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return pkey;
}

std::string sign_pss_base64(EVP_PKEY* pkey, const std::string& msg) {
    std::string sig_b64;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] ERROR: EVP_MD_CTX_new failed\n";
        return sig_b64;
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] ERROR: EVP_DigestSignInit failed\n";
        EVP_MD_CTX_free(ctx);
        return sig_b64;
    }

    EVP_PKEY_CTX* pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
    if (!pctx) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] ERROR: EVP_MD_CTX_get_pkey_ctx failed\n";
        EVP_MD_CTX_free(ctx);
        return sig_b64;
    }
    // Configure PSS
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0) { // saltlen = digest len
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] ERROR: Failed to set RSA-PSS padding/saltlen\n";
        EVP_MD_CTX_free(ctx);
        return sig_b64;
    }

    size_t siglen = 0;
    if (EVP_DigestSignUpdate(ctx, msg.data(), msg.size()) != 1 ||
        EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] ERROR: EVP_DigestSignUpdate/Final (length query) failed\n";
        EVP_MD_CTX_free(ctx);
        return sig_b64;
    }

    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSignFinal(ctx, sig.data(), &siglen) != 1) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] ERROR: EVP_DigestSignFinal (signature generation) failed\n";
        EVP_MD_CTX_free(ctx);
        return sig_b64;
    }
    EVP_MD_CTX_free(ctx);

    sig_b64 = b64_encode(sig.data(), siglen);
    return sig_b64;
}

std::vector<std::pair<std::string,std::string>> make_kalshi_auth_headers(
    const std::string& key_id,
    EVP_PKEY* pkey,
    const std::string& path)
{
    using namespace std::chrono;

    // Get current timestamp in milliseconds
    auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    const std::string ts = std::to_string(ms);

    // Log timestamp for clock skew debugging
    {
        std::time_t secs = ms / 1000;
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] Generating auth headers: now_ms=" << ms
                  << " (" << std::put_time(std::gmtime(&secs), "%F %T") << "Z)"
                  << " path=" << path << "\n";
    }

    // Build string to sign: timestamp + method + path
    const std::string to_sign = ts + "GET" + path; // path must be exactly "/trade-api/ws/v2"

    // Generate RSA-PSS signature
    const std::string sig_b64 = sign_pss_base64(pkey, to_sign);

    // Verify signature was generated successfully
    if (sig_b64.empty()) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] ERROR: Failed to generate RSA-PSS signature! "
                  << "Check that private key is valid.\n";
    } else {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] Signature generated: " << sig_b64.substr(0, 20) << "...\n";
    }

    return {
        {"KALSHI-ACCESS-KEY", key_id},
        {"KALSHI-ACCESS-SIGNATURE", sig_b64},
        {"KALSHI-ACCESS-TIMESTAMP", ts}
    };
}

// ----- utility: simple csv reader -----
std::vector<std::string> csv_split(const std::string &line) {
    std::vector<std::string> out;
    std::string cur;
    bool inq = false;
    for (size_t i=0;i<line.size();++i) {
        char c = line[i];
        if (c == '"' ) { inq = !inq; continue; }
        if (!inq && c == ',') { out.push_back(cur); cur.clear(); continue; }
        cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

std::optional<std::vector<std::string>> read_csv_row(const std::string &path, int row_idx, std::vector<std::string> &header_out) {
    std::ifstream f(path);
    if (!f) return std::nullopt;
    std::string line;
    if (!std::getline(f, line)) return std::nullopt;
    header_out = csv_split(line);
    int cur = 0;
    while (std::getline(f, line)) {
        ++cur;
        if (cur == row_idx) {
            return csv_split(line);
        }
    }
    return std::nullopt;
}

std::string trim_quotes(const std::string &s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') return s.substr(1,s.size()-2);
    return s;
}

// ----- case-insensitive contains -----
static bool icontains(const std::string& hay, const std::string& needle) {
    return boost::ifind_first(hay, needle);
}

// ----- HMAC-SHA256 hex -----
std::string hmac_sha256_hex(const std::string &key, const std::string &msg) {
    unsigned char *result;
    unsigned int len = EVP_MAX_MD_SIZE;
    result = HMAC(EVP_sha256(),
                  (const unsigned char*)key.data(), (int)key.size(),
                  (const unsigned char*)msg.data(), (int)msg.size(),
                  nullptr, nullptr);
    // HMAC returns static pointer, use separate call to get length
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(),
         (const unsigned char*)key.data(), (int)key.size(),
         (const unsigned char*)msg.data(), (int)msg.size(),
         md, &md_len);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i=0;i<md_len;++i) {
        oss << std::setw(2) << (int)md[i];
    }
    return oss.str();
}

// ----- Kalshi auth header maker (adjust to exact spec if needed) -----
struct KalshiAuth {
    std::string key;
    std::string secret; // raw secret string
};

std::vector<std::pair<std::string,std::string>> make_kalshi_auth_headers(const KalshiAuth &a) {
    using namespace std::chrono;
    auto ts = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    std::string ts_s = std::to_string(ts);
    // naive string to sign: timestamp + key (adjust for real spec)
    std::string to_sign = ts_s + a.key;
    std::string sig = hmac_sha256_hex(a.secret, to_sign);
    return {
        {"KALSHI-ACCESS-KEY", a.key},
        {"KALSHI-ACCESS-SIGNATURE", sig},
        {"KALSHI-ACCESS-TIMESTAMP", ts_s}
    };
}

// ----- shared state for best quotes -----
struct QuoteBook {
    std::mutex m;
    std::optional<double> best_bid;
    std::optional<double> best_ask;
    std::chrono::steady_clock::time_point last_update = std::chrono::steady_clock::now();

    void set_bid(double v){
        std::lock_guard lk(m);
        best_bid = v;
        last_update = std::chrono::steady_clock::now();
    }
    void set_ask(double v){
        std::lock_guard lk(m);
        best_ask = v;
        last_update = std::chrono::steady_clock::now();
    }
    // Use this when both sides are updated together
    void set_bbo(double bid, double ask){
        std::lock_guard lk(m);
        best_bid = bid;
        best_ask = ask;
        last_update = std::chrono::steady_clock::now();
    }
    struct Snapshot {
        std::optional<double> bid, ask;
        std::chrono::steady_clock::time_point ts;
    };
    Snapshot snap() {
        std::lock_guard lk(m);
        return {best_bid, best_ask, last_update};
    }
};

// ----- helpers to scan arrays of price levels -----
static std::optional<double> max_price_in_levels(const json& arr) {
    // handles [[price, qty], ...] or [{"price":..., "quantity":...}, ...]
    if (!arr.is_array() || arr.empty()) return std::nullopt;
    std::optional<double> mx;
    for (const auto& e : arr) {
        double p;
        if (e.is_array() && e.size() >= 1) {
            if (e[0].is_number()) {
                p = e[0].get<double>();
            } else if (e[0].is_string()) {
                try {
                    p = std::stod(e[0].get<std::string>());
                } catch (...) {
                    continue;
                }
            } else {
                continue;
            }
        } else if (e.is_object() && e.contains("price")) {
            if (e["price"].is_number()) {
                p = e["price"].get<double>();
            } else if (e["price"].is_string()) {
                try {
                    p = std::stod(e["price"].get<std::string>());
                } catch (...) {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        }
        mx = mx ? std::optional<double>(std::max(*mx, p)) : std::optional<double>(p);
    }
    return mx;
}

static std::optional<double> min_price_in_levels(const json& arr) {
    if (!arr.is_array() || arr.empty()) return std::nullopt;
    std::optional<double> mn;
    for (const auto& e : arr) {
        double p;
        if (e.is_array() && e.size() >= 1) {
            if (e[0].is_number()) {
                p = e[0].get<double>();
            } else if (e[0].is_string()) {
                try {
                    p = std::stod(e[0].get<std::string>());
                } catch (...) {
                    continue;
                }
            } else {
                continue;
            }
        } else if (e.is_object() && e.contains("price")) {
            if (e["price"].is_number()) {
                p = e["price"].get<double>();
            } else if (e["price"].is_string()) {
                try {
                    p = std::stod(e["price"].get<std::string>());
                } catch (...) {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        }
        mn = mn ? std::optional<double>(std::min(*mn, p)) : std::optional<double>(p);
    }
    return mn;
}

// ----- recursive search for a nested orderbook {bids, asks} -----
static bool extract_bbo_from_nested(const json& j, double& best_bid, double& best_ask) {
    if (j.is_object()) {
        // direct bids/asks object
        if (j.contains("bids") && j.contains("asks") && j["bids"].is_array() && j["asks"].is_array()) {
            if (auto bb = max_price_in_levels(j["bids"])) {
                if (auto ba = min_price_in_levels(j["asks"])) {
                    best_bid = *bb;
                    best_ask = *ba;
                    return true;
                }
            }
        }
        // Kalshi's bids_dollars/asks_dollars format
        if (j.contains("bids_dollars") && j.contains("asks_dollars") &&
            j["bids_dollars"].is_array() && j["asks_dollars"].is_array()) {
            if (auto bb = max_price_in_levels(j["bids_dollars"])) {
                if (auto ba = min_price_in_levels(j["asks_dollars"])) {
                    best_bid = *bb;
                    best_ask = *ba;
                    return true;
                }
            }
        }
        // Kalshi's bids_cents/asks_cents format
        if (j.contains("bids_cents") && j.contains("asks_cents") &&
            j["bids_cents"].is_array() && j["asks_cents"].is_array()) {
            if (auto bb = max_price_in_levels(j["bids_cents"])) {
                if (auto ba = min_price_in_levels(j["asks_cents"])) {
                    best_bid = *bb * 0.01; // convert cents to dollars
                    best_ask = *ba * 0.01;
                    return true;
                }
            }
        }
        // recurse through children
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (extract_bbo_from_nested(it.value(), best_bid, best_ask)) return true;
        }
    } else if (j.is_array()) {
        for (const auto& e : j) {
            if (extract_bbo_from_nested(e, best_bid, best_ask)) return true;
        }
    }
    return false;
}

// ----- Kalshi-specific YES/NO synthesis (prices may be cents or dollars) -----
static bool extract_bbo_from_kalshi_yesno(const json& j, double& best_bid, double& best_ask) {
    auto has_yes = j.contains("yes") && j["yes"].is_array();
    auto has_no  = j.contains("no")  && j["no"].is_array();
    auto has_yes_d = j.contains("yes_dollars") && j["yes_dollars"].is_array();
    auto has_no_d  = j.contains("no_dollars")  && j["no_dollars"].is_array();

    // prefer dollars if present
    const json* yesA = nullptr; const json* noA = nullptr; double scale = 1.0;
    if (has_yes_d || has_no_d) {
        if (has_yes_d) yesA = &j["yes_dollars"];
        if (has_no_d)  noA  = &j["no_dollars"];
        scale = 1.0; // already dollars
    } else if (has_yes || has_no) {
        if (has_yes) yesA = &j["yes"];
        if (has_no)  noA  = &j["no"];
        scale = 0.01; // cents -> dollars
    } else {
        return false;
    }

    std::optional<double> yes_bid, no_bid;
    if (yesA) {
        if (auto bb = max_price_in_levels(*yesA)) yes_bid = *bb * scale;
    }
    if (noA) {
        if (auto bb = max_price_in_levels(*noA))  no_bid = *bb * scale;
    }

    // need both sides for consistent spread
    if (!yes_bid || !no_bid) return false;

    // YES best bid = best bid from YES book
    // YES best ask ≈ 1.00 - best bid from NO book (binary complement)
    best_bid = *yes_bid;
    best_ask = 1.0 - *no_bid;
    // guard against negative/invalid due to staleness
    if (best_ask < 0.0) best_ask = 0.0;
    if (best_ask > 1.0) best_ask = 1.0;
    return true;
}

// ----- parse simple orderbook JSON heuristics -----
std::optional<double> extract_best_bid(const json &j) {
    // direct common fields
    if (j.contains("best_bid") && j["best_bid"].is_number()) return j["best_bid"].get<double>();
    if (j.contains("bestBid") && j["bestBid"].is_number())   return j["bestBid"].get<double>();

    // nested orderbook {bids, asks}
    double bb=0, ba=0;
    if (extract_bbo_from_nested(j, bb, ba)) return bb;

    // Kalshi yes/no synthesis
    if (extract_bbo_from_kalshi_yesno(j, bb, ba)) return bb;

    return std::nullopt;
}

std::optional<double> extract_best_ask(const json &j) {
    if (j.contains("best_ask") && j["best_ask"].is_number()) return j["best_ask"].get<double>();
    if (j.contains("bestAsk") && j["bestAsk"].is_number())   return j["bestAsk"].get<double>();

    double bb=0, ba=0;
    if (extract_bbo_from_nested(j, bb, ba)) return ba;
    if (extract_bbo_from_kalshi_yesno(j, bb, ba)) return ba;

    return std::nullopt;
}

// ----- Polymarket token hydration via REST -----
struct PMTokens {
    std::string yes_token;
    std::string no_token;
};

std::optional<PMTokens> fetch_pm_tokens(const std::string& market_id) {
    try {
        asio::io_context ioc;
        ssl::context sslctx(ssl::context::tlsv12_client);
        sslctx.set_default_verify_paths();

        tcp::resolver resolver{ioc};
        auto const results = resolver.resolve("gamma-api.polymarket.com", "443");
        beast::tcp_stream tcp_stream{ioc};
        tcp_stream.connect(results);

        beast::ssl_stream<beast::tcp_stream> tls_stream{std::move(tcp_stream), sslctx};
        if(!SSL_set_tlsext_host_name(tls_stream.native_handle(), "gamma-api.polymarket.com"))
            return std::nullopt;

        beast::get_lowest_layer(tls_stream).expires_after(std::chrono::seconds(30));
        tls_stream.handshake(ssl::stream_base::client);

        std::string target = "/markets?id=" + market_id;
        http::request<http::string_body> req{http::verb::get, target, 11};
        req.set(http::field::host, "gamma-api.polymarket.com");
        req.set(http::field::user_agent, "arb-ws-watcher/1.0");
        http::write(tls_stream, req);

        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(tls_stream, buffer, res);
        if (res.result() != http::status::ok) {
            std::cerr << "[PM] Gamma HTTP " << static_cast<int>(res.result()) << "\n";
            return std::nullopt;
        }

        auto j = json::parse(res.body());
        if (!(j.is_array() && !j.empty())) return std::nullopt;

        const auto& m = j[0];
        PMTokens t;

        if (m.contains("clobTokenIds")) {
            const auto& cti = m["clobTokenIds"];

            // Case 1: already an object { "yes": "...", "no": "..." }
            if (cti.is_object()) {
                if (cti.contains("yes") && cti["yes"].is_string()) t.yes_token = cti["yes"].get<std::string>();
                if (cti.contains("no")  && cti["no"].is_string())  t.no_token  = cti["no"].get<std::string>();
            }
            // Case 2: string-encoded JSON (common)
            else if (cti.is_string()) {
                const std::string s = cti.get<std::string>();
                try {
                    auto cj = json::parse(s);
                    if (cj.is_object()) {
                        if (cj.contains("yes") && cj["yes"].is_string()) t.yes_token = cj["yes"].get<std::string>();
                        if (cj.contains("no")  && cj["no"].is_string())  t.no_token  = cj["no"].get<std::string>();
                    } else if (cj.is_array() && cj.size() >= 2) {
                        // assumption: [yes, no]
                        if (cj[0].is_string()) t.yes_token = cj[0].get<std::string>();
                        if (cj[1].is_string()) t.no_token  = cj[1].get<std::string>();
                    }
                } catch (...) {
                    // Case 3: maybe comma-separated "yes_id,no_id"
                    auto comma = s.find(',');
                    if (comma != std::string::npos) {
                        t.yes_token = s.substr(0, comma);
                        t.no_token  = s.substr(comma+1);
                        // trim quotes/spaces
                        auto trim = [](std::string& x){
                            while(!x.empty() && (x.front()=='"'||x.front()==' ')) x.erase(x.begin());
                            while(!x.empty() && (x.back()=='"'||x.back()==' ')) x.pop_back();
                        };
                        trim(t.yes_token); trim(t.no_token);
                    }
                }
            }
        }

        if (!t.yes_token.empty() || !t.no_token.empty()) return t;
    } catch (const std::exception& e) {
        std::cerr << "[PM] Failed to fetch tokens: " << e.what() << std::endl;
    }
    return std::nullopt;
}

// ----- Kalshi market hydration via REST (from event_ticker) -----
std::optional<std::string> fetch_kalshi_market_ticker_from_event(
    const std::string& event_ticker,
    const std::string& key_id,
    EVP_PKEY* pkey)
{
    try {
        if (event_ticker.empty() || key_id.empty() || !pkey) return std::nullopt;

        asio::io_context ioc;
        ssl::context sslctx(ssl::context::tlsv12_client);
        sslctx.set_default_verify_paths();

        // Use api.kalshi.com for REST endpoints
        const std::string host = "api.kalshi.com";

        tcp::resolver resolver{ioc};
        auto const results = resolver.resolve(host, "443");
        beast::tcp_stream tcp_stream{ioc};
        tcp_stream.connect(results);

        beast::ssl_stream<beast::tcp_stream> tls_stream{std::move(tcp_stream), sslctx};
        if (!SSL_set_tlsext_host_name(tls_stream.native_handle(), host.c_str()))
            return std::nullopt;

        beast::get_lowest_layer(tls_stream).expires_after(std::chrono::seconds(30));
        tls_stream.handshake(ssl::stream_base::client);

        // Kalshi v2 markets endpoint (event_ticker filter)
        // Important: the path (including query) must be what we sign.
        const std::string path = "/trade-api/v2/markets?event_ticker=" + event_ticker;

        // Build RSA-PSS headers (timestamp + "GET" + path)
        auto headers = make_kalshi_auth_headers(key_id, pkey, path);

        http::request<http::string_body> req{http::verb::get, path, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, "arb-ws-watcher/1.0");
        // Kalshi REST also needs these access headers:
        for (auto& h : headers) req.set(h.first, h.second);

        http::write(tls_stream, req);

        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(tls_stream, buffer, res);
        if (res.result() != http::status::ok) {
            std::lock_guard lk(out_mtx);
            std::cerr << "[KX] REST /markets HTTP " << static_cast<unsigned>(res.result()) << "\n";
            return std::nullopt;
        }

        auto j = json::parse(res.body());

        // Two shapes are commonly seen: { "markets":[...] } OR plain array [...]
        const json* arr = nullptr;
        if (j.is_object() && j.contains("markets") && j["markets"].is_array()) {
            arr = &j["markets"];
        } else if (j.is_array()) {
            arr = &j;
        } else {
            return std::nullopt;
        }

        // Pick the "Winner"/moneyline market if available; else first market.
        std::string best;
        for (const auto& m : *arr) {
            if (!m.is_object()) continue;
            std::string ticker = m.value("ticker", "");
            std::string title  = m.value("title", "");
            if (ticker.empty()) continue;

            // Prefer WINNER / MONEYLINE / YES-NO style tickers
            if (icontains(ticker, "WINNER") || icontains(title, "winner") ||
                icontains(title, "moneyline") || icontains(ticker, "MONEYLINE")) {
                best = ticker;
                break;
            }

            // As a secondary heuristic, prefer markets ending with ".WINNER.*"
            if (best.empty()) best = ticker;
        }

        if (!best.empty()) return best;
    } catch (const std::exception& e) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] Failed to fetch market ticker: " << e.what() << "\n";
    }
    return std::nullopt;
}

// ----- Kalshi market hydration and normalization -----
struct KalshiMarketInfo {
    std::string subscribe_ticker;  // Actual ticker to subscribe to (may be contract ticker)
    std::string market_type;       // "binary" or "categorical"
    std::string contract_code;     // "YES", "O", "U", etc.
    double best_bid = 0.0;
    double best_ask = 0.0;
};

std::optional<KalshiMarketInfo> hydrate_and_normalize_kx_market(
    const std::string& raw_ticker,
    const std::string& key_id,
    EVP_PKEY* pkey)
{
    if (raw_ticker.empty() || key_id.empty() || !pkey) return std::nullopt;

    try {
        // Helper to fetch market by ticker
        auto fetch_market = [&](const std::string& ticker) -> std::optional<json> {
            asio::io_context ioc;
            ssl::context sslctx(ssl::context::tlsv12_client);
            sslctx.set_default_verify_paths();

            // Use api.kalshi.com for REST endpoints
            const std::string host = "api.kalshi.com";

            tcp::resolver resolver{ioc};
            auto results = resolver.resolve(host, "443");
            beast::tcp_stream tcp_stream{ioc};
            tcp_stream.connect(results);

            beast::ssl_stream<beast::tcp_stream> tls_stream{std::move(tcp_stream), sslctx};
            if (!SSL_set_tlsext_host_name(tls_stream.native_handle(), host.c_str()))
                return std::nullopt;

            beast::get_lowest_layer(tls_stream).expires_after(std::chrono::seconds(30));
            tls_stream.handshake(ssl::stream_base::client);

            std::string path = "/trade-api/v2/markets?ticker=" + ticker;
            auto headers = make_kalshi_auth_headers(key_id, pkey, path);

            http::request<http::string_body> req{http::verb::get, path, 11};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, "arb-ws-watcher/1.0");
            for (auto& h : headers) req.set(h.first, h.second);

            http::write(tls_stream, req);

            beast::flat_buffer buffer;
            http::response<http::string_body> res;
            http::read(tls_stream, buffer, res);

            if (res.result() != http::status::ok) return std::nullopt;

            return json::parse(res.body());
        };

        // Try exact ticker first
        std::vector<std::string> candidates = {raw_ticker};

        // Generate alternates for common ticker variations
        if (raw_ticker.find("-TOTAL-O") != std::string::npos) {
            candidates.push_back(std::regex_replace(raw_ticker, std::regex("-TOTAL-O"), "-TOTAL-"));
            candidates.push_back(std::regex_replace(raw_ticker, std::regex("-TOTAL-O"), "-TOTAL-OVER-"));
            candidates.push_back(std::regex_replace(raw_ticker, std::regex("-TOTAL-O"), "-OVER-"));
        }
        if (raw_ticker.find("-TOTAL-U") != std::string::npos) {
            candidates.push_back(std::regex_replace(raw_ticker, std::regex("-TOTAL-U"), "-TOTAL-"));
            candidates.push_back(std::regex_replace(raw_ticker, std::regex("-TOTAL-U"), "-TOTAL-UNDER-"));
            candidates.push_back(std::regex_replace(raw_ticker, std::regex("-TOTAL-U"), "-UNDER-"));
        }
        if (raw_ticker.find("-1H-TOTAL-") != std::string::npos) {
            candidates.push_back(std::regex_replace(raw_ticker, std::regex("-1H-TOTAL-"), "-TOTAL-1H-"));
        }

        json market_data;
        std::string found_ticker;

        for (const auto& candidate : candidates) {
            auto resp = fetch_market(candidate);
            if (resp && resp->is_object() && resp->contains("markets")) {
                auto& markets = (*resp)["markets"];
                if (markets.is_array() && !markets.empty()) {
                    // NEW: pick the first with exact ticker match to avoid wrong markets
                    std::optional<json> exact;
                    for (const auto& m : markets) {
                        if (m.is_object() && m.contains("ticker") && m["ticker"].is_string()) {
                            if (m["ticker"].get<std::string>() == candidate) {
                                exact = m;
                                break;
                            }
                        }
                    }
                    if (!exact) {
                        std::lock_guard lk(out_mtx);
                        std::cerr << "[KX] Market response didn't match requested ticker " << candidate << ", trying next\n";
                        continue; // keep trying other candidates
                    }

                    market_data = *exact;
                    found_ticker = candidate;
                    std::lock_guard lk(out_mtx);
                    std::cout << "[KX] Found market: " << candidate << "\n";
                    break;
                }
            }
        }

        if (market_data.empty()) {
            std::lock_guard lk(out_mtx);
            std::cerr << "[KX] Market not found: tried " << candidates.size() << " variations\n";
            return std::nullopt;
        }

        KalshiMarketInfo info;
        std::string mtype = market_data.value("market_type", "");
        info.market_type = mtype;

        if (mtype == "categorical") {
            // Categorical market (e.g., O/U total) - need to pick specific contract
            std::lock_guard lk(out_mtx);
            std::cout << "[KX] Categorical market detected, selecting contract...\n";

            // Determine which contract we want (O vs U)
            bool want_over = (raw_ticker.find("-O") != std::string::npos ||
                            raw_ticker.find("OVER") != std::string::npos);
            bool want_under = (raw_ticker.find("-U") != std::string::npos ||
                             raw_ticker.find("UNDER") != std::string::npos);

            if (!market_data.contains("contracts") || !market_data["contracts"].is_array()) {
                std::cerr << "[KX] No contracts found in categorical market\n";
                return std::nullopt;
            }

            // Find the right contract
            for (const auto& contract : market_data["contracts"]) {
                std::string code = contract.value("code", "");
                std::string display = contract.value("display", "");

                bool is_over = (code == "O" || code == "OVER" || display == "Over");
                bool is_under = (code == "U" || code == "UNDER" || display == "Under");

                if ((want_over && is_over) || (want_under && is_under) ||
                    (!want_over && !want_under && is_over)) {  // default to Over
                    info.subscribe_ticker = contract.value("ticker", "");
                    info.contract_code = code;
                    std::cout << "[KX] Selected contract: " << info.contract_code
                              << " (ticker=" << info.subscribe_ticker << ")\n";
                    break;
                }
            }

            if (info.subscribe_ticker.empty()) {
                std::cerr << "[KX] Could not find matching contract\n";
                return std::nullopt;
            }
        } else {
            // Binary market: subscribe with the exact market ticker we queried
            info.subscribe_ticker = found_ticker; // critical to avoid wrong topic
            info.contract_code = "YES";
        }

        return info;

    } catch (const std::exception& e) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] Market hydration failed: " << e.what() << "\n";
    }
    return std::nullopt;
}

// ----- Fetch orderbook snapshot to seed quotes -----
std::optional<std::pair<double,double>> fetch_kx_orderbook_snapshot(
    const std::string& ticker,
    const std::string& key_id,
    EVP_PKEY* pkey)
{
    if (ticker.empty() || key_id.empty() || !pkey) return std::nullopt;

    try {
        asio::io_context ioc;
        ssl::context sslctx(ssl::context::tlsv12_client);
        sslctx.set_default_verify_paths();

        // Use api.kalshi.com for REST endpoints (api.elections.* returns 404 for market_orderbook)
        const std::string host = "api.kalshi.com";

        tcp::resolver resolver{ioc};
        auto results = resolver.resolve(host, "443");
        beast::tcp_stream tcp_stream{ioc};
        tcp_stream.connect(results);

        beast::ssl_stream<beast::tcp_stream> tls_stream{std::move(tcp_stream), sslctx};
        if (!SSL_set_tlsext_host_name(tls_stream.native_handle(), host.c_str()))
            return std::nullopt;

        beast::get_lowest_layer(tls_stream).expires_after(std::chrono::seconds(30));
        tls_stream.handshake(ssl::stream_base::client);

        // ✅ Correct v2 route + param name
        // Was: "/trade-api/v2/orderbook?ticker=" + ticker
        const std::string path = "/trade-api/v2/market_orderbook?market_ticker=" + ticker;

        // Sign EXACTLY this path
        auto headers = make_kalshi_auth_headers(key_id, pkey, path);

        // Log what we're requesting for debugging
        {
            std::lock_guard lk(out_mtx);
            std::cout << "[KX] Snapshot request: https://" << host << path << "\n";
        }

        http::request<http::string_body> req{http::verb::get, path, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, "arb-ws-watcher/1.0");
        for (auto& h : headers) req.set(h.first, h.second);

        http::write(tls_stream, req);

        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(tls_stream, buffer, res);

        if (res.result() != http::status::ok) {
            std::lock_guard lk(out_mtx);
            std::cerr << "[KX] SNAPSHOT HTTP " << static_cast<unsigned>(res.result())
                      << " body=" << res.body().substr(0, 300) << "\n";
            return std::nullopt;
        }

        auto j = json::parse(res.body());

        // The REST returns either:
        //  { "orderbook": { ... bids_dollars/asks_dollars ... } }
        // or a flat object with best_bid/best_ask/yes_bid/yes_ask, etc.
        const json* payload = &j;
        if (j.is_object() && j.contains("orderbook") && j["orderbook"].is_object()) {
            payload = &j["orderbook"];
        }

        double bid = 0.0, ask = 0.0;

        // 1) Try nested extractor (handles bids/asks, *_dollars, *_cents, etc.)
        if (extract_bbo_from_nested(*payload, bid, ask)) {
            std::lock_guard lk(out_mtx);
            std::cout << "[KX] Snapshot loaded: bid=" << bid << " ask=" << ask << "\n";
            return std::make_pair(bid, ask);
        }

        // 2) Try simple fields (best_bid/best_ask or yes_bid/yes_ask)
        if (payload->contains("best_bid") && (*payload)["best_bid"].is_number())
            bid = (*payload)["best_bid"].get<double>();
        else if (payload->contains("yes_bid") && (*payload)["yes_bid"].is_number())
            bid = (*payload)["yes_bid"].get<double>();

        if (payload->contains("best_ask") && (*payload)["best_ask"].is_number())
            ask = (*payload)["best_ask"].get<double>();
        else if (payload->contains("yes_ask") && (*payload)["yes_ask"].is_number())
            ask = (*payload)["yes_ask"].get<double>();

        if (bid > 0 && ask > 0) {
            std::lock_guard lk(out_mtx);
            std::cout << "[KX] Snapshot loaded (simple): bid=" << bid << " ask=" << ask << "\n";
            return std::make_pair(bid, ask);
        } else {
            std::lock_guard lk(out_mtx);
            std::cerr << "[KX] Snapshot present but no usable quotes. Head: "
                      << j.dump().substr(0, 300) << "...\n";
        }

    } catch (const std::exception& e) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[KX] Snapshot fetch failed: " << e.what() << "\n";
    }
    return std::nullopt;
}

// ----- Helper to extract bid/ask from Kalshi messages (multiple field names) -----
static inline double kx_getBid(const json& j) {
    if (j.contains("best_bid") && j["best_bid"].is_number())
        return j["best_bid"].get<double>();
    if (j.contains("yes_bid") && j["yes_bid"].is_number())
        return j["yes_bid"].get<double>();
    return std::nan("");
}

static inline double kx_getAsk(const json& j) {
    if (j.contains("best_ask") && j["best_ask"].is_number())
        return j["best_ask"].get<double>();
    if (j.contains("yes_ask") && j["yes_ask"].is_number())
        return j["yes_ask"].get<double>();
    return std::nan("");
}

// ----- connect & listen WS using correct Beast TLS handshake -----
websocket::stream<beast::ssl_stream<beast::tcp_stream>> connect_wss(
    asio::io_context& ioc,
    ssl::context& sslctx,
    const std::string& host_for_tcp,  // Can be IP address if DNS fails
    const std::string& port,
    const std::string& target,
    const std::string& sni_host,      // Hostname for SNI and Host header
    const std::vector<std::pair<std::string,std::string>>& extra_headers = {})
{
    // 1) resolve + connect TCP (can use IP if host_for_tcp is an IP)
    tcp::resolver resolver{ioc};
    beast::error_code res_ec;
    auto const results = resolver.resolve(host_for_tcp, port, res_ec);
    if (res_ec) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[RESOLVE] host=" << host_for_tcp << " port=" << port
                  << " ec=" << res_ec.message() << " (" << res_ec.value() << ")\n";
        throw beast::system_error(res_ec);
    }

    beast::tcp_stream tcp_stream{ioc};
    tcp_stream.connect(results);

    // 2) wrap in TLS
    beast::ssl_stream<beast::tcp_stream> tls_stream{std::move(tcp_stream), sslctx};

    // Set SNI hostname (required by many servers)
    if(!SSL_set_tlsext_host_name(tls_stream.native_handle(), sni_host.c_str()))
        throw std::runtime_error("SSL_set_tlsext_host_name failed");

    // Optional: timeout on the lowest layer during handshakes
    beast::get_lowest_layer(tls_stream).expires_after(std::chrono::seconds(30));

    // 3) TLS handshake
    tls_stream.handshake(ssl::stream_base::client);

    // 4) Upgrade to WebSocket over TLS
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws{std::move(tls_stream)};

    // 5) Set decorator for custom headers (especially for Kalshi RSA-PSS headers)
    ws.set_option(websocket::stream_base::decorator(
        [&](websocket::request_type& req){
            req.set(http::field::host, sni_host);  // Host header = SNI host
            req.set(http::field::user_agent, "arb-ws-watcher/1.0");
            // Some gateways require Origin:
            if (sni_host.find("kalshi") != std::string::npos) {
                req.set(http::field::origin, "https://kalshi.com");
            }
            if (sni_host.find("polymarket") != std::string::npos) {
                req.set(http::field::origin, "https://polymarket.com");
            }
            // Add any extra headers (e.g., Kalshi RSA-PSS auth headers)
            for (const auto& h : extra_headers) {
                req.set(h.first, h.second);
            }
            {
                std::lock_guard lk(out_mtx);
                std::cerr << "[WS] upgrading host=" << host_for_tcp
                          << " sni=" << sni_host
                          << " target=" << req.target() << '\n';
            }
        }
    ));

    // 6) WebSocket handshake with response capture
    websocket::response_type hs_res;
    beast::error_code hs_ec;
    ws.handshake(hs_res, sni_host, target, hs_ec);
    if (hs_ec) {
        std::lock_guard lk(out_mtx);
        std::cerr << "[WS] handshake failed host=" << host_for_tcp
                  << " sni=" << sni_host
                  << " target=" << target
                  << " status=" << static_cast<unsigned>(hs_res.result())
                  << " reason=" << hs_res.reason() << " ec=" << hs_ec.message() << "\n";

        // dump headers for debugging
        for (auto const& f : hs_res.base()) {
            std::cerr << "  " << f.name_string() << ": " << f.value() << "\n";
        }
        throw beast::system_error(hs_ec);
    }

    return ws;
}

void run_ws_watch(
    const std::string &ws_url,
    const std::function<std::vector<std::pair<std::string,std::string>>()> &header_supplier,
    const std::string &subscribe_json,
    const std::string &alt_subscribe_json,  // for KX alternate format
    const std::string &snapshot_json,       // for KX snapshot request
    QuoteBook &qb,
    const std::string &label,
    std::atomic<bool> &stop_flag,
    bool verbose,
    const std::string &host_override = "",  // Optional: IP to bypass DNS
    const std::string &sni_host_override = "")  // Optional: SNI hostname
{
    int attempt = 0;
    while (!stop_flag.load()) {
        try {
            // parse URL
            std::string host, port, target;
            // minimal parse for wss://
            if (ws_url.rfind("wss://",0) != 0) {
                throw std::runtime_error("Only wss:// URLs supported");
            }
            std::string rest = ws_url.substr(6); // after "wss://"

            auto slash = rest.find('/');
            if (slash == std::string::npos) {
                host = rest;
                target = "/";
            } else {
                host = rest.substr(0, slash);
                target = rest.substr(slash);
            }

            auto colon = host.find(':');
            if (colon != std::string::npos) {
                port = host.substr(colon+1);
                host = host.substr(0, colon);
            } else {
                port = "443";
            }


            asio::io_context ioc;
            ssl::context sslctx(ssl::context::tlsv12_client);
            sslctx.set_default_verify_paths();

            // NEW: fetch fresh headers each attempt (fresh timestamp/signature)
            auto handshake_headers = header_supplier ? header_supplier()
                                                     : std::vector<std::pair<std::string,std::string>>{};

            // Log what we're connecting to
            {
                std::lock_guard lk(out_mtx);
                std::cout << "["<<label<<"] Connecting to wss://" << host << target << "\n";
            }

            // Determine actual TCP host and SNI host (support IP override for DNS bypass)
            std::string tcp_host = host_override.empty() ? host : host_override;
            std::string sni_hostname = sni_host_override.empty() ? host : sni_host_override;

            if (!host_override.empty()) {
                std::lock_guard lk(out_mtx);
                std::cout << "["<<label<<"] Using host override: tcp=" << tcp_host
                          << " sni=" << sni_hostname << "\n";
            }

            // Connect with correct handshake
            auto ws = connect_wss(ioc, sslctx, tcp_host, port, target, sni_hostname, handshake_headers);

            // send subscribe (as text frame)
            ws.text(true);
            ws.write(asio::buffer(subscribe_json));

            if (label == "KX") {
                if (!snapshot_json.empty()) {
                    ws.write(asio::buffer(snapshot_json));
                }
                if (!alt_subscribe_json.empty()) {
                    ws.write(asio::buffer(alt_subscribe_json));
                    std::lock_guard lk(out_mtx);
                    std::cerr << "[KX] Sent alternate subscribe (namespaced channel) immediately\n";
                }
            }
            bool tried_alt_sub = true; // since we already sent it
            int unmatched_count = 0;

            {
                std::lock_guard lk(out_mtx);
                std::cout << "["<<label<<"] connected and subscribed";
                if (label == "KX" && !snapshot_json.empty()) {
                    std::cout << " (+ snapshot requested)";
                }
                std::cout << "\n";
            }

            // Add keep-alive pinger to prevent idle timeouts
            std::atomic<bool> ws_alive{true};
            std::thread pinger([&ws, &stop_flag, &ws_alive, label, verbose](){
                while(!stop_flag.load() && ws_alive.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(20));
                    beast::error_code ec;
                    if (label == "PM") {
                        ws.text(true);
                        ws.write(asio::buffer(std::string("PING")), ec);
                    } else {
                        ws.ping(websocket::ping_data{}, ec);
                    }
                    if (ec) {
                        if (verbose) {
                            std::lock_guard lk(out_mtx);
                            std::cerr << "["<<label<<"] ping error: " << ec.message() << std::endl;
                        }
                        break;
                    }
                }
            });

            beast::flat_buffer buffer;

            // Kalshi orderbook for delta maintenance (KX only)
            KalshiBook kx_book;

            for (;;) {
                beast::error_code ec;
                ws.read(buffer, ec);
                if (ec) {
                    if (verbose) {
                        std::lock_guard lk(out_mtx);
                        std::cerr << "["<<label<<"] read error: " << ec.message() << std::endl;
                    }
                    break;
                }
                auto data = beast::buffers_to_string(buffer.data());
                buffer.consume(buffer.size());

                // parse JSON and update quotes
                try {
                    auto j = json::parse(data);
                    // Kalshi wraps payload in j["msg"] or j["data"], extract if present
                    const json* payload = &j;
                    if (j.contains("msg") && j["msg"].is_object()) {
                        payload = &j["msg"];
                    } else if (j.contains("data") && j["data"].is_object()) {
                        payload = &j["data"];
                    }

                    // KX: use KalshiBook for snapshots and deltas, OR direct fields for categorical
                    if (label == "KX") {
                        // Fast-path: Kalshi wraps snapshots in {"orderbook":{...}}
                        if (payload->contains("orderbook") && (*payload)["orderbook"].is_object()) {
                            const auto& ob = (*payload)["orderbook"];
                            double bid = 0, ask = 0;
                            // Reuse nested extractor that handles bids_dollars/asks_dollars/etc.
                            if (extract_bbo_from_nested(ob, bid, ask)) {
                                qb.set_bbo(bid, ask);
                                unmatched_count = 0;
                                if (verbose) {
                                    std::lock_guard lk(out_mtx);
                                    std::cout << "[KX] Orderbook snapshot: bid=" << bid << " ask=" << ask << "\n";
                                }
                                continue;
                            }
                        }

                        // Try direct best_bid/best_ask first (categorical contracts, or simpler feeds)
                        double direct_bid = kx_getBid(*payload);
                        double direct_ask = kx_getAsk(*payload);

                        if (!std::isnan(direct_bid) && !std::isnan(direct_ask)) {
                            // Direct quotes available (categorical contract or simple binary)
                            qb.set_bbo(direct_bid, direct_ask);
                            unmatched_count = 0;
                            if (verbose) {
                                std::lock_guard lk(out_mtx);
                                std::cout << "[KX] Direct quotes: bid=" << direct_bid << " ask=" << direct_ask << "\n";
                            }
                            continue;
                        }

                        // Fallback: Handle binary YES/NO snapshot (initialize book)
                        if (payload->contains("yes") || payload->contains("yes_dollars") ||
                            payload->contains("no") || payload->contains("no_dollars")) {
                            kx_book.apply_snapshot(*payload);
                            auto [bb, ba] = kx_book.bbo_yes();
                            if (bb && ba) {
                                qb.set_bbo(*bb, *ba);
                                unmatched_count = 0;
                            } else {
                                if (bb) qb.set_bid(*bb);
                                if (ba) qb.set_ask(*ba);
                            }
                            if (verbose) {
                                std::lock_guard lk(out_mtx);
                                std::cout << "[KX] Loaded snapshot: YES bid=" << (bb ? std::to_string(*bb) : "NA")
                                          << " ask=" << (ba ? std::to_string(*ba) : "NA") << "\n";
                            }
                            continue;
                        }

                        // Handle delta update (now supports Kalshi's book_side/quantity_delta format)
                        if (payload->contains("delta") || payload->contains("quantity_delta") ||
                            payload->contains("book_side") || payload->contains("side")) {
                            kx_book.apply_delta(*payload);
                            auto [bb, ba] = kx_book.bbo_yes();
                            if (bb && ba) {
                                qb.set_bbo(*bb, *ba);
                                unmatched_count = 0;
                                if (verbose) {
                                    std::lock_guard lk(out_mtx);
                                    std::cout << "[KX] Delta applied: bid=" << *bb << " ask=" << *ba << "\n";
                                }
                            } else {
                                if (bb) qb.set_bid(*bb);
                                if (ba) qb.set_ask(*ba);
                            }
                            continue;
                        }

                        // If nothing matched, log for debugging
                        if (verbose) {
                            unmatched_count++;
                            if (unmatched_count <= 5) {  // Only show first few
                                std::lock_guard lk(out_mtx);
                                std::string s = payload->dump();
                                if (s.size() > 800) s.resize(800), s += "...";
                                std::cout << "[TRACE][KX] unmatched payload #" << unmatched_count << ": " << s << "\n";
                            }
                        }
                    }

                    // PM or fallback: use generic extractors
                    auto bb = extract_best_bid(*payload);
                    auto ba = extract_best_ask(*payload);
                    if (bb && ba) {
                        qb.set_bbo(*bb, *ba);
                        if (label == "KX") unmatched_count = 0; // reset on success
                    } else {
                        if (bb) qb.set_bid(*bb);
                        if (ba) qb.set_ask(*ba);

                        // Rate-limited debug logging (not just first message)
                        static auto last_dump = std::chrono::steady_clock::now();
                        auto now_dump = std::chrono::steady_clock::now();
                        if (now_dump - last_dump > std::chrono::seconds(2)) {
                            last_dump = now_dump;
                            std::lock_guard lk(out_mtx);
                            std::string s = payload->dump();
                            if (s.size() > 1500) s.resize(1500), s += "...";
                            std::cout << "[DEBUG]["<<label<<"] unmatched payload: " << s << "\n";
                        }

                        // Kalshi: try alternate subscription if initial format not working
                        if (label == "KX" && !(bb || ba)) {
                            unmatched_count++;
                            if (!tried_alt_sub && unmatched_count >= 5 && !alt_subscribe_json.empty()) {
                                tried_alt_sub = true;
                                ws.text(true);
                                ws.write(asio::buffer(alt_subscribe_json));
                                std::lock_guard lk(out_mtx);
                                std::cerr << "[KX] Sent alternate subscribe (namespaced channel)\n";
                            }
                        }
                    }

                    if (verbose) {
                        std::lock_guard lk(out_mtx);
                        std::cout << "["<<label<<"] got message: " << data << std::endl;
                    }
                } catch (...) {
                    // ignore non-json
                }
            }

            // Stop pinger and close ws cleanly before thread joins
            ws_alive.store(false);
            beast::error_code ignore;
            ws.close(websocket::close_code::normal, ignore);
            if (pinger.joinable()) pinger.join();

        } catch (const std::exception &e) {
            if (verbose) {
                std::lock_guard lk(out_mtx);
                std::cerr << "["<<label<<"] exception: " << e.what() << std::endl;
            }
        }

        if (stop_flag.load()) break;
        int backoff_ms = std::min(5000, 250 * std::max(1, ++attempt));
        if (verbose) {
            std::lock_guard lk(out_mtx);
            std::cerr << "["<<label<<"] reconnecting in " << backoff_ms << "ms\n";
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
    }
}

// ----- small arbitrage detector thread -----
void arbitrage_loop(QuoteBook &pm_q, QuoteBook &kx_q,
                    int pm_fee_bps, int kx_fee_bps, int min_edge_bps,
                    std::atomic<bool> &stop_flag,
                    int stale_ms, int max_skew_ms, int ping_ms,
                    const std::string& windows_csv) {
    using clock = std::chrono::steady_clock;
    auto now_ms = []{ return std::chrono::time_point_cast<std::chrono::milliseconds>(clock::now()); };

    auto safe_mid = [](std::optional<double> b, std::optional<double> a)->std::optional<double>{
        if (!b || !a) return std::nullopt;
        return 0.5 * (*b + *a);
    };
    auto clamp01 = [](double x){ return std::max(0.0, std::min(1.0, x)); };

    // optional CSV
    std::unique_ptr<std::ofstream> csv;
    if (!windows_csv.empty()) {
        csv = std::make_unique<std::ofstream>(windows_csv, std::ios::app);
        if (csv && csv->tellp() == 0) {
            *csv << "opened_ms,closed_ms,duration_ms,leg,"
                 << "sell_bid,buy_ask,raw,bps_capital,bps_buy,max_edge_bps,qualified\n";
        }
    }

    struct Window {
        bool open = false;
        std::string leg;     // "PM->KX" or "KX->PM"
        clock::time_point opened;
        double max_edge_bps = -1e9;
        // for last snapshot detail
        double last_sell_bid=0, last_buy_ask=0, last_raw=0, last_bps_cap=0, last_bps_buy=0;
    } win;

    // spam reduction
    static double last_pm_bid = -1, last_pm_ask = -1;
    static double last_kx_bid = -1, last_kx_ask = -1;

    while(!stop_flag.load()) {
        auto pm = pm_q.snap();
        auto kx = kx_q.snap();
        auto now = clock::now();

        // Heartbeat to show what's missing
        static auto last_hb = clock::now();
        if (clock::now() - last_hb > std::chrono::seconds(2)) {
            last_hb = clock::now();
            std::lock_guard lk(out_mtx);
            std::cout << "[HEARTBEAT] pm_bid=" << (pm.bid ? std::to_string(*pm.bid) : "NA")
                      << " pm_ask=" << (pm.ask ? std::to_string(*pm.ask) : "NA")
                      << " kx_bid=" << (kx.bid ? std::to_string(*kx.bid) : "NA")
                      << " kx_ask=" << (kx.ask ? std::to_string(*kx.ask) : "NA")
                      << " age_ms pm=" << std::chrono::duration_cast<std::chrono::milliseconds>(clock::now()-pm.ts).count()
                      << " kx=" << std::chrono::duration_cast<std::chrono::milliseconds>(clock::now()-kx.ts).count()
                      << "\n";
        }

        // Freshness checks
        auto age_ms = [&](clock::time_point ts){
            return (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - ts).count();
        };
        int pm_age = age_ms(pm.ts), kx_age = age_ms(kx.ts);
        bool pm_fresh = pm_age <= stale_ms;
        bool kx_fresh = kx_age <= stale_ms;
        bool skew_ok  = std::abs(pm_age - kx_age) <= max_skew_ms;

        // Decide if we even try an arb this tick
        bool have_books = (pm.bid && pm.ask && kx.bid && kx.ask);
        if (!have_books || !(pm_fresh && kx_fresh && skew_ok)) {
            // if a window was open, close it (expired)
            if (win.open) {
                auto dur_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - win.opened).count();
                bool qualified = dur_ms >= ping_ms;
                {
                    std::lock_guard lk(out_mtx);
                    std::cout << "[ARB-CLOSE] leg="<<win.leg<<" duration_ms="<<dur_ms
                              << " max_edge_bps="<<win.max_edge_bps
                              << " qualified="<<(qualified?"yes":"no")
                              << " (stale/skew)\n";
                }
                if (csv) {
                    auto opened_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(win.opened).time_since_epoch().count();
                    auto closed_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
                    *csv << opened_ms << "," << closed_ms << "," << dur_ms << "," << win.leg << ","
                         << win.last_sell_bid << "," << win.last_buy_ask << ","
                         << win.last_raw << "," << win.last_bps_cap << "," << win.last_bps_buy << ","
                         << win.max_edge_bps << "," << (qualified?1:0) << "\n";
                }
                win = Window{};
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Potential complement flip on KX (so both represent YES on the same team)
        auto pm_mid = safe_mid(pm.bid, pm.ask);
        auto kx_mid = safe_mid(kx.bid, kx.ask);
        bool flipped_kx = false;
        if (pm_mid && kx_mid && std::abs((*pm_mid + *kx_mid) - 1.0) < 0.10) {
            // flip KX YES book into the complement YES
            auto old_kx_bid = kx.bid;
            auto old_kx_ask = kx.ask;
            if (old_kx_ask) kx.bid = clamp01(1.0 - *old_kx_ask);
            else            kx.bid.reset();
            if (old_kx_bid) kx.ask = clamp01(1.0 - *old_kx_bid);
            else            kx.ask.reset();
            flipped_kx = true;
        }

        // Re-check we have usable prices
        if (!(pm.bid && pm.ask && kx.bid && kx.ask)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Spam reduction on displayed BBO (every 2s)
        static auto last_bbo = clock::now();
        if (clock::now() - last_bbo > std::chrono::seconds(2)) {
            last_bbo = clock::now();
            std::lock_guard lk(out_mtx);
            std::cout << "[BBO] PM " << *pm.bid << "/" << *pm.ask
                      << " | KX" << (flipped_kx?"(flipped)":"") << " "
                      << *kx.bid << "/" << *kx.ask
                      << " | age_ms pm="<<pm_age<<" kx="<<kx_age<<"\n";
        }

        // Edge calculators (net of fees)
        auto pm_sell_kx_buy = [&](){
            double sell_bid = *pm.bid;
            double buy_ask  = *kx.ask;
            double sell_net = sell_bid * (1.0 - pm_fee_bps/10000.0);
            double buy_gross= buy_ask  * (1.0 + kx_fee_bps/10000.0);
            double raw      = sell_net - buy_gross;              // $/contract, net of fees
            double cap      = (1.0 - sell_bid) + buy_ask;        // $ capital tied
            double bps_cap  = (cap>0? raw/cap : 0.0) * 10000.0;
            double bps_buy  = (buy_ask>0? raw/buy_ask : 0.0) * 10000.0;
            return std::make_tuple(std::string("PM->KX"), sell_bid, buy_ask, raw, bps_cap, bps_buy);
        };

        auto kx_sell_pm_buy = [&](){
            double sell_bid = *kx.bid;
            double buy_ask  = *pm.ask;
            double sell_net = sell_bid * (1.0 - kx_fee_bps/10000.0);
            double buy_gross= buy_ask  * (1.0 + pm_fee_bps/10000.0);
            double raw      = sell_net - buy_gross;
            double cap      = (1.0 - sell_bid) + buy_ask;
            double bps_cap  = (cap>0? raw/cap : 0.0) * 10000.0;
            double bps_buy  = (buy_ask>0? raw/buy_ask : 0.0) * 10000.0;
            return std::make_tuple(std::string("KX->PM"), sell_bid, buy_ask, raw, bps_cap, bps_buy);
        };

        auto L1 = pm_sell_kx_buy();
        auto L2 = kx_sell_pm_buy();

        auto better = (std::get<4>(L1) > std::get<4>(L2)) ? L1 : L2; // compare bps_capital
        auto [leg, sell_bid, buy_ask, raw, bps_cap, bps_buy] = better;

        // Open/maintain/close window
        bool edge_ok = (bps_cap >= min_edge_bps);
        if (edge_ok) {
            if (!win.open) {
                win.open = true;
                win.leg = leg;
                win.opened = now;
                win.max_edge_bps = bps_cap;
                win.last_sell_bid=sell_bid; win.last_buy_ask=buy_ask;
                win.last_raw=raw; win.last_bps_cap=bps_cap; win.last_bps_buy=bps_buy;
                std::lock_guard lk(out_mtx);
                std::cout << "[ARB-OPEN] leg="<<leg<<" sell@"<<sell_bid<<" buy@"<<buy_ask
                          <<" raw=$"<<std::fixed<<std::setprecision(4)<<raw
                          <<" bps_capital="<<std::setprecision(1)<<bps_cap
                          <<" bps_buy="<<std::setprecision(1)<<bps_buy
                          << (flipped_kx?" (KX flipped)":"") << "\n";
            } else {
                // update max edge seen
                if (bps_cap > win.max_edge_bps) win.max_edge_bps = bps_cap;
                win.last_sell_bid=sell_bid; win.last_buy_ask=buy_ask;
                win.last_raw=raw; win.last_bps_cap=bps_cap; win.last_bps_buy=bps_buy;
            }
        } else if (win.open) {
            // close and report
            auto dur_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - win.opened).count();
            bool qualified = dur_ms >= ping_ms;
            {
                std::lock_guard lk(out_mtx);
                std::cout << "[ARB-CLOSE] leg="<<win.leg<<" duration_ms="<<dur_ms
                          << " max_edge_bps="<<win.max_edge_bps
                          << " qualified="<<(qualified?"yes":"no") << "\n";
            }
            if (csv) {
                auto opened_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(win.opened).time_since_epoch().count();
                auto closed_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
                *csv << opened_ms << "," << closed_ms << "," << dur_ms << "," << win.leg << ","
                     << win.last_sell_bid << "," << win.last_buy_ask << ","
                     << win.last_raw << "," << win.last_bps_cap << "," << win.last_bps_buy << ","
                     << win.max_edge_bps << "," << (qualified?1:0) << "\n";
            }
            win = Window{};
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(75));
    }
}

// ----- Kalshi ticker pattern recognition -----
static bool is_kalshi_event_ticker(const std::string& t) {
    // Pattern: KX[A-Z]+GAME-DDMMMDDTEAMTEAM
    // e.g., KXNBAGAME-25NOV10MILDAL, KXNHLGAME-25NOV12NJCHI
    std::regex ev_re(R"(^KX[A-Z]+GAME-\d{2}[A-Z]{3}\d{2}[A-Z]{4,12}$)");
    return std::regex_match(t, ev_re);
}

static bool is_kalshi_market_ticker(const std::string& t) {
    // Pattern: ends with team code, TOTAL, SPREAD, ML, etc.
    // e.g., KXNBAGAME-...-MIL, KXNBAGAME-...-TOTAL-O231_5, KXNBAGAME-...-SPREAD-MIL-2_5
    std::regex mrk_re(R"(^KX[A-Z]+GAME-.*-(MIL|DAL|NYR|NJ|CHI|PHI|ATL|BOS|LAC|LAL|GSW|TOTAL-.+|SPREAD-.+|ML|WINNER|MONEYLINE)$)");
    return std::regex_match(t, mrk_re);
}

// ----- main & CLI parsing (simple) -----
int main(int argc, char **argv) {
    // VERY minimal arg parsing -- adapt as needed
    std::string csv = "live_matches.csv";
    int row = 1;
    std::string pm_ws = "wss://clob.polymarket.com/ws";
    std::string kx_ws = "wss://api.elections.kalshi.com/trade-api/ws/v2";
    // Subscribe ONLY to YES to avoid YES/NO intermixing.
    // If you want NO, run a second process for the NO token rather than mixing.
    std::string pm_sub = R"({"type":"market","assets_ids":["{PM_YES_TOKEN}"]})";
    // Kalshi market_orderbook channel (includes snapshot + deltas)
    std::string kx_sub = R"({"id":1,"cmd":"subscribe","params":{"channels":["market_orderbook"],"market_ticker":"{KALSHI_TICKER}","depth":5,"dollars":true}})";
    // Namespaced variant also works on some deployments
    std::string kx_sub_alt = R"({"id":2,"cmd":"subscribe","params":{"channels":["market_orderbook:{KALSHI_TICKER}"],"depth":5,"dollars":true}})";
    // Explicit snapshot request as belt-and-suspenders
    std::string kx_snapshot = R"({"id":3,"cmd":"get_market_orderbook","params":{"market_ticker":"{KALSHI_TICKER}","depth":5,"dollars":true}})";
    int pm_fee_bps = 200;
    int kx_fee_bps = 100;
    int min_edge_bps = 1;
    int stale_ms = 60000;    // venue quote considered stale beyond this age (60s for low-volume markets)
    int max_skew_ms = 30000; // max allowed ts difference between venues (30s)
    int ping_ms = 200;       // your end-to-end order RTT budget
    std::string windows_csv; // optional CSV for window logs
    std::string kalshi_key;
    std::string kalshi_secret_path;
    std::string kalshi_host_override;  // e.g. "104.18.XX.XX" to bypass DNS
    std::string kalshi_sni_host = "api.elections.kalshi.com";  // SNI hostname for TLS (match WS endpoint)

    for (int i=1;i<argc;i++) {
        std::string a = argv[i];
        if (a=="--csv" && i+1<argc) csv = argv[++i];
        else if (a=="--row" && i+1<argc) row = std::stoi(argv[++i]);
        else if (a=="--pm-ws" && i+1<argc) pm_ws = argv[++i];
        else if (a=="--kalshi-ws" && i+1<argc) kx_ws = argv[++i];
        else if (a=="--pm-sub" && i+1<argc) pm_sub = argv[++i];
        else if (a=="--kalshi-sub" && i+1<argc) kx_sub = argv[++i];
        else if (a=="--pm-fee-bps" && i+1<argc) pm_fee_bps = std::stoi(argv[++i]);
        else if (a=="--kalshi-fee-bps" && i+1<argc) kx_fee_bps = std::stoi(argv[++i]);
        else if (a=="--min-edge-bps" && i+1<argc) min_edge_bps = std::stoi(argv[++i]);
        else if (a=="--stale-ms" && i+1<argc) stale_ms = std::stoi(argv[++i]);
        else if (a=="--max-skew-ms" && i+1<argc) max_skew_ms = std::stoi(argv[++i]);
        else if (a=="--ping-ms" && i+1<argc) ping_ms = std::stoi(argv[++i]);
        else if (a=="--windows-csv" && i+1<argc) windows_csv = argv[++i];
        else if (a=="--kalshi-key" && i+1<argc) kalshi_key = argv[++i];
        else if (a=="--kalshi-secret-path" && i+1<argc) kalshi_secret_path = argv[++i];
        else if (a=="--kalshi-host-override" && i+1<argc) kalshi_host_override = argv[++i];
        else if (a=="--kalshi-sni-host" && i+1<argc) kalshi_sni_host = argv[++i];
    }

    // Read Kalshi private key (PEM) from --kalshi-secret-path
    EVP_PKEY* kalshi_pkey = nullptr;
    if (!kalshi_secret_path.empty()) {
        kalshi_pkey = load_private_key_pem(kalshi_secret_path);
        if (!kalshi_pkey) {
            std::cerr << "[KX] ERROR: Failed to load private key PEM at " << kalshi_secret_path << "\n";
            std::cerr << "[KX] Make sure the file is a valid RSA private key in PEM format\n";
        } else {
            std::cout << "[KX] Private key loaded successfully from " << kalshi_secret_path << "\n";
        }
    }

    // Warn about key/pkey matching
    if (!kalshi_key.empty() && kalshi_pkey) {
        std::cout << "[KX] ⚠️  IMPORTANT: Verify that API key '" << kalshi_key.substr(0, 8) << "...'"
                  << " was generated for the private key in " << kalshi_secret_path << "\n";
        std::cout << "[KX] If they don't match, you will get 401 Unauthorized errors\n";
    }

    // read CSV row
    std::vector<std::string> hdr;
    auto row_opt = read_csv_row(csv, row, hdr);
    if (!row_opt) {
        std::cerr << "Failed to read row " << row << " from " << csv << std::endl;
        return 2;
    }
    auto row_data = *row_opt;
    // map header->value
    std::map<std::string,std::string> rowmap;
    for (size_t i=0;i<hdr.size() && i<row_data.size(); ++i) {
        rowmap[hdr[i]] = trim_quotes(row_data[i]);
    }

    // Helper to get CSV values
    auto get = [&](const char* k)->std::string {
        return rowmap.count(k) ? rowmap[k] : "";
    };

    std::string pm_yes_token = get("pm_yes_token");
    std::string pm_no_token  = get("pm_no_token");
    std::string pm_market_id = get("pm_market_id");

    // Read both event and market tickers from CSV
    std::string kx_event_ticker = get("kalshi_event_ticker");
    std::string kx_market_ticker = get("kalshi_market_ticker");

    // Determine which one we actually have
    std::string kx_ticker;  // Will be set to the market ticker we'll use
    bool has_market_ticker = !kx_market_ticker.empty();

    {
        std::lock_guard lk(out_mtx);
        std::cout << "Row " << row << " | pm_market_id=" << pm_market_id
                  << " | pm_yes_token=" << pm_yes_token
                  << " | kalshi_event=" << kx_event_ticker
                  << " | kalshi_market=" << kx_market_ticker << std::endl;
    }

    // Hydrate missing Polymarket tokens via REST API
    if (pm_yes_token.empty() && !pm_market_id.empty()) {
        std::cout << "[PM] Token missing, fetching from Gamma API for market " << pm_market_id << "...\n";
        auto tokens_opt = fetch_pm_tokens(pm_market_id);
        if (tokens_opt) {
            pm_yes_token = tokens_opt->yes_token;
            pm_no_token = tokens_opt->no_token;
            std::cout << "[PM] Hydrated tokens: yes=" << pm_yes_token << ", no=" << pm_no_token << "\n";
        } else {
            std::cerr << "[PM] WARNING: Failed to fetch tokens for market " << pm_market_id << std::endl;
        }
    }

    if (pm_yes_token.empty()) {
        std::cerr << "[PM] No YES token; relying on market subscription payloads only.\n";
    }

    // Hydrate and normalize Kalshi market (handles categorical O/U, ticker variations)
    std::string kx_subscribe_ticker;  // Actual ticker to subscribe to (may be contract ticker)
    std::string kx_market_type;       // "binary" or "categorical"
    std::string kx_contract_code;     // "YES", "O", "U", etc.

    if (!kalshi_key.empty() && kalshi_pkey) {
        // Fix C: If we only have event ticker, convert it to market ticker first
        std::string raw_ticker;
        if (!has_market_ticker && !kx_event_ticker.empty()) {
            std::cout << "[KX] Converting event ticker to market ticker...\n";
            auto mt = fetch_kalshi_market_ticker_from_event(kx_event_ticker, kalshi_key, kalshi_pkey);
            if (mt) {
                raw_ticker = *mt;  // now a real market ticker
                std::cout << "[KX] Resolved event to market: " << raw_ticker << "\n";
            } else {
                std::cerr << "[KX] Could not resolve a market ticker from event ticker.\n";
            }
        }

        // Fall back to what we have in CSV if conversion didn't work
        if (raw_ticker.empty()) {
            raw_ticker = has_market_ticker ? kx_market_ticker : kx_event_ticker;
        }

        if (!raw_ticker.empty()) {
            std::cout << "[KX] Hydrating and normalizing ticker=" << raw_ticker << "...\n";
            auto kx_info = hydrate_and_normalize_kx_market(raw_ticker, kalshi_key, kalshi_pkey);

            if (kx_info) {
                kx_subscribe_ticker = kx_info->subscribe_ticker;
                kx_market_type = kx_info->market_type;
                kx_contract_code = kx_info->contract_code;

                std::cout << "[KX] Normalized: subscribe_ticker=" << kx_subscribe_ticker
                          << " type=" << kx_market_type
                          << " contract=" << kx_contract_code << "\n";

                // Log which side we matched (for totals)
                if (kx_market_type == "categorical") {
                    std::cout << "[KX] Contract side = " << kx_contract_code
                              << " (assume PM YES matches " << (kx_contract_code=="U"?"Under":"Over") << ")\n";
                }

                // Echo the final ticker we'll subscribe to
                std::cout << "[KX] Will subscribe to ticker: " << kx_subscribe_ticker << "\n";
            } else {
                std::cerr << "[KX] WARNING: Could not hydrate/normalize ticker; KX quotes may remain empty.\n";
            }
        }
    }

    // Use subscribe_ticker for WS, fall back to raw if hydration failed
    kx_ticker = !kx_subscribe_ticker.empty() ? kx_subscribe_ticker :
                (has_market_ticker ? kx_market_ticker : kx_event_ticker);

    // Normalize Polymarket WS URL (subscriptions gateway wants /ws/market)
    auto normalize_pm_ws = [](const std::string& s) -> std::string {
        // Accept any of these and rewrite to the canonical /ws/market endpoint
        if (s == "wss://clob.polymarket.com/ws" ||
            s == "wss://ws-subscriptions-clob.polymarket.com/ws" ||
            s == "wss://ws-subscriptions-clob.polymarket.com/ws/market") {
            std::cerr << "[PM] INFO: Using subscriptions endpoint wss://ws-subscriptions-clob.polymarket.com/ws/market\n";
            return "wss://ws-subscriptions-clob.polymarket.com/ws/market";
        }
        return s;
    };
    pm_ws = normalize_pm_ws(pm_ws);

    // Normalize Kalshi WS URL - keep as-is (no-op)
    auto normalize_kx_ws = [](const std::string& s) -> std::string {
        return s;
    };
    kx_ws = normalize_kx_ws(kx_ws);

    // build actual subscribe JSONs by replacing tokens
    auto replace_all = [](std::string s, const std::string &pat, const std::string &val){
        size_t pos = 0;
        while ((pos = s.find(pat,pos)) != std::string::npos) {
            s.replace(pos, pat.size(), val);
            pos += val.size();
        }
        return s;
    };
    pm_sub = replace_all(pm_sub, "{PM_YES_TOKEN}", pm_yes_token);
    pm_sub = replace_all(pm_sub, "{PM_NO_TOKEN}", pm_no_token);
    pm_sub = replace_all(pm_sub, "{PM_MARKET_ID}", pm_market_id);
    // Support both {KALSHI_TICKER} (new) and {KALSHI_EVENT} (old) placeholders
    kx_sub = replace_all(kx_sub, "{KALSHI_TICKER}", kx_ticker);
    kx_sub = replace_all(kx_sub, "{KALSHI_EVENT}", kx_ticker);
    kx_sub_alt = replace_all(kx_sub_alt, "{KALSHI_TICKER}", kx_ticker);
    kx_sub_alt = replace_all(kx_sub_alt, "{KALSHI_EVENT}", kx_ticker);
    kx_snapshot = replace_all(kx_snapshot, "{KALSHI_TICKER}", kx_ticker);
    kx_snapshot = replace_all(kx_snapshot, "{KALSHI_EVENT}", kx_ticker);

    // Warn if PM tokens are missing (but market L2 feed may work anyway)
    if (pm_yes_token.empty() || pm_no_token.empty()) {
        std::cerr << "[PM] WARNING: Missing token ids for market "
                  << pm_market_id << ". Market L2 feed should still work.\n";
    }

    // Log Kalshi auth status
    if (!kalshi_key.empty() && kalshi_pkey) {
        std::lock_guard lk(out_mtx);
        std::cout << "[KX] Using RSA-PSS headers for WebSocket authentication\n";
    } else {
        std::lock_guard lk(out_mtx);
        std::cout << "[KX] WARNING: Missing API key or private key; Kalshi WS auth will fail.\n";
    }

    QuoteBook pm_q, kx_q;
    std::atomic<bool> stop_flag{false};

    // Seed initial Kalshi quotes from REST snapshot (avoids sitting on NAs waiting for first delta)
    if (!kx_subscribe_ticker.empty() && !kalshi_key.empty() && kalshi_pkey) {
        auto snapshot = fetch_kx_orderbook_snapshot(kx_subscribe_ticker, kalshi_key, kalshi_pkey);
        if (snapshot) {
            kx_q.set_bbo(snapshot->first, snapshot->second);
            std::cout << "[KX] Seeded from snapshot: bid=" << snapshot->first
                      << " ask=" << snapshot->second << "\n";
        }
    }

    // Polymarket: no special headers
    auto pm_header_supplier = []() {
        return std::vector<std::pair<std::string,std::string>>{};
    };

    // Kalshi: regenerate RSA-PSS headers every connect (fresh timestamp/signature)
    const std::string kx_path = "/trade-api/ws/v2";
    auto kx_header_supplier = [&]() {
        std::vector<std::pair<std::string,std::string>> h;
        if (!kalshi_key.empty() && kalshi_pkey) {
            auto fresh = make_kalshi_auth_headers(kalshi_key, kalshi_pkey, kx_path);
            h.insert(h.end(), fresh.begin(), fresh.end());
        }
        return h;
    };

    // start threads
    std::thread t_pm([&](){
        run_ws_watch(pm_ws, pm_header_supplier, pm_sub, "", "", pm_q, "PM", stop_flag, /*verbose=*/false);
    });
    std::thread t_kx([&](){
        run_ws_watch(kx_ws, kx_header_supplier, kx_sub, kx_sub_alt, kx_snapshot, kx_q, "KX", stop_flag, /*verbose=*/true, kalshi_host_override, kalshi_sni_host);
    });
    std::thread t_arb([&](){
        arbitrage_loop(pm_q, kx_q, pm_fee_bps, kx_fee_bps, min_edge_bps, stop_flag,
                       stale_ms, max_skew_ms, ping_ms, windows_csv);
    });

    // ctrl-c handling: simple wait for Enter to quit
    std::cout << "Running. Press ENTER to stop.\n";
    std::string dummy; std::getline(std::cin, dummy);
    stop_flag.store(true);

    t_pm.join();
    t_kx.join();
    t_arb.join();

    std::cout << "Stopped cleanly\n";
    return 0;
}
