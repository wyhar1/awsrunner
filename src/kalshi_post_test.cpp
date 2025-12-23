#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <algorithm>

using json = nlohmann::json;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;

static std::string b64_encode(const unsigned char* data, size_t len) {
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

static EVP_PKEY* load_pkey(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return nullptr;
    EVP_PKEY* p = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    return p;
}

static std::string sign_pss_base64(EVP_PKEY* pkey, const std::string& msg) {
    std::string ret;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return ret;
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) { EVP_MD_CTX_free(ctx); return ret; }
    EVP_PKEY_CTX* pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
    if (pctx) {
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1);
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256());
    }
    size_t siglen = 0;
    if (EVP_DigestSignUpdate(ctx, msg.data(), msg.size()) != 1 || EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) { EVP_MD_CTX_free(ctx); return ret; }
    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSignFinal(ctx, sig.data(), &siglen) != 1) { EVP_MD_CTX_free(ctx); return ret; }
    EVP_MD_CTX_free(ctx);
    ret = b64_encode(sig.data(), siglen);
    return ret;
}

static std::vector<std::pair<std::string,std::string>> make_kalshi_rest_auth_headers(
    const std::string& key_id,
    EVP_PKEY* pkey,
    const std::string& method,
    const std::string& path,
    const std::string& body = "") {
    using namespace std::chrono;
    auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    std::string ts = std::to_string(ms);
    std::string m = method;
    for (auto &c : m) c = std::toupper(static_cast<unsigned char>(c));
    std::string to_sign = ts + m + path + body;
    std::string sig_b64 = sign_pss_base64(pkey, to_sign);
    return {
        {"KALSHI-ACCESS-KEY",       key_id},
        {"KALSHI-ACCESS-SIGNATURE", sig_b64},
        {"KALSHI-ACCESS-TIMESTAMP", ts}
    };
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: kalshi_post_test <KALSHI_KEY_ID> <PRIVATE_KEY_PEM_PATH> [host=api.elections.kalshi.com] [--no-http]" << std::endl;
        return 2;
    }
    std::string key_id = argv[1];
    std::string pkey_path = argv[2];
    std::string host = "api.elections.kalshi.com";
    std::string connect_ip = ""; // optional explicit connect IP to bypass DNS
    bool do_http = true;
    bool do_live = false;
    bool do_send_only = false;
    bool auto_probe = false; // try many canonicalizations automatically
    // Parse flags and optional host. Flags start with '-' and are handled; the first non-flag arg is host.
    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--no-http") { do_http = false; }
        else if (a == "--live") { do_live = true; }
        else if (a == "--send-only") { do_send_only = true; }
        else if (a == "--auto-probe") { auto_probe = true; }
        else if (a == "--connect-ip" && i+1 < argc) { connect_ip = argv[++i]; }
        else if (!a.empty() && a[0] == '-') {
            // unknown flag - ignore
        } else {
            host = a; // first non-flag argument is host
        }
    }
    if (!do_http) std::cerr << "NOTICE: running in --no-http mode (will not perform network requests)\n";
    std::string path = "/trade-api/v2/portfolio/orders";

    EVP_PKEY* pkey = load_pkey(pkey_path);
    if (!pkey) { std::cerr << "Failed to load private key: "<<pkey_path<<"\n"; return 2; }

    // Minimal limit IOC buy YES example.
    // For safety, default to count=0 (non-filling) unless --live is passed.
    json body = {
        {"ticker","TEST-TICKER"},
        {"side","yes"},
        {"action","buy"},
        {"count", do_live ? 1 : 0},
        {"type","limit"},
        {"time_in_force","immediate_or_cancel"},
        {"yes_price_dollars","0.3100"}
    };
    std::string body_str = body.dump();
    // also build a deterministically sorted-key JSON representation for testing
    auto dump_sorted = [&](const json &j) {
        if (!j.is_object()) return j.dump();
        std::vector<std::string> keys;
        for (auto it = j.begin(); it != j.end(); ++it) keys.push_back(it.key());
        std::sort(keys.begin(), keys.end());
        json out = json::object();
        for (auto &k : keys) out[k] = j[k];
        return out.dump();
    };
    std::string body_sorted = dump_sorted(body);

    std::vector<std::string> ts_units = {"sec","ms"};
    std::vector<int> ts_mult = {1, 1000}; // multiply seconds by these to produce timestamp
    std::vector<std::string> formats = {
        "concat",
        "newline",
        "newline_trailing"
    };
    std::vector<std::string> method_cases = {"UPPER","lower"};
    std::vector<std::string> body_variants = {"compact","sorted"};
    std::vector<std::string> body_hash_modes = {"raw","sha256_hex","sha256_b64"};
    std::vector<int> saltlens = {-1, 32, 0};
    std::vector<std::string> sig_algs = {"PSS", "PKCS1"};
    std::vector<std::string> b64_variants = {"std", "urlsafe"};

    asio::io_context ioc;
    ssl::context ctx(ssl::context::tlsv12_client);
    ctx.set_default_verify_paths();

    bool found = false;
    struct Candidate { std::string fmt, method_case, ts_unit, body_variant; int saltlen; } winner;
    for (size_t ui = 0; ui < ts_units.size() && !found; ++ui) {
        for (auto const &fmt : formats) {
            for (auto const &mcase : method_cases) {
                for (auto const &bvar : body_variants) {
                    for (int saltlen : saltlens) {
                        using namespace std::chrono;
                        auto now = system_clock::now();
                        auto s = duration_cast<seconds>(now.time_since_epoch()).count();
                        long long ts = s * ts_mult[ui];
                        std::string ts_str = std::to_string(ts);
                        std::string method = (mcase=="UPPER")?"POST":"post";
                        std::string body_used = (bvar=="compact")?body_str:body_sorted;
                        // compute body hash variants
                        std::string body_sha256_hex;
                        std::string body_sha256_b64;
                        // compute SHA256 of body_used
                        {
                            unsigned char md[EVP_MAX_MD_SIZE];
                            unsigned int mdlen = 0;
                            EVP_MD_CTX* mctx = EVP_MD_CTX_new();
                            if (mctx) {
                                EVP_DigestInit_ex(mctx, EVP_sha256(), nullptr);
                                EVP_DigestUpdate(mctx, body_used.data(), body_used.size());
                                EVP_DigestFinal_ex(mctx, md, &mdlen);
                                EVP_MD_CTX_free(mctx);
                                // hex
                                std::ostringstream os; os<<std::hex<<std::setfill('0');
                                for (unsigned int ii=0; ii<mdlen; ++ii) os<<std::setw(2)<<(int)md[ii];
                                body_sha256_hex = os.str();
                                // b64
                                body_sha256_b64 = b64_encode(md, mdlen);
                            }
                        }
                        std::string to_sign;
                        if (fmt == "concat") {
                            to_sign = ts_str + method + path + body_used;
                        } else if (fmt == "newline" || fmt=="newline_trailing") {
                            to_sign = ts_str + "\n" + method + "\n" + path + "\n" + body_used;
                            if (fmt=="newline_trailing") to_sign += "\n"; // try trailing newline variant
                        }

                        for (auto const &alg : sig_algs) {
                            for (auto const &b64v : b64_variants) {
                                // Sign with specific algorithm and saltlen (saltlen only used for PSS)
                                for (auto const &body_hash_mode : body_hash_modes) {
                                    std::string body_for_sign = body_used;
                                    if (body_hash_mode == "sha256_hex") body_for_sign = body_sha256_hex;
                                    else if (body_hash_mode == "sha256_b64") body_for_sign = body_sha256_b64;
                                    std::string sig;
                                    if (alg == "PSS") {
                                        EVP_MD_CTX* ctx2 = EVP_MD_CTX_new();
                                        if (ctx2) {
                                            if (EVP_DigestSignInit(ctx2, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
                                                EVP_PKEY_CTX* pctx = EVP_MD_CTX_get_pkey_ctx(ctx2);
                                                if (pctx) {
                                                    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
                                                    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen);
                                                    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256());
                                                }
                                                size_t slen = 0;
                                                std::string to_sign_variant = to_sign;
                                                // if body hash mode != raw, replace the body part in to_sign with the hash
                                                if (body_hash_mode != "raw") {
                                                    // naive replacement: find body_used in to_sign and replace with body_for_sign
                                                    size_t pos = to_sign_variant.find(body_used);
                                                    if (pos != std::string::npos) to_sign_variant.replace(pos, body_used.size(), body_for_sign);
                                                }
                                                if (EVP_DigestSignUpdate(ctx2, to_sign_variant.data(), to_sign_variant.size()) == 1 && EVP_DigestSignFinal(ctx2, nullptr, &slen) == 1) {
                                                    std::vector<unsigned char> sbuf(slen);
                                                    if (EVP_DigestSignFinal(ctx2, sbuf.data(), &slen) == 1) sig = b64_encode(sbuf.data(), slen);
                                                }
                                            }
                                            EVP_MD_CTX_free(ctx2);
                                        }
                                    } else { // PKCS1
                                        EVP_MD_CTX* ctx2 = EVP_MD_CTX_new();
                                        if (ctx2) {
                                            if (EVP_DigestSignInit(ctx2, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
                                                size_t slen = 0;
                                                std::string to_sign_variant = to_sign;
                                                if (body_hash_mode != "raw") {
                                                    size_t pos = to_sign_variant.find(body_used);
                                                    if (pos != std::string::npos) to_sign_variant.replace(pos, body_used.size(), body_for_sign);
                                                }
                                                if (EVP_DigestSignUpdate(ctx2, to_sign_variant.data(), to_sign_variant.size()) == 1 && EVP_DigestSignFinal(ctx2, nullptr, &slen) == 1) {
                                                    std::vector<unsigned char> sbuf(slen);
                                                    if (EVP_DigestSignFinal(ctx2, sbuf.data(), &slen) == 1) sig = b64_encode(sbuf.data(), slen);
                                                }
                                            }
                                            EVP_MD_CTX_free(ctx2);
                                        }
                                    }
                                    // Apply URL-safe base64 variant if requested
                                    if (b64v == "urlsafe" && !sig.empty()) {
                                        for (auto &c : sig) {
                                            if (c == '+') c = '-';
                                            else if (c == '/') c = '_';
                                        }
                                        // remove padding '=' for URL-safe variant
                                        while (!sig.empty() && sig.back() == '=') sig.pop_back();
                                    }

                                    std::cerr << "--- TRY fmt="<<fmt<<" method="<<method<<" ts_unit="<<ts_units[ui]
                                              <<" body="<<bvar<<" saltlen="<<saltlen<<" alg="<<alg<<" b64="<<b64v<<" ---\n";
                                    std::cerr << "to_sign(len="<<to_sign.size()<<"):'"<< (to_sign.size()>200?to_sign.substr(0,200)+"...":to_sign) <<"'\n";
                                    std::cerr << "signature(base64)='"<< (sig.empty()?"<sign-failed>":sig) <<"'\n";

                                    // For each variant, attempt HTTP if allowed
                                    if (do_http) {
                                        try {
                                            tcp::resolver resolver{ioc};
                                            auto const results = connect_ip.empty() ? resolver.resolve(host, "443") : resolver.resolve(connect_ip, "443");
                                            beast::tcp_stream tcp(ioc);
                                            tcp.connect(results);
                                            beast::ssl_stream<beast::tcp_stream> tls(std::move(tcp), ctx);
                                            if(!SSL_set_tlsext_host_name(tls.native_handle(), host.c_str())) {}
                                            tls.handshake(ssl::stream_base::client);
                                            http::request<http::string_body> req{http::verb::post, path, 11};
                                            req.set(http::field::host, host);
                                            req.set(http::field::content_type, "application/json");
                                            req.set("KALSHI-ACCESS-KEY", key_id);
                                            req.set("KALSHI-ACCESS-SIGNATURE", sig);
                                            req.set("KALSHI-ACCESS-TIMESTAMP", ts_str);
                                            req.body() = body_str;
                                            req.prepare_payload();
                                            if (!do_live && !do_send_only) {
                                                std::cerr << "(HTTP would be sent here, but neither --live nor --send-only specified)\n";
                                            }
                                            if (do_live || do_send_only) {
                                                http::write(tls, req);
                                                beast::flat_buffer buffer;
                                                http::response<http::string_body> res;
                                                http::read(tls, buffer, res);
                                                std::cerr << "HTTP "<<static_cast<int>(res.result())<<" reason='"<<res.reason()<<"' body='"<<res.body()<<"'\n";
                                                if (static_cast<int>(res.result()) >= 200 && static_cast<int>(res.result()) < 300) {
                                                    std::cerr << "*** SUCCESS with variant: fmt="<<fmt<<" method="<<method<<" ts_unit="<<ts_units[ui]
                                                              <<" body="<<bvar<<" saltlen="<<saltlen<<" alg="<<alg<<" b64="<<b64v<<"***\n";
                                                    EVP_PKEY_free(pkey);
                                                    return 0;
                                                }
                                            }
                                            tls.shutdown();
                                        } catch (const std::exception &e) {
                                            std::cerr << "HTTP request exception: "<< e.what() <<"\n";
                                        }
                                    } else {
                                        std::cerr << "(skipped HTTP request -- no network)" << std::endl;
                                    }
                                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                } // end body_hash_mode
                            } // end b64 variants
                        } // end alg loop
                    } // saltlen loop
                } // bvar loop
            } // method_cases loop
        } // formats loop
    } // ts_units loop

    EVP_PKEY_free(pkey);
    return 0;
}
