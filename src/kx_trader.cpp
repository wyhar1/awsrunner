// kx_trader.cpp
// Build: g++ -O2 -std=c++20 kx_trader.cpp -lssl -lcrypto -lpthread -lboost_system
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <iostream>
#include <chrono>
#include <string>

using json = nlohmann::json;
namespace asio = boost::asio;
namespace ssl  = boost::asio::ssl;
namespace http = boost::beast::http;
using tcp      = asio::ip::tcp;

static std::string b64(const unsigned char* data, size_t len){
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}

static EVP_PKEY* load_key(const std::string& pem_path){
    FILE* fp = fopen(pem_path.c_str(), "rb");
    if(!fp) return nullptr;
    EVP_PKEY* k = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return k;
}

static std::string sign_pss_b64(EVP_PKEY* key, const std::string& msg){
    std::string out;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx) return out;
    if(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) != 1){ EVP_MD_CTX_free(ctx); return out; }
    EVP_PKEY_CTX* pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1);
    size_t len=0;
    EVP_DigestSignUpdate(ctx, msg.data(), msg.size());
    EVP_DigestSignFinal(ctx, nullptr, &len);
    std::vector<unsigned char> sig(len);
    if(EVP_DigestSignFinal(ctx, sig.data(), &len) == 1) out = b64(sig.data(), len);
    EVP_MD_CTX_free(ctx);
    return out;
}

// CLI:
//   --key-id <KALSHI_KEY_ID>
//   --pem    </path/to/private_key.pem>
//   --ticker <MARKET_TICKER>   (e.g., KXNBAGAME-25NOV07BOSORL-BOS or a YES/NO binary ticker)
//   --side   <buy|sell>        (YES side implied for binaries; for categorical your ticker should be the contract)
//   --qty    <integer shares>
//   --price  <dollars, e.g. 0.62>
//   --tif    <GTC|IOC|FOK>     (Kalshi uses tif in payload)
// Optional:
//   --host   api.elections.kalshi.com
int main(int argc, char** argv){
    std::string key_id, pem, ticker, side, tif="GTC", host="api.elections.kalshi.com";
    int qty = 0; double price = 0.0;
    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        if(a=="--key-id" && i+1<argc) key_id=argv[++i];
        else if(a=="--pem" && i+1<argc) pem=argv[++i];
        else if(a=="--ticker" && i+1<argc) ticker=argv[++i];
        else if(a=="--side" && i+1<argc) side=argv[++i];
        else if(a=="--qty" && i+1<argc) qty=std::stoi(argv[++i]);
        else if(a=="--price" && i+1<argc) price=std::stod(argv[++i]);
        else if(a=="--tif" && i+1<argc) tif=argv[++i];
        else if(a=="--host" && i+1<argc) host=argv[++i];
    }
    if(key_id.empty()||pem.empty()||ticker.empty()||side.empty()||qty<=0||price<=0){
        std::cerr << "usage: kx_trader --key-id ... --pem key.pem --ticker ... --side buy|sell --qty N --price P [--tif GTC|IOC|FOK]\n";
        return 2;
    }
    EVP_PKEY* pkey = load_key(pem);
    if(!pkey){ std::cerr<<"bad pem\n"; return 3; }

    // 1) Auth headers (timestamp + "POST" + path) -> RSA-PSS b64 (per v2 WS/REST auth pattern)
    const std::string path = "/trade-api/v2/portfolio/orders";
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string ts = std::to_string(ms);
    const std::string to_sign = ts + "POST" + path;  // Kalshi specifies ts+METHOD+path
    const std::string sig = sign_pss_b64(pkey, to_sign);

    // 2) Build order JSON (matches docs’ v2 create order)
    //    { "order": {market_ticker, type:"limit", action:"buy"/"sell", yes/no implied, quantity, price, tif}, "action":"create" }
    json payload = {
        {"order", {
            {"market_ticker", ticker},
            {"type", "limit"},
            {"action", side},
            {"quantity", qty},
            {"price", price},
            {"tif", tif}
        }},
        {"action", "create"}
    };

    try{
        asio::io_context ioc;
        ssl::context sslctx(ssl::context::tlsv12_client);
        sslctx.set_default_verify_paths();
        tcp::resolver res{ioc};
        auto results = res.resolve(host, "443");
        boost::beast::tcp_stream tcp(ioc);
        tcp.connect(results);
        boost::beast::ssl_stream<boost::beast::tcp_stream> tls(std::move(tcp), sslctx);
        if(!SSL_set_tlsext_host_name(tls.native_handle(), host.c_str())) throw std::runtime_error("SNI fail");
        tls.handshake(ssl::stream_base::client);

        http::request<http::string_body> req{http::verb::post, path, 11};
        req.set(http::field::host, host);
        req.set(http::field::content_type, "application/json");
        req.set("KALSHI-ACCESS-KEY", key_id);
        req.set("KALSHI-ACCESS-SIGNATURE", sig);
        req.set("KALSHI-ACCESS-TIMESTAMP", ts);
        req.body() = payload.dump();
        req.prepare_payload();

        http::write(tls, req);
        boost::beast::flat_buffer buffer;
        http::response<http::string_body> res2;
        http::read(tls, buffer, res2);
        std::cout << res2.body() << std::endl;
        boost::system::error_code ec;
        tls.shutdown(ec);
    }catch(std::exception& e){
        std::cerr << "ERR: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

