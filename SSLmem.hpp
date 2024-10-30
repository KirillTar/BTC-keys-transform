#pragma once
#include <memory>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

struct EVP_CTX_deleter {
    void operator()(void* ptr) {
        EVP_MD_CTX_free((EVP_MD_CTX*)ptr);
    }
};

template <typename T>
using EVP_MD_CTX_ptr = std::unique_ptr<T, EVP_CTX_deleter>;


struct EC_KEY_deleter {
    void operator()(void* ptr) {
#pragma warning(suppress : 4996)
        EC_KEY_free((EC_KEY*)ptr);
    }
};

template <typename T>
using EC_KEY_ptr = std::unique_ptr<T, EC_KEY_deleter>;


struct BN_deleter {
    void operator()(void* ptr) {
        BN_free((BIGNUM*)ptr);
    }
};

template <typename T>
using BN_ptr = std::unique_ptr<T, BN_deleter>;


struct EC_POINT_deleter {
    void operator()(void* ptr) {
        EC_POINT_free((EC_POINT*)ptr);
    }
};

template <typename T>
using EC_POINT_ptr = std::unique_ptr<T, EC_POINT_deleter>;