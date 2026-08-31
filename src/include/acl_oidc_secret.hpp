//===----------------------------------------------------------------------===//
// acl_oidc_secret.hpp — the quack OIDC secret provider (spec 061, design/016 A1)
//
// Registers `CREATE SECRET (TYPE quack, PROVIDER oidc, ...)`: the provider runs
// the configured OAuth flow against the issuer at CREATE SECRET time and stores
// the minted access token in the exact shape quack's client already reads
// (secret_map["token"]) — quack itself is unchanged, and the node never calls
// any of this: it is client-side acquisition (design/016 §0).
//===----------------------------------------------------------------------===//

#pragma once

namespace duckdb {
class ExtensionLoader;

namespace acl {

void RegisterQuackOidcProvider(ExtensionLoader &loader);

} // namespace acl
} // namespace duckdb
