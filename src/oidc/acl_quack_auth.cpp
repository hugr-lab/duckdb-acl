// acl_quack_auth.cpp - the door's auth-discovery document (spec 062/064). See acl_quack_auth.hpp.
#include "acl_quack_auth.hpp"

#include "yyjson.hpp"

namespace duckdb {
namespace acl {
namespace oidc {

DoorAuth FetchQuackAuth(const std::string &base_url, int timeout_seconds) {
	DoorAuth out;
	auto base = base_url;
	while (!base.empty() && base.back() == '/') {
		base.pop_back();
	}
	return ParseQuackAuthDocument(HttpGet(base + "/.well-known/quack-auth", timeout_seconds));
}

DoorAuth ParseQuackAuthDocument(const HttpResult &response) {
	DoorAuth out;
	if (!response.Ok()) {
		out.error = response.error.empty() ? ("door discovery answered HTTP " + std::to_string(response.status))
		                                   : response.error;
		return out;
	}
	auto *doc = duckdb_yyjson::yyjson_read(response.body.data(), response.body.size(), 0);
	if (!doc) {
		out.error = "door discovery answered non-JSON";
		return out;
	}
	auto *issuers = duckdb_yyjson::yyjson_obj_get(duckdb_yyjson::yyjson_doc_get_root(doc), "issuers");
	if (issuers && duckdb_yyjson::yyjson_is_arr(issuers)) {
		duckdb_yyjson::yyjson_arr_iter iter;
		duckdb_yyjson::yyjson_arr_iter_init(issuers, &iter);
		while (auto *item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
			if (duckdb_yyjson::yyjson_is_str(item)) {
				// the spec-062 shape: a bare issuer URL
				out.issuers.emplace_back(duckdb_yyjson::yyjson_get_str(item));
			} else if (duckdb_yyjson::yyjson_is_obj(item)) {
				// the spec-064 shape: {"issuer": ..., "client_id": ..., endpoints...}
				auto *issuer = duckdb_yyjson::yyjson_obj_get(item, "issuer");
				if (issuer && duckdb_yyjson::yyjson_is_str(issuer)) {
					out.issuers.emplace_back(duckdb_yyjson::yyjson_get_str(issuer));
				}
			}
		}
	}
	duckdb_yyjson::yyjson_doc_free(doc);
	return out;
}

} // namespace oidc
} // namespace acl
} // namespace duckdb
