// The identity model on the store (spec 095): which model is in force, how a write is checked and
// kept, how an issuer's and a client's connection is resolved (its own fields, its secret in the
// node's secrets service, OIDC discovery), the documents read for it, and the verification of a
// token down to its roles and attributes. The decisions themselves are acl_identity's.

#include "acl_policy.hpp"
#include "acl_rewriter.hpp"
#include "acl_token.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "yyjson.hpp"

#include <chrono>

namespace duckdb {
namespace acl {
namespace {

int64_t Now() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

[[noreturn]] void Reject(const string &reason) {
	throw BinderException("acl_rewrite: token rejected: %s", reason);
}

//! The secret's field, '' when absent
string Field(const case_insensitive_map_t<string> &fields, const char *name) {
	auto entry = fields.find(name);
	return entry == fields.end() ? string() : entry->second;
}

string Fingerprint(const string &text) {
	char buffer[20];
	snprintf(buffer, sizeof(buffer), "%016llx", static_cast<unsigned long long>(std::hash<string> {}(text)));
	return buffer;
}

bool SameIssuer(const IdentityIssuer &a, const IdentityIssuer &b) {
	return a.url == b.url && a.secret == b.secret && StringUtil::CIEquals(a.secret_service, b.secret_service);
}

bool SameClient(const IdentityClient &a, const IdentityClient &b) {
	return StringUtil::CIEquals(a.issuer, b.issuer) && a.audiences == b.audiences && a.azp == b.azp &&
	       StoredConditions(a.conditions) == StoredConditions(b.conditions) && a.roles_from == b.roles_from &&
	       a.roles_constant == b.roles_constant && a.unmapped_as_role == b.unmapped_as_role &&
	       StoredAttributes(a.attributes) == StoredAttributes(b.attributes) && a.subject == b.subject &&
	       a.token_type == b.token_type && a.client_id == b.client_id && a.flows == b.flows && a.secret == b.secret &&
	       StringUtil::CIEquals(a.secret_service, b.secret_service) && a.implicit == b.implicit;
}

//! What a discovery document says about keys
struct Discovered {
	string jwks_uri;
	vector<string> algs;
};

Discovered ParseDiscovery(const string &document, const string &url, const string &issuer) {
	auto doc = duckdb_yyjson::yyjson_read(document.c_str(), document.size(), 0);
	auto root = doc ? duckdb_yyjson::yyjson_doc_get_root(doc) : nullptr;
	if (!root || !duckdb_yyjson::yyjson_is_obj(root)) {
		if (doc) {
			duckdb_yyjson::yyjson_doc_free(doc);
		}
		Reject("the discovery document of issuer \"" + issuer + "\" is not a JSON object");
	}
	auto text = [&](const char *key) {
		auto value = duckdb_yyjson::yyjson_obj_get(root, key);
		return value && duckdb_yyjson::yyjson_is_str(value)
		           ? string(duckdb_yyjson::yyjson_get_str(value), duckdb_yyjson::yyjson_get_len(value))
		           : string();
	};
	Discovered out;
	auto named = text("issuer");
	out.jwks_uri = text("jwks_uri");
	auto algs = duckdb_yyjson::yyjson_obj_get(root, "id_token_signing_alg_values_supported");
	if (algs && duckdb_yyjson::yyjson_is_arr(algs)) {
		duckdb_yyjson::yyjson_arr_iter iter;
		duckdb_yyjson::yyjson_arr_iter_init(algs, &iter);
		while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
			if (duckdb_yyjson::yyjson_is_str(item)) {
				out.algs.emplace_back(duckdb_yyjson::yyjson_get_str(item));
			}
		}
	}
	duckdb_yyjson::yyjson_doc_free(doc);
	// OIDC Discovery 1.0 §4.3: the document's issuer is exactly the one it was fetched for - anything
	// else is somebody else's keys
	if (named != url) {
		Reject("the discovery document of issuer \"" + issuer + "\" names issuer \"" + named + "\", not \"" + url +
		       "\"");
	}
	if (out.jwks_uri.empty()) {
		Reject("the discovery document of issuer \"" + issuer + "\" names no jwks_uri");
	}
	return out;
}

unique_ptr<BaseSecret> CreateIdentitySecret(ClientContext &, CreateSecretInput &input) {
	vector<string> scope = input.scope;
	auto secret = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	for (auto &option : input.options) {
		auto key = StringUtil::Lower(option.first);
		if (!option.second.IsNull()) {
			secret->secret_map[Identifier(key)] = Value(option.second.ToString());
		}
	}
	if (input.type.GetIdentifierName() == "oidc_issuer") {
		secret->redact_keys = {"keys"};
	} else {
		secret->redact_keys = {"client_secret"};
	}
	return std::move(secret);
}

} // namespace

void RegisterIdentitySecretTypes(ExtensionLoader &loader) {
	// spec 095: an issuer's and a client's connection, kept in the node's secrets service. The types
	// are ours; any storage that keeps registered types keeps them (tresor does), and the store reads
	// them back only from a secrets service (ReadIdentitySecret).
	struct Shape {
		const char *type;
		vector<const char *> fields;
	};
	for (auto &shape : vector<Shape> {{"oidc_issuer", {"url", "keys", "keys_from", "algs"}},
	                                  {"oidc_client", {"audiences", "client_id", "client_secret"}}}) {
		SecretType type;
		type.name = shape.type;
		type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
		type.default_provider = "config";
		type.extension = "acl";
		loader.RegisterSecretType(type);
		CreateSecretFunction function;
		function.secret_type = shape.type;
		function.provider = "config";
		function.function = CreateIdentitySecret;
		for (auto field : shape.fields) {
			function.named_parameters[field] = LogicalType::VARCHAR;
		}
		loader.RegisterFunction(std::move(function));
	}
}

shared_ptr<const IdentityModel> PolicyStore::Identity() {
	if (catalog) {
		return CatalogIdentity();
	}
	lock_guard<mutex> guard(lock);
	if (!memory_identity) {
		memory_identity = make_shared_ptr<const IdentityModel>();
	}
	return memory_identity;
}

void PolicyStore::EditIdentity(const char *function, const std::function<void(IdentityModel &)> &edit) {
	// the write proper: edit, settle where each named secret lives, validate the whole, keep
	auto apply = [&](IdentityModel &model) {
		auto before = model;
		edit(model);
		case_insensitive_set_t touched;
		for (auto &issuer : model.issuers) {
			auto old = before.Issuer(issuer.name);
			if (old && SameIssuer(*old, issuer)) {
				continue;
			}
			touched.insert("issuer\x1f" + issuer.name);
			if (!issuer.secret.empty()) {
				// a secret written without IN lives in the one service attached; with IN, in that one
				issuer.secret_service = SecretService(issuer.secret_service);
			}
		}
		for (auto &client : model.clients) {
			auto old = before.Client(client.name);
			if (old && SameClient(*old, client)) {
				continue;
			}
			touched.insert("client\x1f" + client.name);
			if (!client.secret.empty()) {
				client.secret_service = SecretService(client.secret_service);
			}
		}
		for (auto &mapping : model.mappings) {
			auto key = mapping.scope_kind + "\x1f" + mapping.scope_name + "\x1f" + mapping.source + "\x1f" +
			           mapping.external_value + "\x1f" + mapping.role;
			bool had = false;
			for (auto &old : before.mappings) {
				had = had ||
				      (old.scope_kind == mapping.scope_kind &&
				       StringUtil::CIEquals(old.scope_name, mapping.scope_name) && old.source == mapping.source &&
				       old.external_value == mapping.external_value && StringUtil::CIEquals(old.role, mapping.role));
			}
			if (!had) {
				touched.insert("mapping\x1f" + key);
			}
		}
		IdentityCheckContext context;
		context.touched = [&](const string &kind, const string &name) {
			return touched.count(kind + "\x1f" + name) > 0;
		};
		context.read_secret = [&](const string &service, const string &name, const string &type,
		                          case_insensitive_map_t<string> &fields) {
			return ReadIdentitySecret(service, name, type, fields);
		};
		context.privileged = [&](const string &role) {
			return RolePrivileged(role);
		};
		ValidateIdentity(model, context);
	};
	if (catalog) {
		CatalogEditIdentity(apply);
		return;
	}
	lock_guard<mutex> writer(identity_write_lock);
	auto model = *Identity();
	apply(model);
	auto next = make_shared_ptr<const IdentityModel>(std::move(model));
	lock_guard<mutex> guard(lock);
	memory_identity = std::move(next);
	(void)function;
}

bool PolicyStore::ReadIdentitySecret(const string &service, const string &name, const string &type,
                                     case_insensitive_map_t<string> &fields) {
	auto db = instance.lock();
	if (!db) {
		return false;
	}
	// judged now, not only where it was written: the service must still be a secrets service of this
	// node (spec 082) - never the node's own memory or local_file storage of the same name
	auto resolved = SecretService(service);
	Connection con(*db);
	unique_ptr<SecretEntry> entry;
	con.context->RunFunctionInTransaction([&]() {
		auto &manager = SecretManager::Get(*con.context);
		entry = manager.GetSecretByName(CatalogTransaction::GetSystemCatalogTransaction(*con.context), name, resolved);
	});
	if (!entry || !entry->secret || !StringUtil::CIEquals(entry->secret->GetType().GetIdentifierName(), type)) {
		return false;
	}
	// the two types are acl's own, registered as key-value secrets
	auto &values = static_cast<const KeyValueSecret &>(*entry->secret);
	for (auto &field : values.secret_map) {
		fields[field.first.GetIdentifierName()] = field.second.IsNull() ? string() : field.second.ToString();
	}
	return true;
}

bool PolicyStore::IssuerUrl(const IdentityIssuer &issuer, string &url) {
	if (issuer.secret.empty()) {
		url = issuer.url;
		return !url.empty();
	}
	case_insensitive_map_t<string> fields;
	try {
		// a service that is gone (detached, down) makes THIS issuer unresolved - routing every other
		// token goes on, and a token meant for this one is refused naming it
		if (!ReadIdentitySecret(issuer.secret_service, issuer.secret, "oidc_issuer", fields)) {
			return false;
		}
	} catch (std::exception &) {
		TakeDenyReason(); // the note belongs to the token's own refusal, if there is one
		return false;
	}
	auto in_secret = Field(fields, "url");
	if (!issuer.url.empty() && !in_secret.empty()) {
		return false; // two homes: neither is trusted (fail closed)
	}
	url = issuer.url.empty() ? in_secret : issuer.url;
	return !url.empty();
}

PolicyStore::ResolvedIssuer PolicyStore::ResolveIssuer(const IdentityIssuer &issuer, const string &url) {
	ResolvedIssuer out;
	out.name = issuer.name;
	out.url = url;
	if (issuer.secret.empty()) {
		return out;
	}
	case_insensitive_map_t<string> fields;
	if (!ReadIdentitySecret(issuer.secret_service, issuer.secret, "oidc_issuer", fields)) {
		NoteDenyReason(Reason::SOURCE_ERROR);
		Reject("the secret of issuer \"" + issuer.name + "\" (" + issuer.secret_service + "." + issuer.secret +
		       ") cannot be read");
	}
	out.keys_json = Field(fields, "keys");
	out.keys_from = Field(fields, "keys_from");
	if (!out.keys_json.empty() && !out.keys_from.empty()) {
		NoteDenyReason(Reason::POLICY_ERROR);
		Reject("the secret of issuer \"" + issuer.name + "\" carries both KEYS and KEYS_FROM");
	}
	for (auto &alg : ParseStoredList(Field(fields, "algs"))) {
		out.algs.insert(alg);
	}
	if (!out.keys_json.empty() || !out.keys_from.empty()) {
		out.key_source = "secret " + issuer.secret_service + "." + issuer.secret;
	}
	// the connection: the URL, where the keys come from and - pasted ones - the keys themselves. Swapping
	// a pasted key in the service changes whom the node trusts as much as repointing the issuer does
	// (whoever holds the new key mints its tokens), so it is a connection change too. Only a fingerprint
	// of it is ever written; a token already lets anyone test guesses at an HS256 key offline.
	NoteConnection("issuer", issuer.name,
	               url + "|" + out.keys_from + "|" + out.keys_json + "|" +
	                   StringUtil::Join(vector<string>(out.algs.begin(), out.algs.end()), ","));
	return out;
}

PolicyStore::ResolvedClient PolicyStore::ResolveClient(const IdentityClient &client) {
	ResolvedClient out;
	out.audiences = client.audiences;
	out.client_id = client.client_id;
	if (client.secret.empty()) {
		return out;
	}
	case_insensitive_map_t<string> fields;
	if (!ReadIdentitySecret(client.secret_service, client.secret, "oidc_client", fields)) {
		NoteDenyReason(Reason::SOURCE_ERROR);
		Reject("the secret of client \"" + client.name + "\" (" + client.secret_service + "." + client.secret +
		       ") cannot be read");
	}
	auto audiences = ParseStoredList(Field(fields, "audiences"));
	auto client_id = Field(fields, "client_id");
	if ((!audiences.empty() && !client.audiences.empty()) || (!client_id.empty() && !client.client_id.empty())) {
		NoteDenyReason(Reason::POLICY_ERROR);
		Reject("client \"" + client.name + "\" has a parameter both on itself and in its secret");
	}
	if (!audiences.empty()) {
		out.audiences = std::move(audiences);
	}
	if (!client_id.empty()) {
		out.client_id = client_id;
	}
	out.client_secret = Field(fields, "client_secret");
	NoteConnection("client", client.name, StringUtil::Join(out.audiences, ",") + "|" + out.client_id);
	return out;
}

string PolicyStore::IssuerKeys(ResolvedIssuer &issuer, const string &kid) {
	if (!issuer.keys_json.empty()) {
		// pasted keys (a secret's KEYS): the one place an HS256 key may come from, and only when the
		// secret's ALGS names it
		if (issuer.algs.empty()) {
			issuer.algs = {"RS256", "ES256"};
		}
		return issuer.keys_json;
	}
	// a key fetched from a location is never a shared secret: HS256 is for pasted keys only
	issuer.algs.erase("HS256");
	auto location = issuer.keys_from;
	if (location.empty()) {
		auto discovery = DiscoveryLocation(issuer.url);
		auto found = ParseDiscovery(CachedDocument(discovery, issuer.name, string(), false), issuer.url, issuer.name);
		location = found.jwks_uri;
		issuer.key_source = "discovery " + location;
		if (issuer.algs.empty()) {
			for (auto &alg : found.algs) {
				if (alg == "RS256" || alg == "ES256") {
					issuer.algs.insert(alg);
				}
			}
			if (found.algs.empty()) {
				issuer.algs = {"RS256"};
			} else if (issuer.algs.empty()) {
				NoteDenyReason(Reason::POLICY_ERROR);
				Reject("issuer \"" + issuer.name + "\" signs with " + StringUtil::Join(found.algs, ", ") +
				       " - this node verifies RS256 and ES256");
			}
		}
	} else if (issuer.algs.empty()) {
		issuer.algs = {"RS256", "ES256"};
	}
	if (issuer.algs.empty()) {
		NoteDenyReason(Reason::POLICY_ERROR);
		Reject("issuer \"" + issuer.name + "\" allows no algorithm this node verifies with keys read from a location");
	}
	return CachedDocument(location, issuer.name, kid, true);
}

bool PolicyStore::ReadDocumentText(const string &uri, string &out, string &error) {
	auto db = instance.lock();
	if (!db) {
		error = "the database is shutting down";
		return false;
	}
	Connection con(*db);
	// spec 101: a document is read whole. httpfs reads in ranges sized by a HEAD, and an IdP that
	// compresses its GET (Microsoft Entra ID: HEAD 24644 bytes, GET 1964) fails that check - so the
	// read forces one full download, on this connection only. A local location never needs it (and its
	// SET could autoload httpfs for nothing); a remote one without httpfs fails at the read, as before.
	if (uri.find("://") != string::npos && !StringUtil::StartsWith(StringUtil::Lower(uri), "file://")) {
		con.Query("SET SESSION force_download = true");
	}
	auto result = con.Query("SELECT content FROM read_text(" + Value(uri).ToSQLString() + ")");
	if (result->HasError()) {
		error = result->GetError();
		return false;
	}
	if (result->RowCount() == 0) {
		error = "there is no document there";
		return false;
	}
	auto value = result->Collection().GetValue(0, 0);
	if (result->RowCount() != 1 || value.IsNull()) {
		error = "the location holds no single document";
		return false;
	}
	out = value.ToString();
	return true;
}

//! spec 023's reading rules, keyed by location (spec 095): a TTL says when to read again, a document
//! without the token's kid is worth one early re-read, and a failed read is survived for a bounded
//! while. Every location is judged against acl_jwks_locations first (spec 071).
string PolicyStore::CachedDocument(const string &location, const string &issuer, const string &kid, bool is_jwks) {
	auto now = Now();
	static constexpr int64_t RETRY_FLOOR_SECONDS = 10;
	string why;
	if (!JwksLocationAllowed(location, why)) {
		bool record = false;
		{
			lock_guard<mutex> guard(lock);
			auto &entry = jwks_cache[location];
			entry.uri = location;
			entry.issuer = issuer;
			record = entry.error != why || now - entry.tried_at >= RETRY_FLOOR_SECONDS;
			entry.tried_at = now;
			entry.error = why;
			entry.keys_json.clear();
			entry.fetched_at = 0;
		}
		if (record) {
			AuditKeys(issuer, false, why, "location_refused", "policy_error");
		}
		NoteDenyReason(Reason::POLICY_ERROR); // the policy names a source this node does not read from
		Reject("issuer \"" + issuer + "\" reads \"" + location + "\", which this node does not: " + why +
		       " - list its prefix there");
	}
	auto refresh = JwksRefreshInterval();
	JwksEntry entry;
	{
		lock_guard<mutex> guard(lock);
		auto found = jwks_cache.find(location);
		if (found != jwks_cache.end()) {
			entry = found->second;
		}
	}
	entry.uri = location;
	entry.issuer = issuer;
	bool expired = entry.keys_json.empty() || now - entry.fetched_at >= refresh;
	// a key that rotated in since the last read: worth one more read, but not once per token
	bool rotated = is_jwks && !expired && !JwksHasKid(entry.keys_json, kid);
	if ((expired || rotated) && now - entry.tried_at >= (rotated ? RETRY_FLOOR_SECONDS : 0)) {
		string document, error;
		entry.tried_at = now;
		if (ReadDocumentText(location, document, error)) {
			entry.keys_json = std::move(document);
			entry.fetched_at = now;
			entry.error.clear();
		} else {
			entry.error = std::move(error);
		}
		AuditKeys(issuer, entry.error.empty(), entry.error);
		lock_guard<mutex> guard(lock);
		if (!entry.error.empty() && jwks_cache.find(location) == jwks_cache.end()) {
			// acl_jwks_refresh dropped the entry while this read was in flight and the read failed: the
			// copy in hand carries the old document, which the drop meant to end (spec 071 review)
			entry.keys_json.clear();
			entry.fetched_at = 0;
		}
		jwks_cache[location] = entry;
	}
	if (entry.keys_json.empty()) {
		NoteDenyReason(Reason::SOURCE_ERROR); // the document's source, not the principal, is what failed
		Reject("issuer \"" + issuer + "\" could not read \"" + location + "\": " + entry.error);
	}
	// a document that can no longer be read is used for a bounded while and then stops being trusted
	auto max_stale = JwksMaxStale();
	if (!entry.error.empty() && (max_stale <= 0 || now - entry.fetched_at > max_stale)) {
		NoteDenyReason(Reason::SOURCE_ERROR);
		Reject("issuer \"" + issuer + "\" last read \"" + location + "\" " + std::to_string(now - entry.fetched_at) +
		       " seconds ago and it is still unreadable (" + entry.error + "); acl_jwks_max_stale is " +
		       std::to_string(max_stale));
	}
	return entry.keys_json;
}

vector<PolicyStore::JwksCacheRow> PolicyStore::JwksCacheRows() {
	vector<JwksCacheRow> rows;
	lock_guard<mutex> guard(lock);
	for (auto &cached : jwks_cache) {
		JwksCacheRow row;
		row.issuer = cached.second.issuer;
		row.location = cached.second.uri;
		string why;
		row.allowed = JwksLocationAllowed(row.location, why);
		row.fetched_at = cached.second.fetched_at;
		row.tried_at = cached.second.tried_at;
		row.error = cached.second.error;
		if (!cached.second.keys_json.empty()) {
			row.keys = JwksKeyIds(cached.second.keys_json, row.kids);
		}
		rows.push_back(std::move(row));
	}
	std::sort(rows.begin(), rows.end(), [](const JwksCacheRow &a, const JwksCacheRow &b) {
		return a.issuer != b.issuer ? a.issuer < b.issuer : a.location < b.location;
	});
	return rows;
}

int64_t PolicyStore::JwksDropCache(const string &issuer) {
	lock_guard<mutex> guard(lock);
	int64_t dropped = 0;
	for (auto entry = jwks_cache.begin(); entry != jwks_cache.end();) {
		if (issuer.empty() || StringUtil::CIEquals(entry->second.issuer, issuer)) {
			entry = jwks_cache.erase(entry);
			dropped++;
		} else {
			++entry;
		}
	}
	return dropped;
}

void PolicyStore::NoteConnection(const string &kind, const string &name, const string &connection) {
	auto fingerprint = Fingerprint(connection);
	bool changed = false;
	{
		lock_guard<mutex> guard(lock);
		auto &last = connection_fingerprints[kind + "\x1f" + name];
		changed = !last.empty() && last != fingerprint;
		last = fingerprint;
	}
	if (changed) {
		AuditConnection(kind, name, fingerprint);
	}
}

bool PolicyStore::RoleKnown(const string &role) {
	if (catalog) {
		case_insensitive_set_t known;
		CatalogKnownRoles({role}, known);
		return known.count(role) > 0;
	}
	lock_guard<mutex> guard(lock);
	return tables.count(role) || table_functions.count(role) || scalar_functions.count(role) ||
	       role_claims.count(role) || admin_scopes.count(role);
}

bool PolicyStore::RolePrivileged(const string &role) {
	Principal probe;
	probe.roles = {role};
	auto rights = AdminRightsOf(probe);
	// any scope, observe included (spec 097): a role that reads the node's load report is privileged
	// too - reached only through a client's own mapping (spec 095), never by an IdP group's name
	return rights.scope != AdminScope::NONE || rights.unrestricted_manage || !rights.catalogs.empty() ||
	       rights.unknown_scope;
}

void PolicyStore::VerifyJwtPrincipal(const string &token, const string &iss, Principal &out, bool ignore_exp,
                                     int64_t *expires_at) {
	auto model = Identity();
	// route by URL: exactly one issuer, whatever its secrets say right now
	optional_ptr<const IdentityIssuer> routed;
	vector<string> unresolved;
	for (auto &issuer : model->issuers) {
		string url;
		if (!IssuerUrl(issuer, url)) {
			unresolved.push_back(issuer.name);
			continue;
		}
		if (url == iss) {
			if (routed) {
				NoteDenyReason(Reason::POLICY_ERROR);
				Reject("issuers \"" + routed->name + "\" and \"" + issuer.name + "\" both resolve to \"" + iss + "\"");
			}
			routed = &issuer;
		}
	}
	if (!routed) {
		if (!unresolved.empty()) {
			NoteDenyReason(Reason::SOURCE_ERROR);
			Reject("unknown issuer \"" + iss + "\" (the URL of " + StringUtil::Join(unresolved, ", ") +
			       " is in a secret that could not be read)");
		}
		Reject("unknown issuer \"" + iss + "\"");
	}
	auto resolved = ResolveIssuer(*routed, iss);
	auto keys = IssuerKeys(resolved, JwtKid(token));
	auto verified = VerifyJwtSignature(token, keys, resolved.algs, JwtClockSkew(), ignore_exp);
	if (verified.issuer != resolved.url) {
		Reject("issuer mismatch");
	}
	TokenClaims claims(verified.payload_json);
	if (!claims.Valid()) {
		Reject("malformed JWT JSON");
	}
	// route to exactly one client: the most specific that accepts the token
	vector<optional_ptr<const IdentityClient>> candidates;
	vector<int> specificities;
	string refusal;
	for (auto &client : model->clients) {
		if (!StringUtil::CIEquals(client.issuer, routed->name)) {
			continue;
		}
		// a client whose secret cannot be read refuses the token rather than being skipped: skipping
		// it could hand the token to a less specific client, which is a widening
		auto connection = ResolveClient(client);
		string why;
		if (ClientAccepts(client, connection.audiences, claims, verified.token_type, why)) {
			candidates.push_back(&client);
			specificities.push_back(ClientSpecificity(client));
		} else if (refusal.empty() || (refusal == "audience not accepted" && why != refusal)) {
			// the reason worth reading is that of a client the token was meant for: past its audience
			refusal = why;
		}
	}
	if (candidates.empty()) {
		Reject("no client of issuer \"" + routed->name + "\" accepts this token" +
		       (refusal.empty() ? string() : " (" + refusal + ")"));
	}
	bool ambiguous = false;
	auto chosen = PickClient(specificities, ambiguous);
	if (chosen < 0) {
		vector<string> names;
		for (auto &candidate : candidates) {
			names.push_back(candidate->name);
		}
		NoteDenyReason(Reason::POLICY_ERROR);
		Reject("the token fits clients " + StringUtil::Join(names, ", ") + " of issuer \"" + routed->name +
		       "\" equally - tell them apart by AUDIENCES, AZP or REQUIRE");
	}
	auto &client = *candidates[NumericCast<idx_t>(chosen)];
	out.subject = SubjectFor(client, claims);
	// the IdP's URL, not the issuer's name: what the audit and a secrets service key a user's identity
	// by must change when the name is pointed at another IdP
	out.issuer = resolved.url;
	auto roles = RolesFor(
	    *model, client, claims, [&](const string &role) { return RoleKnown(role); },
	    [&](const string &role) { return RolePrivileged(role); });
	out.roles = std::move(roles.roles);
	if (out.roles.empty()) {
		if (claims.GroupsOverage()) {
			Reject("groups overage - the groups claim was replaced by a Graph link; resolve groups at the gateway "
			       "and use the ROLE form");
		}
		Reject("no recognized roles");
	}
	out.claims = AttributesFor(client, claims);
	if (expires_at) {
		*expires_at = verified.expires_at;
	}
	// role-default claims of the mapped roles (explicit token claims win); the catalog side is
	// merged by the caller via CatalogLoadRoleClaims
	MergeMemoryRoleDefaults(out);
}

vector<PolicyStore::DoorIssuer> PolicyStore::DoorIssuers(bool with_client_secrets) {
	vector<DoorIssuer> out;
	auto model = Identity();
	for (auto &issuer : model->issuers) {
		DoorIssuer door;
		door.name = issuer.name;
		try {
			if (!IssuerUrl(issuer, door.url)) {
				continue; // its URL is in a secret that cannot be read now: not advertised (fail closed)
			}
		} catch (std::exception &) {
			continue;
		}
		for (auto &client : model->clients) {
			if (!StringUtil::CIEquals(client.issuer, issuer.name)) {
				continue;
			}
			try {
				auto connection = ResolveClient(client);
				door.clients.push_back({client.name, connection.client_id,
				                        with_client_secrets ? connection.client_secret : string(), client.flows});
			} catch (std::exception &) {
				TakeDenyReason(); // a note for nobody: this is a listing, not a refusal
				continue;
			}
		}
		out.push_back(std::move(door));
	}
	return out;
}

} // namespace acl
} // namespace duckdb
