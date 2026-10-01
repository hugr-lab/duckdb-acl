// Spec 093: the cluster profile - the shared part of every node's bootstrap, kept in the policy catalog
// as desired state only. A change is checked, written with a config_version bump in one catalog
// transaction, and - when it can be applied live - applied on this node before the commit, so what
// reaches the cluster has worked on at least one node. Converging the other nodes is not this
// extension's: that is the node agent's (hugr_node). Seam: RegisterAclCluster.

#include "acl_cluster.hpp"

#include "acl_door_common.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_result_rows.hpp"

#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "yyjson.hpp"

#include <algorithm>
#include <functional>

namespace duckdb {
namespace acl {

using acl_detail::CatalogBackend;
using acl_detail::Lit;

namespace {

//! Keys that carry a credential, wherever they are written: a conninfo `k=v`, a URI query parameter,
//! an ATTACH option. The profile names secrets; it never holds one (design/017 §3.6a).
const case_insensitive_set_t CREDENTIAL_KEYS = {"password",
                                                "passwd",
                                                "pwd",
                                                "passfile",
                                                "secret",
                                                "client_secret",
                                                "token",
                                                "bearer_token",
                                                "access_token",
                                                "key_id",
                                                "session_token",
                                                "secret_access_key",
                                                "account_key",
                                                "sas_token",
                                                "sig",
                                                "private_key",
                                                "connection_string",
                                                "aws_secret_access_key"};

//! The node's hardening, fixed by its bootstrap - never a profile item
const case_insensitive_set_t HARDENING_SETTINGS = {"allow_unsigned_extensions",
                                                   "allow_community_extensions",
                                                   "allow_extension_repositories",
                                                   "allow_persistent_secrets",
                                                   "allow_unredacted_secrets",
                                                   "lock_configuration",
                                                   "extension_repository_directory",
                                                   "allow_parser_override_extension",
                                                   "enable_external_access",
                                                   "secret_directory",
                                                   "extension_directory",
                                                   "extension_directories",
                                                   "home_directory",
                                                   "allowed_directories",
                                                   "allowed_paths"};

//! Source types whose connection needs a credential: written without SECRET, refused
const case_insensitive_set_t TYPES_NEEDING_SECRET = {"postgres", "postgres_scanner", "mysql", "mysql_scanner", "mssql"};

//! The extension a source type needs loaded ('' = a core type)
string ExtensionOfType(const string &type) {
	auto t = StringUtil::Lower(type);
	if (t == "postgres" || t == "postgres_scanner") {
		return "postgres_scanner";
	}
	if (t == "mysql" || t == "mysql_scanner") {
		return "mysql_scanner";
	}
	if (t == "sqlite" || t == "sqlite_scanner") {
		return "sqlite_scanner";
	}
	if (t == "duckdb" || t.empty()) {
		return "";
	}
	return t; // ducklake, mssql, iceberg, delta, ... are named like their extension
}

[[noreturn]] void RefuseCredential(const string &key, const string &where) {
	throw BinderException("acl cluster: \"%s\" in %s is a credential, and the cluster profile never holds one - "
	                      "create a secret (in the node's secrets service) and name it with SECRET <name>",
	                      key, where);
}

void LintKey(const string &key, const string &where) {
	auto k = key;
	StringUtil::Trim(k);
	if (CREDENTIAL_KEYS.count(k)) {
		RefuseCredential(k, where);
	}
}

//! A path as written: a conninfo list, a URI, a prefixed form (`ducklake:postgres:k=v ...`) - every
//! `k=v` in it is checked by its key, and a URI's userinfo may carry a user but never a password
void LintPath(const string &path) {
	// userinfo: scheme://user:secret@host
	auto scheme = path.find("://");
	if (scheme != string::npos) {
		auto authority_start = scheme + 3;
		auto authority_end = path.find_first_of("/?#", authority_start);
		auto authority = path.substr(authority_start,
		                             authority_end == string::npos ? string::npos : authority_end - authority_start);
		auto at = authority.rfind('@');
		if (at != string::npos && authority.substr(0, at).find(':') != string::npos) {
			RefuseCredential("user:password@", "the source's URI");
		}
	}
	string token;
	auto flush = [&]() {
		auto eq = token.find('=');
		if (eq != string::npos) {
			auto key = token.substr(0, eq);
			auto colon = key.find_last_of(":/");
			if (colon != string::npos) {
				key = key.substr(colon + 1);
			}
			LintKey(key, "the source's path");
		}
		token.clear();
	};
	for (auto c : path) {
		if (c == ' ' || c == '\t' || c == ';' || c == '&' || c == '?' || c == '\n') {
			flush();
		} else {
			token += c;
		}
	}
	flush();
}

string JsonObjectOf(const vector<std::pair<string, string>> &entries) {
	vector<string> out;
	for (auto &entry : entries) {
		out.push_back(JsonQuote(entry.first) + ": " + JsonQuote(entry.second));
	}
	return "{" + StringUtil::Join(out, ", ") + "}";
}

vector<std::pair<string, string>> ParseOptions(const string &json) {
	using namespace duckdb_yyjson; // NOLINT
	vector<std::pair<string, string>> out;
	if (json.empty()) {
		return out;
	}
	auto doc = yyjson_read(json.c_str(), json.size(), 0);
	if (!doc) {
		throw BinderException("acl cluster: the source's options are a JSON object, got \"%s\"", json);
	}
	auto root = yyjson_doc_get_root(doc);
	if (!yyjson_is_obj(root)) {
		yyjson_doc_free(doc);
		throw BinderException("acl cluster: the source's options are a JSON object");
	}
	yyjson_val *key;
	yyjson_obj_iter iter = yyjson_obj_iter_with(root);
	while ((key = yyjson_obj_iter_next(&iter))) {
		auto val = yyjson_obj_iter_get_val(key);
		string value;
		if (yyjson_is_str(val)) {
			value = yyjson_get_str(val);
		} else if (yyjson_is_bool(val)) {
			value = yyjson_get_bool(val) ? "true" : "false";
		} else if (yyjson_is_num(val)) {
			value = std::to_string(yyjson_get_num(val));
		}
		out.emplace_back(yyjson_get_str(key), value);
	}
	yyjson_doc_free(doc);
	return out;
}

//! A type or an option key goes into the ATTACH as written: a plain identifier, nothing else
void RequireIdentifier(const string &value, const char *what) {
	for (auto c : value) {
		if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) {
			throw BinderException("acl cluster: %s \"%s\" is not a plain identifier", what, value);
		}
	}
}

string Quoted(const string &value) {
	return "'" + StringUtil::Replace(value, "'", "''") + "'";
}

string Ident(const string &value) {
	return "\"" + StringUtil::Replace(value, "\"", "\"\"") + "\"";
}

//! the names of (scope, name) items, a group's written `name (group g)`
vector<string> Names(const vector<std::pair<string, string>> &items) {
	vector<string> names;
	for (auto &item : items) {
		names.push_back(item.first.empty() ? item.second : item.second + " (group " + item.first + ")");
	}
	return names;
}

//! spec 096: whether a resource group has its own item of this kind and name (which overrides the cluster's)
bool GroupHasItem(CatalogBackend &catalog, const string &group, const char *kind, const string &name) {
	return catalog
	           .Query("SELECT 1 FROM " + catalog.Tbl("cluster_items") + " WHERE \"scope\" = " + Lit(group) +
	                  " AND \"kind\" = " + Lit(kind) + " AND lower(\"name\") = lower(" + Lit(name) + ")")
	           ->RowCount() > 0;
}

//! spec 096: the node's resource group ('' = none), as the deployment set it
string NodeGroupOf(DatabaseInstance &db) {
	Value value;
	if (db.TryGetCurrentSetting("acl_node_group", value) && !value.IsNull()) {
		return value.ToString();
	}
	return string();
}

//! spec 096: an item of another group than this node's is written, never applied here - the group's
//! nodes roll it out. True (with the answer's note) when the item is not this node's to apply now.
bool NotThisNodesScope(DatabaseInstance &db, const string &scope, PolicyStore::ClusterAnswer &answer,
                       const std::function<bool(const string &group)> &group_overrides = nullptr) {
	auto node_group = NodeGroupOf(db);
	if (scope.empty()) {
		// a cluster item this node's own group overrides is not this node's either: its group's item is
		// what acl_cluster_effective() says the node runs
		if (!node_group.empty() && group_overrides && group_overrides(node_group)) {
			answer.note =
			    "cluster item overridden by resource group " + node_group + "'s own on this node - not applied here";
			return true;
		}
		return false;
	}
	if (node_group == scope) {
		return false;
	}
	answer.note = "item of resource group " + scope + " - this node is " +
	              (node_group.empty() ? string("in no group") : "in group " + node_group) +
	              "; the group's nodes roll it out";
	return true;
}

//! A query on its own connection of the node: what the live apply and the node-side checks run on
unique_ptr<QueryResult> NodeQuery(DatabaseInstance &db, const string &sql) {
	Connection con(db);
	auto result = con.Query(sql);
	if (result->HasError()) {
		result->ThrowError("acl cluster: ");
	}
	return result;
}

bool NodeHasDatabase(DatabaseInstance &db, const string &alias) {
	auto result = NodeQuery(db, "SELECT 1 FROM duckdb_databases() WHERE database_name = " + Quoted(alias));
	return result->RowCount() > 0;
}

//! The ATTACH this item stands for, as the node runs it
string AttachStatement(const string &alias, const string &path, const string &type, const string &secret,
                       const vector<std::pair<string, string>> &options) {
	vector<string> parts;
	if (!type.empty()) {
		parts.push_back("TYPE " + type);
	}
	if (!secret.empty()) {
		parts.push_back("SECRET " + Ident(secret));
	}
	for (auto &option : options) {
		if (StringUtil::CIEquals(option.second, "true")) {
			parts.push_back(option.first);
		} else {
			parts.push_back(option.first + " " + Quoted(option.second));
		}
	}
	return "ATTACH " + Quoted(path) + " AS " + Ident(alias) +
	       (parts.empty() ? string() : " (" + StringUtil::Join(parts, ", ") + ")");
}

void RequireClusterCatalog(const unique_ptr<CatalogBackend> &catalog, const char *what) {
	if (!catalog) {
		throw BinderException("%s: the cluster profile lives in a policy catalog - run acl_use_db() first", what);
	}
	if (catalog->FunctionMode()) {
		throw BinderException("%s: the function-driver policy source has no cluster profile", what);
	}
}

using ReadFn = std::function<unique_ptr<QueryResult>(const string &)>;

void RequireScope(const ReadFn &read, CatalogBackend &catalog, const string &scope) {
	if (scope.empty()) {
		return;
	}
	auto exists = read("SELECT 1 FROM " + catalog.Tbl("resource_groups") + " WHERE \"group\" = " + Lit(scope));
	if (exists->RowCount() == 0) {
		throw BinderException("acl cluster: resource group \"%s\" does not exist - IN GROUP names a resource "
		                      "group (CREATE RESOURCE GROUP)",
		                      scope);
	}
}

//! The item's current spec, or "" when it is not in the profile
string CurrentSpec(const ReadFn &read, CatalogBackend &catalog, const string &scope, const string &kind,
                   const string &name) {
	auto row = read("SELECT \"spec\" FROM " + catalog.Tbl("cluster_items") + " WHERE \"scope\" = " + Lit(scope) +
	                " AND \"kind\" = " + Lit(kind) + " AND lower(\"name\") = lower(" + Lit(name) + ")");
	return row->RowCount() == 0 ? string() : row->Collection().GetValue(0, 0).ToString();
}

string UpsertItem(CatalogBackend &catalog, const string &scope, const string &kind, const string &name,
                  const string &spec, const string &item_class, const string &comment, bool keep_pos) {
	auto table = catalog.Tbl("cluster_items");
	auto where = " WHERE \"scope\" = " + Lit(scope) + " AND \"kind\" = " + Lit(kind) + " AND lower(\"name\") = lower(" +
	             Lit(name) + ")";
	string version =
	    "(SELECT CAST(\"value\" AS BIGINT) FROM " + catalog.Tbl("meta") + " WHERE \"key\" = 'config_version') + 1";
	if (keep_pos) {
		return "UPDATE " + table + " SET \"spec\" = " + Lit(spec) + ", \"class\" = " + Lit(item_class) +
		       ", \"version\" = " + version + ", \"comment\" = " + Lit(comment) + where;
	}
	return "INSERT INTO " + table + " VALUES (" + Lit(scope) + ", " + Lit(kind) + ", " + Lit(name) + ", " + Lit(spec) +
	       ", " + Lit(item_class) + ", " + version + ", (SELECT coalesce(max(\"pos\"), 0) + 1 FROM " + table + "), " +
	       Lit(comment) + ")";
}

string DeleteItem(CatalogBackend &catalog, const string &scope, const string &kind, const string &name) {
	return "DELETE FROM " + catalog.Tbl("cluster_items") + " WHERE \"scope\" = " + Lit(scope) +
	       " AND \"kind\" = " + Lit(kind) + " AND lower(\"name\") = lower(" + Lit(name) + ")";
}

string JsonField(const string &json, const char *field) {
	using namespace duckdb_yyjson; // NOLINT
	auto doc = yyjson_read(json.c_str(), json.size(), 0);
	if (!doc) {
		return string();
	}
	auto val = yyjson_obj_get(yyjson_doc_get_root(doc), field);
	string out = val && yyjson_is_str(val) ? string(yyjson_get_str(val)) : string();
	yyjson_doc_free(doc);
	return out;
}

} // namespace

PolicyStore::ClusterAnswer PolicyStore::ClusterExtension(const string &verb, const string &scope, const string &name,
                                                         const string &version, const string &repository,
                                                         const string &sha256, const string &comment) {
	RequireClusterCatalog(catalog, "acl_cluster_extension");
	auto db = instance.lock();
	if (!db) {
		throw BinderException("acl cluster: the instance is gone");
	}
	auto v = StringUtil::Lower(verb);
	if (v != "install" && v != "update" && v != "remove") {
		throw BinderException("acl_cluster_extension: the verb is install, update or remove, not \"%s\"", verb);
	}
	if (name.empty() || name.find_first_of("/\\:. '\"") != string::npos) {
		throw BinderException("acl cluster: \"%s\" is not an extension name - the profile installs an extension "
		                      "by its name from a trusted repository, never by a path or URL",
		                      name);
	}
	ClusterAnswer answer;
	answer.item_class = v == "install" ? "hot" : "restart";
	string repo = repository;
	if (v != "remove") {
		if (version.empty()) {
			throw BinderException("acl cluster: an extension in the profile names its VERSION - every node installs "
			                      "the same build");
		}
		// a trusted repository of the node's (duckdb 2.0 CREATE EXTENSION REPOSITORY): core and community
		// are never the profile's source, and neither is a path or URL
		auto repos = NodeQuery(*db, "SELECT repository_name FROM duckdb_extension_repositories() WHERE type = "
		                            "'USER_PROVIDED' ORDER BY 1");
		ResultRows rows(*repos);
		vector<string> names;
		for (idx_t i = 0; i < rows.Count(); i++) {
			names.push_back(rows.GetValue(0, i).ToString());
		}
		if (repo.empty()) {
			if (names.size() != 1) {
				throw BinderException("acl cluster: name the repository with FROM <name> - this node trusts %s",
				                      names.empty()
				                          ? string("no user-provided repository (CREATE EXTENSION REPOSITORY)")
				                          : StringUtil::Join(names, ", "));
			}
			repo = names[0];
		}
		bool known = false;
		for (auto &n : names) {
			known = known || StringUtil::CIEquals(n, repo);
		}
		if (!known) {
			throw BinderException("acl cluster: \"%s\" is not a trusted repository of this node - the profile installs "
			                      "only from a repository created with CREATE EXTENSION REPOSITORY",
			                      repo);
		}
	}
	answer.version = catalog->WriteWithReads(
	    [&](const ReadFn &read, vector<string> &statements) {
		    RequireScope(read, *catalog, scope);
		    auto current = CurrentSpec(read, *catalog, scope, "extension", name);
		    if (v == "install" && !current.empty()) {
			    throw BinderException("acl cluster: extension \"%s\" is already in the profile - UPDATE EXTENSION "
			                          "changes its version",
			                          name);
		    }
		    if (v != "install" && current.empty()) {
			    throw BinderException("acl cluster: extension \"%s\" is not in the profile", name);
		    }
		    if (v == "remove") {
			    // a source of the profile that needs it would leave a node unable to start
			    auto sources = read("SELECT \"name\", \"spec\" FROM " + catalog->Tbl("cluster_items") +
			                        " WHERE \"kind\" = 'source'");
			    ResultRows rows(*sources);
			    for (idx_t i = 0; i < rows.Count(); i++) {
				    auto type = JsonField(rows.GetValue(1, i).ToString(), "type");
				    if (StringUtil::CIEquals(ExtensionOfType(type), name)) {
					    throw BinderException("acl cluster: source \"%s\" needs extension \"%s\" - DETACH it first",
					                          rows.GetValue(0, i).ToString(), name);
				    }
			    }
			    statements.push_back(DeleteItem(*catalog, scope, "extension", name));
			    return;
		    }
		    auto spec = JsonObjectOf({{"version", version}, {"repository", repo}, {"sha256", sha256}});
		    statements.push_back(
		        UpsertItem(*catalog, scope, "extension", name, spec, answer.item_class, comment, !current.empty()));
	    },
	    "config_version",
	    [&](int64_t) {
		    if (NotThisNodesScope(*db, scope, answer, [&](const string &group) {
			        return GroupHasItem(*catalog, group, "extension", name);
		        })) {
			    return;
		    }
		    if (v != "install") {
			    answer.note = "restart class - a running process cannot unload or reload an extension; the node agent "
			                  "rolls it out through drain";
			    return;
		    }
		    NodeQuery(*db, "INSTALL " + Ident(name) + " FROM " + Ident(repo) + " VERSION " + Quoted(version));
		    if (!sha256.empty()) {
			    // an extension from a user-provided repository is installed apart, under
			    // <extension directory>/repositories/<repository>/ - and loaded only by LOAD ... FROM it
			    auto &fs = FileSystem::GetFileSystem(*db);
			    string file;
			    for (auto &dir : ExtensionHelper::GetExtensionDirectoryPath(*db, fs)) {
				    auto candidate = fs.JoinPath(fs.JoinPath(fs.JoinPath(dir, "repositories"), repo),
				                                 StringUtil::Lower(name) + ".duckdb_extension");
				    if (fs.FileExists(candidate)) {
					    file = candidate;
					    break;
				    }
			    }
			    string got;
			    if (!file.empty()) {
				    auto digest = NodeQuery(*db, "SELECT sha256(content) FROM read_blob(" + Quoted(file) + ")");
				    got = digest->RowCount() ? digest->Collection().GetValue(0, 0).ToString() : string();
			    }
			    if (got.empty() || !StringUtil::CIEquals(got, sha256)) {
				    // never leave a binary the profile refused where a later LOAD could find it
				    if (!file.empty()) {
					    fs.TryRemoveFile(file);
					    fs.TryRemoveFile(file + ".info");
				    }
				    throw BinderException("acl cluster: extension \"%s\" %s from \"%s\" has sha256 %s, the profile "
				                          "names %s - refused before LOAD, and the downloaded file removed",
				                          name, version, repo, got.empty() ? string("(not found)") : got, sha256);
			    }
		    }
		    NodeQuery(*db, "LOAD " + Ident(name) + " FROM " + Ident(repo));
		    answer.applied_here = true;
	    });
	return answer;
}

PolicyStore::ClusterAnswer PolicyStore::ClusterAttach(const string &scope, const string &alias, const string &path,
                                                      const string &type, const string &secret,
                                                      const string &options_json, const vector<string> &depends_on,
                                                      const string &comment) {
	RequireClusterCatalog(catalog, "acl_cluster_attach");
	auto db = instance.lock();
	if (!db) {
		throw BinderException("acl cluster: the instance is gone");
	}
	if (alias.empty()) {
		throw BinderException("acl cluster: ATTACH names its alias (AS <name>)");
	}
	if (StringUtil::CIEquals(alias, catalog->db_name)) {
		throw BinderException("acl cluster: \"%s\" is the policy catalog's database - the node attaches it from its "
		                      "local bootstrap, never from the profile it holds",
		                      alias);
	}
	RequireIdentifier(type, "the source's TYPE");
	LintPath(path);
	auto options = ParseOptions(options_json);
	for (auto &option : options) {
		RequireIdentifier(option.first, "an ATTACH option");
		LintKey(option.first, "the source's options");
	}
	if (secret.empty() && TYPES_NEEDING_SECRET.count(type)) {
		throw BinderException("acl cluster: a %s source connects with a credential - name the secret that holds it: "
		                      "(TYPE %s, SECRET <name>)",
		                      type, type);
	}
	auto spec = "{" + JsonQuote("type") + ": " + JsonQuote(type) + ", " + JsonQuote("path") + ": " + JsonQuote(path) +
	            ", " + JsonQuote("secret") + ": " + JsonQuote(secret) + ", " + JsonQuote("options") + ": " +
	            JsonObjectOf(options) + "}";
	ClusterAnswer answer;
	bool repoint = false;
	// a group's source named like a cluster's overrides it on the group's nodes: there it is a re-point
	bool overrides = false;
	answer.version = catalog->WriteWithReads(
	    [&](const ReadFn &read, vector<string> &statements) {
		    RequireScope(read, *catalog, scope);
		    auto current = CurrentSpec(read, *catalog, scope, "source", alias);
		    repoint = !current.empty();
		    overrides = !scope.empty() && !CurrentSpec(read, *catalog, "", "source", alias).empty();
		    answer.item_class = repoint || overrides ? "drain" : "hot";
		    // dependencies: sources of this scope or of the whole cluster, never a cycle
		    for (auto &dep : depends_on) {
			    auto exists = read("SELECT 1 FROM " + catalog->Tbl("cluster_items") +
			                       " WHERE \"kind\" = 'source' AND lower(\"name\") = lower(" + Lit(dep) +
			                       ") AND (\"scope\" = " + Lit(scope) + " OR \"scope\" = '')");
			    if (exists->RowCount() == 0) {
				    throw BinderException("acl cluster: DEPENDS ON \"%s\" - no such source in the profile%s", dep,
				                          scope.empty() ? string() : " of group " + scope + " or the cluster");
			    }
		    }
		    // cycle: from each dependency, can we reach `alias` again through the existing edges?
		    auto edges_result =
		        read("SELECT lower(\"name\"), lower(\"depends_on\") FROM " + catalog->Tbl("cluster_deps"));
		    ResultRows edges(*edges_result);
		    std::function<bool(const string &, case_insensitive_set_t &)> reaches = [&](const string &from,
		                                                                                case_insensitive_set_t &seen) {
			    if (StringUtil::CIEquals(from, alias)) {
				    return true;
			    }
			    if (!seen.insert(from).second) {
				    return false;
			    }
			    for (idx_t i = 0; i < edges.Count(); i++) {
				    if (StringUtil::CIEquals(edges.GetValue(0, i).ToString(), from) &&
				        reaches(edges.GetValue(1, i).ToString(), seen)) {
					    return true;
				    }
			    }
			    return false;
		    };
		    for (auto &dep : depends_on) {
			    case_insensitive_set_t seen;
			    if (reaches(dep, seen)) {
				    throw BinderException("acl cluster: DEPENDS ON \"%s\" would make a cycle through \"%s\"", dep,
				                          alias);
			    }
		    }
		    statements.push_back(
		        UpsertItem(*catalog, scope, "source", alias, spec, answer.item_class, comment, repoint));
		    statements.push_back("DELETE FROM " + catalog->Tbl("cluster_deps") + " WHERE \"scope\" = " + Lit(scope) +
		                         " AND lower(\"name\") = lower(" + Lit(alias) + ")");
		    for (auto &dep : depends_on) {
			    statements.push_back("INSERT INTO " + catalog->Tbl("cluster_deps") + " VALUES (" + Lit(scope) + ", " +
			                         Lit(alias) + ", " + Lit(dep) + ")");
		    }
	    },
	    "config_version",
	    [&](int64_t) {
		    if (NotThisNodesScope(*db, scope, answer, [&](const string &group) {
			        return GroupHasItem(*catalog, group, "source", alias);
		        })) {
			    return;
		    }
		    if (repoint || (overrides && NodeHasDatabase(*db, alias))) {
			    answer.note = string(overrides && !repoint ? "drain class - it overrides the cluster's source of that "
			                                                 "name on this group's nodes; "
			                                               : "drain class - ") +
			                  "re-pointing an attached source is DETACH + ATTACH under the same name; the node agent "
			                  "applies it through drain";
			    return;
		    }
		    if (NodeHasDatabase(*db, alias)) {
			    answer.note = "\"" + alias + "\" is already attached on this node - the profile now describes it";
			    return;
		    }
		    NodeQuery(*db, AttachStatement(alias, path, type, secret, options));
		    answer.applied_here = true;
	    });
	return answer;
}

PolicyStore::ClusterAnswer PolicyStore::ClusterDetach(const string &scope, const string &alias, bool cascade,
                                                      bool force) {
	RequireClusterCatalog(catalog, "acl_cluster_detach");
	auto db = instance.lock();
	if (!db) {
		throw BinderException("acl cluster: the instance is gone");
	}
	if (StringUtil::CIEquals(alias, catalog->db_name)) {
		throw BinderException("acl cluster: \"%s\" is the policy catalog's database - never the profile's", alias);
	}
	ClusterAnswer answer;
	answer.item_class = "hot";
	// what goes, each with its scope: the source and (CASCADE) whatever depends on it
	vector<std::pair<string, string>> removed {{scope, alias}};
	// group items whose name the cluster also has: on the group's nodes the cluster's comes back
	case_insensitive_set_t falls_back;
	// what of it is in effect on THIS node (the cluster's item, unless this node's group has its own)
	case_insensitive_set_t in_effect;
	auto node_group = NodeGroupOf(*db);
	auto key = [](const std::pair<string, string> &item) {
		return item.first + "\x1f" + item.second;
	};
	answer.version = catalog->WriteWithReads(
	    [&](const ReadFn &read, vector<string> &statements) {
		    RequireScope(read, *catalog, scope);
		    if (CurrentSpec(read, *catalog, scope, "source", alias).empty()) {
			    throw BinderException("acl cluster: source \"%s\" is not in the profile", alias);
		    }
		    // who depends on it (transitively, for CASCADE). An edge is of its dependent's scope and names
		    // a source of that scope, else the cluster's: a group edge depends on a cluster source only
		    // while the group has none of that name, and a cluster edge never on a group's source.
		    auto edges_result = read("SELECT \"scope\", \"name\", \"depends_on\" FROM " + catalog->Tbl("cluster_deps"));
		    ResultRows edges(*edges_result);
		    auto group_sources_result = read("SELECT \"scope\", lower(\"name\") FROM " + catalog->Tbl("cluster_items") +
		                                     " WHERE \"kind\" = 'source' AND \"scope\" <> ''");
		    ResultRows group_sources(*group_sources_result);
		    auto group_has = [&](const string &group, const string &name) {
			    for (idx_t i = 0; i < group_sources.Count(); i++) {
				    if (group_sources.GetValue(0, i).ToString() == group &&
				        StringUtil::CIEquals(group_sources.GetValue(1, i).ToString(), name)) {
					    return true;
				    }
			    }
			    return false;
		    };
		    auto depends_on_removed = [&](const string &edge_scope, const string &dep,
		                                  const std::pair<string, string> &r) {
			    if (!StringUtil::CIEquals(dep, r.second)) {
				    return false;
			    }
			    if (edge_scope == r.first) {
				    return true;
			    }
			    return r.first.empty() && !group_has(edge_scope, dep);
		    };
		    auto removing = [&](const string &item_scope, const string &name) {
			    return std::find_if(removed.begin(), removed.end(), [&](const std::pair<string, string> &r) {
				           return r.first == item_scope && StringUtil::CIEquals(r.second, name);
			           }) != removed.end();
		    };
		    // a group's source whose name the cluster's keeps: its dependents fall back to the cluster's
		    auto keeps_fallback = [&](const std::pair<string, string> &r) {
			    return !r.first.empty() && !removing("", r.second) &&
			           !CurrentSpec(read, *catalog, "", "source", r.second).empty();
		    };
		    auto walk_dependents = [&](idx_t at) {
			    auto of = removed[at]; // a copy: emplace_back below may move the vector
			    if (keeps_fallback(of)) {
				    return;
			    }
			    for (idx_t i = 0; i < edges.Count(); i++) {
				    auto edge_scope = edges.GetValue(0, i).ToString();
				    auto dependent = edges.GetValue(1, i).ToString();
				    if (!depends_on_removed(edge_scope, edges.GetValue(2, i).ToString(), of) ||
				        removing(edge_scope, dependent)) {
					    continue;
				    }
				    if (!cascade) {
					    throw BinderException("acl cluster: source \"%s\"%s DEPENDS ON \"%s\" - detach it first, or "
					                          "DETACH %s CASCADE",
					                          dependent, edge_scope.empty() ? string() : " of group " + edge_scope,
					                          of.second, alias);
				    }
				    removed.emplace_back(edge_scope, dependent);
			    }
		    };
		    // to a fixpoint: a group source skipped because the cluster's of its name stays loses that
		    // fallback when the walk reaches the cluster's later - then its dependents go too
		    idx_t walked = 0;
		    do {
			    walked = removed.size();
			    for (idx_t at = 0; at < removed.size(); at++) {
				    walk_dependents(at);
			    }
		    } while (removed.size() != walked);
		    for (auto &r : removed) {
			    if (!r.first.empty() && !removing("", r.second) &&
			        !CurrentSpec(read, *catalog, "", "source", r.second).empty()) {
				    falls_back.insert(key(r));
			    }
			    bool here = r.first.empty() ? node_group.empty() || !group_has(node_group, r.second) ||
			                                      removing(node_group, r.second)
			                                : r.first == node_group;
			    if (here) {
				    in_effect.insert(key(r));
			    }
		    }
		    // the policy reads through it: the policy goes first (design/017 §3.2a)
		    vector<string> readers;
		    for (auto &r : removed) {
			    if (falls_back.count(key(r))) {
				    continue; // the cluster's source of that name stays: the policy still reads through it
			    }
			    auto &source = r.second;
			    // a physical name as stored: bare (src.main.t) or quoted ("src".main.t)
			    auto lower = StringUtil::Lower(source);
			    auto through = [&](const char *column) {
				    auto c = string("lower(\"") + column + "\")";
				    return "(" + c + " LIKE " + Lit(lower + ".%") + " OR " + c + " LIKE " + Lit("\"" + lower + "\".%") +
				           " OR " + c + " = " + Lit(lower) + " OR " + c + " = " + Lit("\"" + lower + "\"") + ")";
			    };
			    auto rel = read("SELECT \"vcat\" || '.' || \"vname\" FROM " + catalog->Tbl("relations") + " WHERE " +
			                    through("phys"));
			    auto sch = read("SELECT \"vcat\" || '.' || \"path\" FROM " + catalog->Tbl("schemas") + " WHERE " +
			                    through("phys_path"));
			    auto fun = read("SELECT \"vcat\" || '.' || \"vname\" FROM " + catalog->Tbl("functions") + " WHERE " +
			                    through("target"));
			    for (auto *result : {rel.get(), sch.get(), fun.get()}) {
				    ResultRows rows(*result);
				    for (idx_t i = 0; i < rows.Count(); i++) {
					    readers.push_back(rows.GetValue(0, i).ToString());
				    }
			    }
		    }
		    if (!readers.empty() && !force) {
			    throw BinderException("acl cluster: the policy reads through %s: %s - remove those first, or DETACH %s "
			                          "FORCE (acl_check_catalog then reports them as source_missing)",
			                          StringUtil::Join(Names(removed), ", "), StringUtil::Join(readers, ", "), alias);
		    }
		    for (auto &r : removed) {
			    statements.push_back(DeleteItem(*catalog, r.first, "source", r.second));
			    statements.push_back("DELETE FROM " + catalog->Tbl("cluster_deps") + " WHERE \"scope\" = " +
			                         Lit(r.first) + " AND lower(\"name\") = lower(" + Lit(r.second) + ")");
		    }
	    },
	    "config_version",
	    [&](int64_t) {
		    // dependents first; only what is in effect on this node, and never a name the cluster's item
		    // takes back on it (a re-point, the agent's through drain). The source itself may be another
		    // group's, or a cluster item this node's group overrides, while what depends on it is here.
		    vector<string> busy;
		    vector<string> repointed;
		    for (auto it = removed.rbegin(); it != removed.rend(); ++it) {
			    if (!in_effect.count(key(*it)) || !NodeHasDatabase(*db, it->second)) {
				    continue;
			    }
			    if (falls_back.count(key(*it))) {
				    repointed.push_back(it->second);
				    continue;
			    }
			    Connection con(*db);
			    auto result = con.Query("DETACH " + Ident(it->second));
			    if (result->HasError()) {
				    busy.push_back(it->second);
			    }
		    }
		    bool head_here = in_effect.count(key(removed[0])) > 0;
		    if (!head_here) {
			    NotThisNodesScope(*db, scope, answer, [&](const string &) { return true; });
		    }
		    answer.applied_here = head_here && busy.empty() && repointed.empty();
		    if (removed.size() > 1) {
			    auto names = Names(removed);
			    answer.note += string(answer.note.empty() ? "" : "; ") + "detached with it: " +
			                   StringUtil::Join(vector<string>(names.begin() + 1, names.end()), ", ");
		    }
		    if (!repointed.empty()) {
			    answer.item_class = "drain";
			    answer.note += string(answer.note.empty() ? "" : "; ") +
			                   "the cluster's source of that name is in "
			                   "effect again on this node: " +
			                   StringUtil::Join(repointed, ", ") + " - the node agent re-points it through drain";
		    }
		    if (!busy.empty()) {
			    answer.item_class = "drain";
			    answer.note += string(answer.note.empty() ? "" : "; ") +
			                   "in use on this node: " + StringUtil::Join(busy, ", ") +
			                   " - the node agent detaches it through drain";
		    }
	    });
	return answer;
}

PolicyStore::ClusterAnswer PolicyStore::ClusterSetting(const string &verb, const string &scope, const string &name,
                                                       const string &value) {
	RequireClusterCatalog(catalog, "acl_cluster_setting");
	auto db = instance.lock();
	if (!db) {
		throw BinderException("acl cluster: the instance is gone");
	}
	auto v = StringUtil::Lower(verb);
	if (v != "set" && v != "reset") {
		throw BinderException("acl_cluster_setting: the verb is set or reset, not \"%s\"", verb);
	}
	if (HARDENING_SETTINGS.count(name)) {
		throw BinderException("acl cluster: \"%s\" is the node's hardening, fixed by its bootstrap - never a "
		                      "cluster profile item",
		                      name);
	}
	if (StringUtil::CIEquals(name, "acl_node_group")) {
		// spec 096: which group a node is in is its deployment's, never the policy's - a profile item
		// would let a catalog write move nodes between groups
		throw BinderException("acl cluster: \"acl_node_group\" is the node's own (its deployment sets it) - never a "
		                      "cluster profile item");
	}
	LintKey(name, "a setting's name");
	auto known = NodeQuery(*db, "SELECT scope FROM duckdb_settings() WHERE lower(name) = lower(" + Quoted(name) + ")");
	if (known->RowCount() == 0) {
		throw BinderException("acl cluster: \"%s\" is not a setting of this node", name);
	}
	if (!StringUtil::CIEquals(known->Collection().GetValue(0, 0).ToString(), "GLOBAL")) {
		throw BinderException("acl cluster: \"%s\" is not a GLOBAL setting - the profile carries the node's settings, "
		                      "not a session's",
		                      name);
	}
	ClusterAnswer answer;
	answer.item_class = "restart";
	answer.version = catalog->WriteWithReads(
	    [&](const ReadFn &read, vector<string> &statements) {
		    RequireScope(read, *catalog, scope);
		    auto current = CurrentSpec(read, *catalog, scope, "setting", name);
		    if (v == "reset") {
			    if (current.empty()) {
				    throw BinderException("acl cluster: setting \"%s\" is not in the profile", name);
			    }
			    statements.push_back(DeleteItem(*catalog, scope, "setting", name));
			    return;
		    }
		    statements.push_back(UpsertItem(*catalog, scope, "setting", StringUtil::Lower(name),
		                                    JsonObjectOf({{"value", value}}), answer.item_class, "", !current.empty()));
	    },
	    "config_version",
	    [&](int64_t) {
		    if (NotThisNodesScope(*db, scope, answer, [&](const string &group) {
			        return GroupHasItem(*catalog, group, "setting", StringUtil::Lower(name));
		        })) {
			    return;
		    }
		    answer.note = "restart class - the node's configuration is locked after its bootstrap; the node agent "
		                  "rolls the change out through drain";
	    });
	return answer;
}

string PolicyStore::NodeGroup() {
	auto db = instance.lock();
	Value value;
	if (db && db->TryGetCurrentSetting("acl_node_group", value) && !value.IsNull()) {
		return value.ToString();
	}
	return string();
}

uint64_t PolicyStore::CatalogLocalWrites() {
	return catalog ? catalog->local_writes.load() : 0;
}

bool PolicyStore::NodeGroupKnown() {
	// the catalog judged like any read of it (spec 094): one this build may not read throws, and the
	// report says neither the group nor the target
	if (catalog && !catalog->FunctionMode()) {
		catalog->EnsureFresh();
	}
	auto group = NodeGroup();
	if (group.empty()) {
		return true;
	}
	if (!catalog || catalog->FunctionMode()) {
		return false;
	}
	return catalog->Query("SELECT 1 FROM " + catalog->Tbl("resource_groups") + " WHERE \"group\" = " + Lit(group))
	           ->RowCount() > 0;
}

vector<PolicyStore::ClusterItem> PolicyStore::ClusterEffective() {
	// the cluster's items, then this node's group's over them - one row per kind and name, in the
	// profile's order (settings, extensions, sources), each with the scope it came from
	auto group = NodeGroup();
	vector<ClusterItem> out;
	case_insensitive_map_t<idx_t> at;
	for (auto &item : ClusterItems(string())) {
		if (!item.scope.empty() && item.scope != group) {
			continue;
		}
		auto key = item.kind + "\x1f" + item.name;
		auto found = at.find(key);
		if (found == at.end()) {
			at[key] = out.size();
			out.push_back(item);
		} else if (!item.scope.empty()) {
			out[found->second] = item; // the group's item overrides the cluster's
		}
	}
	// the profile's order - settings, extensions, sources - whichever scope each came from: a group's own
	// extension must come before the cluster's source that loads through it
	auto rank = [](const string &kind) {
		return kind == "setting" ? 0 : kind == "extension" ? 1 : 2;
	};
	std::stable_sort(out.begin(), out.end(),
	                 [&](const ClusterItem &a, const ClusterItem &b) { return rank(a.kind) < rank(b.kind); });
	return out;
}

int64_t PolicyStore::ClusterVersion() {
	RequireClusterCatalog(catalog, "acl_cluster_version");
	auto result = catalog->Query("SELECT CAST(\"value\" AS BIGINT) FROM " + catalog->Tbl("meta") +
	                             " WHERE \"key\" = 'config_version'");
	return result->RowCount() ? result->Collection().GetValue(0, 0).GetValue<int64_t>() : 0;
}

vector<PolicyStore::ClusterItem> PolicyStore::ClusterItems(const string &scope) {
	RequireClusterCatalog(catalog, "acl_cluster_items");
	auto where = scope.empty() ? string() : " WHERE i.\"scope\" = " + Lit(scope);
	auto result = catalog->Query(
	    "SELECT i.\"scope\", i.\"kind\", i.\"name\", i.\"spec\", i.\"class\", i.\"version\", i.\"comment\", "
	    "(SELECT string_agg(d.\"depends_on\", ',' ORDER BY d.\"depends_on\") FROM " +
	    catalog->Tbl("cluster_deps") +
	    " d WHERE d.\"scope\" = i.\"scope\" AND lower(d.\"name\") = lower(i.\"name\")) " + "FROM " +
	    catalog->Tbl("cluster_items") + " i" + where +
	    " ORDER BY i.\"scope\", CASE i.\"kind\" WHEN 'setting' THEN 0 WHEN 'extension' THEN 1 ELSE 2 END, i.\"pos\"");
	ResultRows rows(*result);
	vector<ClusterItem> out;
	for (idx_t i = 0; i < rows.Count(); i++) {
		ClusterItem item;
		item.scope = rows.GetValue(0, i).ToString();
		item.kind = rows.GetValue(1, i).ToString();
		item.name = rows.GetValue(2, i).ToString();
		item.spec = rows.GetValue(3, i).ToString();
		item.item_class = rows.GetValue(4, i).ToString();
		item.version = rows.GetValue(5, i).GetValue<int64_t>();
		auto comment = rows.GetValue(6, i);
		item.comment = comment.IsNull() ? string() : comment.ToString();
		auto deps = rows.GetValue(7, i);
		if (!deps.IsNull()) {
			item.depends_on = StringUtil::Split(deps.ToString(), ',');
		}
		out.push_back(std::move(item));
	}
	return out;
}

//===--------------------------------------------------------------------===//
// The SQL surface
//===--------------------------------------------------------------------===//

namespace {

LogicalType AnswerType() {
	child_list_t<LogicalType> children {{"version", LogicalType::BIGINT},
	                                    {"class", LogicalType::VARCHAR},
	                                    {"applied_here", LogicalType::BOOLEAN},
	                                    {"note", LogicalType::VARCHAR}};
	return LogicalType::STRUCT(std::move(children));
}

Value AnswerValue(const PolicyStore::ClusterAnswer &answer) {
	child_list_t<Value> children {{"version", Value::BIGINT(answer.version)},
	                              {"class", Value(answer.item_class)},
	                              {"applied_here", Value::BOOLEAN(answer.applied_here)},
	                              {"note", answer.note.empty() ? Value(LogicalType::VARCHAR) : Value(answer.note)}};
	return Value::STRUCT(std::move(children));
}

string Arg(DataChunk &args, idx_t column, idx_t row) {
	if (column >= args.ColumnCount()) {
		return string();
	}
	auto value = args.data[column].GetValue(row);
	return value.IsNull() ? string() : value.ToString();
}

template <class FN>
void EachRow(DataChunk &args, Vector &result, FN &&fn) {
	for (idx_t row = 0; row < args.size(); row++) {
		result.SetValue(row, AnswerValue(fn(row)));
	}
}

//! acl_cluster_extension(verb, scope, name, version, repository, sha256, comment)
void ClusterExtensionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	EachRow(args, result, [&](idx_t row) {
		return StoreOf(state).ClusterExtension(Arg(args, 0, row), Arg(args, 1, row), Arg(args, 2, row),
		                                       Arg(args, 3, row), Arg(args, 4, row), Arg(args, 5, row),
		                                       Arg(args, 6, row));
	});
}

//! acl_cluster_attach(scope, alias, path, type, secret, options_json, depends_on_csv, comment)
void ClusterAttachFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	EachRow(args, result, [&](idx_t row) {
		vector<string> deps;
		for (auto &dep : StringUtil::Split(Arg(args, 6, row), ',')) {
			auto d = dep;
			StringUtil::Trim(d);
			if (!d.empty()) {
				deps.push_back(d);
			}
		}
		return StoreOf(state).ClusterAttach(Arg(args, 0, row), Arg(args, 1, row), Arg(args, 2, row), Arg(args, 3, row),
		                                    Arg(args, 4, row), Arg(args, 5, row), deps, Arg(args, 7, row));
	});
}

//! acl_cluster_detach(scope, alias, cascade, force)
void ClusterDetachFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	EachRow(args, result, [&](idx_t row) {
		return StoreOf(state).ClusterDetach(Arg(args, 0, row), Arg(args, 1, row),
		                                    StringUtil::CIEquals(Arg(args, 2, row), "true"),
		                                    StringUtil::CIEquals(Arg(args, 3, row), "true"));
	});
}

//! acl_cluster_setting(verb, scope, name, value)
void ClusterSettingFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	EachRow(args, result, [&](idx_t row) {
		return StoreOf(state).ClusterSetting(Arg(args, 0, row), Arg(args, 1, row), Arg(args, 2, row),
		                                     Arg(args, 3, row));
	});
}

void ClusterVersionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.Reference(Value::BIGINT(StoreOf(state).ClusterVersion()), count_t(args.size()));
}

struct ClusterInfo : public TableFunctionInfo {
	explicit ClusterInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

struct ItemsBind : public TableFunctionData {
	shared_ptr<PolicyStore> store;
	string scope;
};

struct ItemsState : public GlobalTableFunctionState {
	vector<PolicyStore::ClusterItem> rows;
	idx_t next = 0;
};

unique_ptr<FunctionData> ItemsBindFn(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                     vector<Identifier> &names) {
	for (auto name : {"scope", "kind", "name", "spec", "class", "version", "depends_on", "comment"}) {
		names.push_back(Identifier(name));
	}
	types = {LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::BIGINT,
	         LogicalType::LIST(LogicalType::VARCHAR),
	         LogicalType::VARCHAR};
	auto bind = make_uniq<ItemsBind>();
	bind->store = input.info->Cast<ClusterInfo>().store;
	if (!input.inputs.empty() && !input.inputs[0].IsNull()) {
		bind->scope = input.inputs[0].ToString();
	}
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> ItemsInit(ClientContext &, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<ItemsBind>();
	auto state = make_uniq<ItemsState>();
	state->rows = bind.store->ClusterItems(bind.scope);
	return std::move(state);
}

void ItemsScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<ItemsState>();
	idx_t count = 0;
	while (state.next < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.next++];
		output.data[0].SetValue(count, Value(row.scope));
		output.data[1].SetValue(count, Value(row.kind));
		output.data[2].SetValue(count, Value(row.name));
		output.data[3].SetValue(count, Value(row.spec));
		output.data[4].SetValue(count, Value(row.item_class));
		output.data[5].SetValue(count, Value::BIGINT(row.version));
		vector<Value> deps;
		for (auto &d : row.depends_on) {
			deps.emplace_back(d);
		}
		output.data[6].SetValue(count, Value::LIST(LogicalType::VARCHAR, std::move(deps)));
		output.data[7].SetValue(count, row.comment.empty() ? Value(LogicalType::VARCHAR) : Value(row.comment));
		count++;
	}
	output.SetChildCardinality(count);
}

unique_ptr<FunctionData> EffectiveBindFn(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &types, vector<Identifier> &names) {
	return ItemsBindFn(context, input, types, names);
}

unique_ptr<GlobalTableFunctionState> EffectiveInit(ClientContext &, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<ItemsBind>();
	auto state = make_uniq<ItemsState>();
	state->rows = bind.store->ClusterEffective();
	return std::move(state);
}

//! acl_cluster_applied(version) (spec 096): the node agent says which profile version this node has
//! converged to - acl does not converge a node, it reports what the agent says (the load report's
//! config.applied, and readiness when it equals the target)
void ClusterAppliedFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &store = StoreOf(state);
	for (idx_t row = 0; row < args.size(); row++) {
		// a NULL version never arrives here: the default null handling answers NULL and records nothing
		auto version = args.data[0].GetValue(row).GetValue<int64_t>();
		auto target = store.ClusterVersion();
		if (version < 0 || version > target) {
			throw BinderException("acl_cluster_applied: version %lld is not one of the profile's (0 .. %lld)", version,
			                      target);
		}
		store.cluster_applied.store(version);
		result.SetValue(row, Value::BIGINT(version));
	}
}

} // namespace

void RegisterAclCluster(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	const LogicalType &v = LogicalType::VARCHAR;
	auto scalar = [&](const char *name, vector<LogicalType> arguments, const scalar_function_t &fn,
	                  const LogicalType &returns) {
		ScalarFunction function(Identifier(name), std::move(arguments), returns, fn);
		MarkAclScalar(function, store);
		loader.RegisterFunction(function);
	};
	scalar("acl_cluster_extension", {v, v, v, v, v, v, v}, ClusterExtensionFunc, AnswerType());
	scalar("acl_cluster_attach", {v, v, v, v, v, v, v, v}, ClusterAttachFunc, AnswerType());
	scalar("acl_cluster_detach", {v, v, v, v}, ClusterDetachFunc, AnswerType());
	scalar("acl_cluster_setting", {v, v, v, v}, ClusterSettingFunc, AnswerType());
	scalar("acl_cluster_version", {}, ClusterVersionFunc, LogicalType::BIGINT);

	auto info = make_shared_ptr<ClusterInfo>(store);
	TableFunctionSet items(Identifier("acl_cluster_items"));
	for (auto &arguments : {vector<LogicalType> {}, vector<LogicalType> {v}}) {
		TableFunction function(Identifier("acl_cluster_items"), arguments, ItemsScan, ItemsBindFn, ItemsInit);
		function.function_info = info;
		items.AddFunction(function);
	}
	loader.RegisterFunction(items);
	// spec 096: what applies to THIS node, and the version its agent reports applied
	TableFunction effective(Identifier("acl_cluster_effective"), {}, ItemsScan, EffectiveBindFn, EffectiveInit);
	effective.function_info = info;
	loader.RegisterFunction(effective);
	scalar("acl_cluster_applied", {LogicalType::BIGINT}, ClusterAppliedFunc, LogicalType::BIGINT);
}

} // namespace acl
} // namespace duckdb
