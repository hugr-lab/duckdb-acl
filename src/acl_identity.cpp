// The identity model's decisions (spec 095): stored shapes, client acceptance, routing by
// specificity, roles and attributes, and the checks a write must pass. No store and no IO here - the
// callers hand in what only they can read (secrets, which roles exist and which are privileged).

#include "acl_identity.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "yyjson.hpp"

#include <set>

namespace duckdb {
namespace acl {
namespace {

using duckdb_yyjson::yyjson_doc;
using duckdb_yyjson::yyjson_val;

struct Json {
	explicit Json(const string &text) : doc(duckdb_yyjson::yyjson_read(text.c_str(), text.size(), 0)) {
	}
	~Json() {
		if (doc) {
			duckdb_yyjson::yyjson_doc_free(doc);
		}
	}
	Json(const Json &) = delete;
	Json &operator=(const Json &) = delete;
	yyjson_val *Root() const {
		return doc ? duckdb_yyjson::yyjson_doc_get_root(doc) : nullptr;
	}
	yyjson_doc *doc;
};

string Quote(const string &value) {
	string out = "\"";
	for (auto c : value) {
		switch (c) {
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		case '\n':
			out += "\\n";
			break;
		case '\r':
			out += "\\r";
			break;
		case '\t':
			out += "\\t";
			break;
		default:
			if (static_cast<unsigned char>(c) < 0x20) {
				char buffer[8];
				snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
				out += buffer;
			} else {
				out += c;
			}
		}
	}
	return out + "\"";
}

string Text(yyjson_val *value) {
	if (!value) {
		return string();
	}
	if (duckdb_yyjson::yyjson_is_str(value)) {
		return string(duckdb_yyjson::yyjson_get_str(value), duckdb_yyjson::yyjson_get_len(value));
	}
	if (duckdb_yyjson::yyjson_is_int(value)) {
		return std::to_string(duckdb_yyjson::yyjson_get_sint(value));
	}
	if (duckdb_yyjson::yyjson_is_real(value)) {
		return std::to_string(duckdb_yyjson::yyjson_get_real(value));
	}
	if (duckdb_yyjson::yyjson_is_bool(value)) {
		return duckdb_yyjson::yyjson_get_bool(value) ? "true" : "false";
	}
	return string();
}

[[noreturn]] void Bad(const string &what) {
	throw BinderException("acl admin: %s", what);
}

vector<string> StringArray(yyjson_val *value, const char *key) {
	vector<string> out;
	if (!value || duckdb_yyjson::yyjson_is_null(value)) {
		return out;
	}
	if (duckdb_yyjson::yyjson_is_str(value)) {
		// a single value where a list goes: the list of one
		out.push_back(Text(value));
		return out;
	}
	if (!duckdb_yyjson::yyjson_is_arr(value)) {
		Bad(string("\"") + key + "\" must be a list of strings");
	}
	duckdb_yyjson::yyjson_arr_iter iter;
	duckdb_yyjson::yyjson_arr_iter_init(value, &iter);
	while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
		if (!duckdb_yyjson::yyjson_is_str(item)) {
			Bad(string("\"") + key + "\" must be a list of strings");
		}
		auto text = Text(item);
		if (!text.empty()) {
			out.push_back(text);
		}
	}
	return out;
}

string StringOf(yyjson_val *value, const char *key) {
	if (!value || duckdb_yyjson::yyjson_is_null(value)) {
		return string();
	}
	if (!duckdb_yyjson::yyjson_is_str(value)) {
		Bad(string("\"") + key + "\" must be a string");
	}
	return Text(value);
}

const char *OpName(ClaimCondition::Op op) {
	switch (op) {
	case ClaimCondition::Op::EQUALS:
		return "eq";
	case ClaimCondition::Op::ONE_OF:
		return "in";
	case ClaimCondition::Op::CONTAINS:
		return "contains";
	default:
		return "like";
	}
}

ClaimCondition::Op ParseOp(const string &name) {
	if (StringUtil::CIEquals(name, "eq") || name == "=") {
		return ClaimCondition::Op::EQUALS;
	}
	if (StringUtil::CIEquals(name, "in")) {
		return ClaimCondition::Op::ONE_OF;
	}
	if (StringUtil::CIEquals(name, "contains")) {
		return ClaimCondition::Op::CONTAINS;
	}
	if (StringUtil::CIEquals(name, "like")) {
		return ClaimCondition::Op::LIKE;
	}
	Bad("a REQUIRE condition's operator is one of =, IN, contains (v IN path) or LIKE - got \"" + name + "\"");
}

vector<ClaimCondition> ConditionsOf(yyjson_val *value) {
	vector<ClaimCondition> out;
	if (!value || duckdb_yyjson::yyjson_is_null(value)) {
		return out;
	}
	if (!duckdb_yyjson::yyjson_is_arr(value)) {
		Bad("\"require\" must be a list of conditions");
	}
	duckdb_yyjson::yyjson_arr_iter iter;
	duckdb_yyjson::yyjson_arr_iter_init(value, &iter);
	while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
		if (!duckdb_yyjson::yyjson_is_obj(item)) {
			Bad("a REQUIRE condition is {\"path\", \"op\", \"values\"}");
		}
		ClaimCondition condition;
		condition.path = StringOf(duckdb_yyjson::yyjson_obj_get(item, "path"), "path");
		condition.op = ParseOp(StringOf(duckdb_yyjson::yyjson_obj_get(item, "op"), "op"));
		condition.values = StringArray(duckdb_yyjson::yyjson_obj_get(item, "values"), "values");
		if (condition.path.empty() || condition.values.empty()) {
			Bad("a REQUIRE condition names a claim path and at least one value");
		}
		if (condition.op != ClaimCondition::Op::ONE_OF && condition.values.size() != 1) {
			Bad("only IN compares a claim against a list - =, contains and LIKE take one value");
		}
		out.push_back(std::move(condition));
	}
	return out;
}

vector<AttributeDef> AttributesOf(yyjson_val *value) {
	vector<AttributeDef> out;
	if (!value || duckdb_yyjson::yyjson_is_null(value)) {
		return out;
	}
	if (duckdb_yyjson::yyjson_is_obj(value)) {
		// the v16 claim map, {"<jwt path>": "<name>"} - what a migrated catalog carries and CLAIM MAP writes
		duckdb_yyjson::yyjson_obj_iter iter;
		duckdb_yyjson::yyjson_obj_iter_init(value, &iter);
		while (auto key = duckdb_yyjson::yyjson_obj_iter_next(&iter)) {
			AttributeDef attribute;
			attribute.paths.push_back(Text(key));
			attribute.name = Text(duckdb_yyjson::yyjson_obj_iter_get_val(key));
			if (attribute.name.empty() || attribute.paths[0].empty()) {
				Bad("a claim map pairs a JWT path with an attribute name");
			}
			out.push_back(std::move(attribute));
		}
		return out;
	}
	if (!duckdb_yyjson::yyjson_is_arr(value)) {
		Bad("\"attributes\" must be a list of {\"name\", \"paths\" | \"constant\"}");
	}
	duckdb_yyjson::yyjson_arr_iter iter;
	duckdb_yyjson::yyjson_arr_iter_init(value, &iter);
	while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
		if (!duckdb_yyjson::yyjson_is_obj(item)) {
			Bad("an attribute is {\"name\", \"paths\" | \"constant\"}");
		}
		AttributeDef attribute;
		attribute.name = StringOf(duckdb_yyjson::yyjson_obj_get(item, "name"), "name");
		auto constant = duckdb_yyjson::yyjson_obj_get(item, "constant");
		if (constant && !duckdb_yyjson::yyjson_is_null(constant)) {
			attribute.is_constant = true;
			attribute.constant = StringOf(constant, "constant");
		} else {
			attribute.paths = StringArray(duckdb_yyjson::yyjson_obj_get(item, "paths"), "paths");
		}
		if (attribute.name.empty() || (!attribute.is_constant && attribute.paths.empty())) {
			Bad("an attribute has a name and either the claim paths it is read from or a CONSTANT");
		}
		out.push_back(std::move(attribute));
	}
	return out;
}

//! Look a path up as one key first (a claim named like a URL), then walk it as a dot path
yyjson_val *ClaimAt(yyjson_val *root, const string &path) {
	if (!root || !duckdb_yyjson::yyjson_is_obj(root)) {
		return nullptr;
	}
	if (auto whole = duckdb_yyjson::yyjson_obj_getn(root, path.c_str(), path.size())) {
		return whole;
	}
	auto value = root;
	for (auto &part : StringUtil::Split(path, '.')) {
		if (!value || !duckdb_yyjson::yyjson_is_obj(value)) {
			return nullptr;
		}
		value = duckdb_yyjson::yyjson_obj_getn(value, part.c_str(), part.size());
	}
	return value;
}

vector<string> ValuesAt(yyjson_val *value) {
	vector<string> out;
	if (!value) {
		return out;
	}
	if (duckdb_yyjson::yyjson_is_arr(value)) {
		duckdb_yyjson::yyjson_arr_iter iter;
		duckdb_yyjson::yyjson_arr_iter_init(value, &iter);
		while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
			auto text = Text(item);
			if (!text.empty()) {
				out.push_back(text);
			}
		}
		return out;
	}
	auto text = Text(value);
	if (!text.empty()) {
		out.push_back(text);
	}
	return out;
}

bool Intersects(const vector<string> &a, const vector<string> &b) {
	for (auto &x : a) {
		for (auto &y : b) {
			if (x == y) {
				return true;
			}
		}
	}
	return false;
}

bool Contains(const vector<string> &values, const string &value) {
	for (auto &v : values) {
		if (v == value) {
			return true;
		}
	}
	return false;
}

yyjson_val *RootOf(void *doc) {
	return doc ? duckdb_yyjson::yyjson_doc_get_root(static_cast<yyjson_doc *>(doc)) : nullptr;
}

} // namespace

optional_ptr<const IdentityIssuer> IdentityModel::Issuer(const string &name) const {
	for (auto &issuer : issuers) {
		if (StringUtil::CIEquals(issuer.name, name)) {
			return &issuer;
		}
	}
	return nullptr;
}

optional_ptr<const IdentityClient> IdentityModel::Client(const string &name) const {
	for (auto &client : clients) {
		if (StringUtil::CIEquals(client.name, name)) {
			return &client;
		}
	}
	return nullptr;
}

bool IsKnownFlow(const string &flow) {
	return flow == "password" || flow == "authcode" || flow == "device" || flow == "client_credentials";
}

bool IsDriverFlow(const string &flow) {
	return flow == "authcode" || flow == "device";
}

string DiscoveryLocation(const string &url) {
	return url + (StringUtil::EndsWith(url, "/") ? "" : "/") + ".well-known/openid-configuration";
}

vector<string> ParseStoredList(const string &text) {
	auto trimmed = text;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		return {};
	}
	if (trimmed[0] == '[') {
		Json json(trimmed);
		if (!json.Root()) {
			throw BinderException("acl: a stored list is not valid JSON: %s", trimmed);
		}
		return StringArray(json.Root(), "list");
	}
	vector<string> out;
	for (auto &item : StringUtil::Split(trimmed, ',')) {
		StringUtil::Trim(item);
		if (!item.empty()) {
			out.push_back(item);
		}
	}
	return out;
}

string StoredList(const vector<string> &values) {
	if (values.empty()) {
		return string();
	}
	string out = "[";
	for (idx_t i = 0; i < values.size(); i++) {
		out += (i ? "," : "") + Quote(values[i]);
	}
	return out + "]";
}

vector<AttributeDef> ParseStoredAttributes(const string &text) {
	auto trimmed = text;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		return {};
	}
	Json json(trimmed);
	if (!json.Root()) {
		throw BinderException("acl: stored attributes are not valid JSON: %s", trimmed);
	}
	return AttributesOf(json.Root());
}

string StoredAttributes(const vector<AttributeDef> &attributes) {
	if (attributes.empty()) {
		return string();
	}
	string out = "[";
	for (idx_t i = 0; i < attributes.size(); i++) {
		auto &attribute = attributes[i];
		out += (i ? "," : "") + string("{\"name\":") + Quote(attribute.name);
		if (attribute.is_constant) {
			out += ",\"constant\":" + Quote(attribute.constant);
		} else {
			out += ",\"paths\":" + StoredList(attribute.paths);
		}
		out += "}";
	}
	return out + "]";
}

vector<ClaimCondition> ParseStoredConditions(const string &text) {
	auto trimmed = text;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		return {};
	}
	Json json(trimmed);
	if (!json.Root()) {
		throw BinderException("acl: stored conditions are not valid JSON: %s", trimmed);
	}
	return ConditionsOf(json.Root());
}

string StoredConditions(const vector<ClaimCondition> &conditions) {
	if (conditions.empty()) {
		return string();
	}
	string out = "[";
	for (idx_t i = 0; i < conditions.size(); i++) {
		auto &condition = conditions[i];
		out += (i ? "," : "") + string("{\"path\":") + Quote(condition.path) +
		       ",\"op\":" + Quote(OpName(condition.op)) + ",\"values\":" + StoredList(condition.values) + "}";
	}
	return out + "]";
}

void ApplyClientSpec(IdentityClient &client, const string &spec_json, case_insensitive_set_t *written) {
	if (spec_json.empty()) {
		return;
	}
	Json json(spec_json);
	if (!json.Root() || !duckdb_yyjson::yyjson_is_obj(json.Root())) {
		Bad("a client spec is a JSON object");
	}
	duckdb_yyjson::yyjson_obj_iter iter;
	duckdb_yyjson::yyjson_obj_iter_init(json.Root(), &iter);
	while (auto key_value = duckdb_yyjson::yyjson_obj_iter_next(&iter)) {
		auto key = StringUtil::Lower(Text(key_value));
		auto value = duckdb_yyjson::yyjson_obj_iter_get_val(key_value);
		if (written) {
			written->insert(key);
		}
		if (key == "audiences") {
			client.audiences = StringArray(value, "audiences");
		} else if (key == "azp") {
			client.azp = StringArray(value, "azp");
		} else if (key == "require") {
			client.conditions = ConditionsOf(value);
		} else if (key == "roles_from") {
			client.roles_from = StringArray(value, "roles_from");
		} else if (key == "roles_constant") {
			client.roles_constant = StringArray(value, "roles_constant");
		} else if (key == "unmapped") {
			auto unmapped = StringUtil::Lower(StringOf(value, "unmapped"));
			if (unmapped == "as_role" || unmapped == "as role") {
				client.unmapped_as_role = true;
			} else if (unmapped == "ignore" || unmapped.empty()) {
				client.unmapped_as_role = false;
			} else {
				Bad("UNMAPPED is IGNORE or AS ROLE - got \"" + unmapped + "\"");
			}
		} else if (key == "attributes") {
			client.attributes = AttributesOf(value);
		} else if (key == "claim_map") {
			// the short form's CLAIM MAP as text, {"<jwt path>": "<name>"}: parsed here, never spliced
			auto text = StringOf(value, "claim_map");
			if (text.empty()) {
				client.attributes.clear();
			} else {
				Json map(text);
				if (!map.Root() || !duckdb_yyjson::yyjson_is_obj(map.Root())) {
					Bad("CLAIM MAP is a JSON object {\"<jwt path>\": \"<name>\"}");
				}
				client.attributes = AttributesOf(map.Root());
			}
		} else if (key == "subject") {
			client.subject = StringArray(value, "subject");
		} else if (key == "token_type") {
			client.token_type = StringOf(value, "token_type");
		} else if (key == "client_id") {
			client.client_id = StringOf(value, "client_id");
		} else if (key == "flows") {
			auto flows = StringArray(value, "flows");
			for (auto &flow : flows) {
				flow = StringUtil::Lower(flow);
				if (!IsKnownFlow(flow)) {
					Bad("unknown flow \"" + flow + "\" - FLOWS names password, authcode, device or client_credentials");
				}
			}
			client.flows = std::move(flows);
		} else if (key == "secret") {
			// a secret named anew lives where its own IN says (a "service" key after it), else in the one
			// service attached - never silently in the previous secret's
			client.secret = StringOf(value, "secret");
			client.secret_service.clear();
		} else if (key == "service") {
			client.secret_service = StringOf(value, "service");
		} else {
			Bad("unknown client property \"" + key + "\"");
		}
	}
}

void ApplyIssuerSpec(IdentityIssuer &issuer, const string &spec_json, string &client_spec_json) {
	client_spec_json.clear();
	if (spec_json.empty()) {
		return;
	}
	Json json(spec_json);
	if (!json.Root() || !duckdb_yyjson::yyjson_is_obj(json.Root())) {
		Bad("an issuer spec is a JSON object");
	}
	duckdb_yyjson::yyjson_obj_iter iter;
	duckdb_yyjson::yyjson_obj_iter_init(json.Root(), &iter);
	while (auto key_value = duckdb_yyjson::yyjson_obj_iter_next(&iter)) {
		auto key = StringUtil::Lower(Text(key_value));
		auto value = duckdb_yyjson::yyjson_obj_iter_get_val(key_value);
		if (key == "url") {
			issuer.url = StringOf(value, "url");
		} else if (key == "secret") {
			issuer.secret = StringOf(value, "secret");
			issuer.secret_service.clear();
		} else if (key == "service") {
			issuer.secret_service = StringOf(value, "service");
		} else if (key == "client") {
			if (!duckdb_yyjson::yyjson_is_obj(value)) {
				Bad("an issuer's \"client\" is the client spec object");
			}
			size_t length = 0;
			auto written = duckdb_yyjson::yyjson_val_write(value, 0, &length);
			if (!written) {
				Bad("an issuer's \"client\" could not be read");
			}
			client_spec_json = string(written, length);
			free(written);
		} else {
			Bad("unknown issuer property \"" + key + "\"");
		}
	}
}

TokenClaims::TokenClaims(const string &payload_json)
    : doc(duckdb_yyjson::yyjson_read(payload_json.c_str(), payload_json.size(), 0)) {
}

TokenClaims::~TokenClaims() {
	if (doc) {
		duckdb_yyjson::yyjson_doc_free(static_cast<yyjson_doc *>(doc));
	}
}

bool TokenClaims::Valid() const {
	auto root = RootOf(doc);
	return root && duckdb_yyjson::yyjson_is_obj(root);
}

bool TokenClaims::Present(const string &path) const {
	auto value = ClaimAt(RootOf(doc), path);
	return value && !duckdb_yyjson::yyjson_is_null(value);
}

vector<string> TokenClaims::Strings(const string &path) const {
	return ValuesAt(ClaimAt(RootOf(doc), path));
}

string TokenClaims::First(const vector<string> &paths) const {
	for (auto &path : paths) {
		auto value = ClaimAt(RootOf(doc), path);
		if (value && !duckdb_yyjson::yyjson_is_null(value)) {
			return Text(value);
		}
	}
	return string();
}

vector<string> TokenClaims::Audiences() const {
	auto root = RootOf(doc);
	return ValuesAt(root ? duckdb_yyjson::yyjson_obj_get(root, "aud") : nullptr);
}

string TokenClaims::AuthorizedParty() const {
	auto root = RootOf(doc);
	if (!root) {
		return string();
	}
	auto azp = Text(duckdb_yyjson::yyjson_obj_get(root, "azp"));
	if (!azp.empty()) {
		return azp;
	}
	// Entra's v1 tokens name the client `appid`; another IdP's `appid` claim decides nothing
	return Text(duckdb_yyjson::yyjson_obj_get(root, "ver")) == "1.0"
	           ? Text(duckdb_yyjson::yyjson_obj_get(root, "appid"))
	           : string();
}

bool TokenClaims::GroupsOverage() const {
	auto root = RootOf(doc);
	auto names = root ? duckdb_yyjson::yyjson_obj_get(root, "_claim_names") : nullptr;
	return names && duckdb_yyjson::yyjson_is_obj(names) && duckdb_yyjson::yyjson_obj_get(names, "groups");
}

bool LikeMatches(const string &value, const string &pattern) {
	// iterative wildcard match with one backtrack point - linear in practice, never exponential
	idx_t v = 0, p = 0;
	idx_t star_p = string::npos, star_v = 0;
	while (v < value.size()) {
		if (p < pattern.size() && pattern[p] == '%') {
			star_p = p++;
			star_v = v;
		} else if (p < pattern.size() && (pattern[p] == '_' || pattern[p] == value[v])) {
			v++;
			p++;
		} else if (star_p != string::npos) {
			p = star_p + 1;
			v = ++star_v;
		} else {
			return false;
		}
	}
	while (p < pattern.size() && pattern[p] == '%') {
		p++;
	}
	return p == pattern.size();
}

bool ClientAccepts(const IdentityClient &client, const vector<string> &audiences, const TokenClaims &claims,
                   const string &token_type, string &why) {
	if (audiences.empty() || !Intersects(claims.Audiences(), audiences)) {
		why = "audience not accepted";
		return false;
	}
	if (!client.azp.empty() && !Contains(client.azp, claims.AuthorizedParty())) {
		why = "authorized party (azp) not accepted";
		return false;
	}
	for (auto &condition : client.conditions) {
		auto values = claims.Strings(condition.path);
		bool holds = false;
		switch (condition.op) {
		case ClaimCondition::Op::EQUALS:
			holds = values.size() == 1 && values[0] == condition.values[0];
			break;
		case ClaimCondition::Op::ONE_OF:
			holds = values.size() == 1 && Contains(condition.values, values[0]);
			break;
		case ClaimCondition::Op::CONTAINS:
			holds = Contains(values, condition.values[0]);
			break;
		case ClaimCondition::Op::LIKE:
			holds = values.size() == 1 && LikeMatches(values[0], condition.values[0]);
			break;
		}
		if (!holds) {
			why = "the condition on \"" + condition.path + "\" does not hold";
			return false;
		}
	}
	if (!client.token_type.empty()) {
		// RFC 9068: "at+jwt", which a header may also spell with the media type's prefix
		auto typ = StringUtil::Lower(token_type);
		if (StringUtil::StartsWith(typ, "application/")) {
			typ = typ.substr(12);
		}
		auto wanted = StringUtil::Lower(client.token_type);
		if (StringUtil::StartsWith(wanted, "application/")) {
			wanted = wanted.substr(12);
		}
		if (typ != wanted) {
			why = "token type \"" + token_type + "\" is not " + client.token_type;
			return false;
		}
	}
	return true;
}

int ClientSpecificity(const IdentityClient &client) {
	if (!client.azp.empty() || !client.conditions.empty()) {
		return 2;
	}
	return client.implicit ? 0 : 1;
}

int64_t PickClient(const vector<int> &specificities, bool &ambiguous) {
	ambiguous = false;
	int64_t best = -1;
	for (idx_t i = 0; i < specificities.size(); i++) {
		if (best < 0 || specificities[i] > specificities[NumericCast<idx_t>(best)]) {
			best = NumericCast<int64_t>(i);
			ambiguous = false;
		} else if (specificities[i] == specificities[NumericCast<idx_t>(best)]) {
			ambiguous = true;
		}
	}
	return ambiguous ? -1 : best;
}

ClientRoles RolesFor(const IdentityModel &model, const IdentityClient &client, const TokenClaims &claims,
                     const std::function<bool(const string &)> &known_role,
                     const std::function<bool(const string &)> &privileged) {
	ClientRoles out;
	case_insensitive_set_t seen;
	auto add = [&](const string &role, bool own_mapping) {
		if (seen.count(role)) {
			return;
		}
		if (!own_mapping && privileged(role)) {
			// a privileged role is reached only through the client's own explicit mapping
			out.dropped_privileged.push_back(role);
			return;
		}
		seen.insert(role);
		out.roles.push_back(role);
	};
	vector<string> candidates;
	for (auto &path : client.roles_from) {
		for (auto &value : claims.Strings(path)) {
			candidates.push_back(value);
		}
	}
	for (auto &raw : candidates) {
		bool matched = false;
		for (auto &mapping : model.mappings) {
			bool own = mapping.scope_kind == "client" && StringUtil::CIEquals(mapping.scope_name, client.name);
			bool issuer_wide =
			    mapping.scope_kind == "issuer" && StringUtil::CIEquals(mapping.scope_name, client.issuer);
			if ((own || issuer_wide) && mapping.external_value == raw) {
				add(mapping.role, own);
				matched = true;
			}
		}
		if (!matched && client.unmapped_as_role && known_role(raw)) {
			add(raw, false);
		}
	}
	for (auto &role : client.roles_constant) {
		add(role, false);
	}
	return out;
}

case_insensitive_map_t<string> AttributesFor(const IdentityClient &client, const TokenClaims &claims) {
	case_insensitive_map_t<string> out;
	for (auto &attribute : client.attributes) {
		if (attribute.is_constant) {
			out[attribute.name] = attribute.constant;
			continue;
		}
		for (auto &path : attribute.paths) {
			if (claims.Present(path)) {
				out[attribute.name] = claims.First({path});
				break;
			}
		}
	}
	return out;
}

string SubjectFor(const IdentityClient &client, const TokenClaims &claims) {
	return claims.First(client.subject.empty() ? vector<string> {"sub"} : client.subject);
}

void ValidateIdentity(const IdentityModel &model, const IdentityCheckContext &context) {
	case_insensitive_set_t issuer_names, client_names;
	case_insensitive_map_t<string> urls; // resolved URL -> issuer
	case_insensitive_map_t<vector<string>> client_audiences;
	for (auto &issuer : model.issuers) {
		if (issuer.name.empty()) {
			Bad("an issuer needs a name");
		}
		if (!issuer_names.insert(issuer.name).second) {
			Bad("issuer \"" + issuer.name + "\" is defined twice");
		}
		auto url = issuer.url;
		bool judged = !context.touched || context.touched("issuer", issuer.name);
		if (!issuer.secret.empty() && !judged) {
			continue; // its URL is the secret's, judged where it is used
		}
		if (!issuer.secret.empty()) {
			case_insensitive_map_t<string> fields;
			if (!context.read_secret(issuer.secret_service, issuer.secret, "oidc_issuer", fields)) {
				Bad("issuer \"" + issuer.name + "\" names secret \"" + issuer.secret + "\", and " +
				    issuer.secret_service + " has no secret of type oidc_issuer by that name");
			}
			auto in_secret = fields.find("url");
			if (in_secret != fields.end() && !in_secret->second.empty()) {
				if (!issuer.url.empty()) {
					Bad("issuer \"" + issuer.name +
					    "\" has its URL both on the issuer and in its secret - keep it in one place");
				}
				url = in_secret->second;
			}
			auto algs = fields.find("algs");
			if (algs != fields.end()) {
				for (auto &alg : ParseStoredList(algs->second)) {
					if (alg != "RS256" && alg != "ES256" && alg != "HS256") {
						Bad("issuer \"" + issuer.name + "\": ALGS names RS256, ES256 or HS256 - got \"" + alg + "\"");
					}
				}
			}
			auto keys = fields.find("keys");
			auto keys_from = fields.find("keys_from");
			if (keys != fields.end() && !keys->second.empty() && keys_from != fields.end() &&
			    !keys_from->second.empty()) {
				Bad("issuer \"" + issuer.name + "\": its secret carries both KEYS and KEYS_FROM - keep one");
			}
		}
		if (url.empty()) {
			Bad("issuer \"" + issuer.name + "\" has no URL - write URL '<url>' or keep it in its secret");
		}
		auto taken = urls.find(url);
		if (taken != urls.end()) {
			Bad("issuers \"" + taken->second + "\" and \"" + issuer.name + "\" have the same URL \"" + url +
			    "\" - one IdP is one issuer; tell its applications apart with clients");
		}
		urls[url] = issuer.name;
	}
	for (auto &client : model.clients) {
		if (client.name.empty()) {
			Bad("a client needs a name");
		}
		if (!client_names.insert(client.name).second) {
			Bad("client \"" + client.name + "\" is defined twice");
		}
		if (!model.Issuer(client.issuer)) {
			Bad("client \"" + client.name + "\" names issuer \"" + client.issuer + "\", which does not exist");
		}
		auto audiences = client.audiences;
		auto client_id = client.client_id;
		bool confidential = false;
		// what a client says is judged when a write touches it: a client the write did not change was
		// valid when written (or migrated as it was), and an unrelated write must not be refused for
		// it - a role granted an admin scope later, a migrated client without audiences. What it says
		// at use is judged at use (the privileged rule, an empty audience list accepting nothing).
		bool judged = !context.touched || context.touched("client", client.name);
		if (!judged) {
			client_audiences[client.name] = client.audiences;
			continue;
		}
		if (!client.secret.empty()) {
			case_insensitive_map_t<string> fields;
			if (!context.read_secret(client.secret_service, client.secret, "oidc_client", fields)) {
				Bad("client \"" + client.name + "\" names secret \"" + client.secret + "\", and " +
				    client.secret_service + " has no secret of type oidc_client by that name");
			}
			auto in_secret = fields.find("audiences");
			if (in_secret != fields.end() && !in_secret->second.empty()) {
				if (!client.audiences.empty()) {
					Bad("client \"" + client.name +
					    "\" has its AUDIENCES both on the client and in its secret - keep them in one place");
				}
				audiences = ParseStoredList(in_secret->second);
			}
			auto id = fields.find("client_id");
			if (id != fields.end() && !id->second.empty()) {
				if (!client.client_id.empty()) {
					Bad("client \"" + client.name +
					    "\" has its CLIENT ID both on the client and in its secret - keep it in one place");
				}
				client_id = id->second;
			}
			auto secret = fields.find("client_secret");
			confidential = secret != fields.end() && !secret->second.empty();
		}
		if (audiences.empty()) {
			Bad("client \"" + client.name +
			    "\" accepts no audience - AUDIENCES is required (on the client or in its secret), so a token "
			    "issued for another API is never accepted here");
		}
		if (!client.flows.empty() && client_id.empty()) {
			Bad("client \"" + client.name + "\" names FLOWS but has no CLIENT ID to run them as");
		}
		if (confidential && client_id.empty()) {
			Bad("client \"" + client.name + "\" has a CLIENT_SECRET but no CLIENT ID");
		}
		for (auto &role : client.roles_constant) {
			if (context.privileged(role)) {
				Bad("client \"" + client.name + "\": ROLES CONSTANT names \"" + role +
				    "\", which holds an administration scope - a privileged role is reached only through an "
				    "explicit mapping of the client itself");
			}
		}
		if (client.roles_from.empty() && client.roles_constant.empty()) {
			Bad("client \"" + client.name + "\" yields no roles - name ROLES FROM (claim paths) or ROLES CONSTANT");
		}
		case_insensitive_set_t attribute_names;
		for (auto &attribute : client.attributes) {
			if (!attribute_names.insert(attribute.name).second) {
				Bad("client \"" + client.name + "\" defines attribute \"" + attribute.name + "\" twice");
			}
		}
		client_audiences[client.name] = audiences;
	}
	// overlaps visible at write: the same issuer, the same specificity, shared audiences, and either
	// a shared AZP or neither having AZP nor REQUIRE - a token that fits one fits the other
	for (idx_t i = 0; i < model.clients.size(); i++) {
		for (idx_t j = i + 1; j < model.clients.size(); j++) {
			auto &a = model.clients[i];
			auto &b = model.clients[j];
			if (!StringUtil::CIEquals(a.issuer, b.issuer) || ClientSpecificity(a) != ClientSpecificity(b)) {
				continue;
			}
			if (context.touched && !context.touched("client", a.name) && !context.touched("client", b.name)) {
				continue; // a pair the write did not touch was judged when it was written
			}
			if (!Intersects(client_audiences[a.name], client_audiences[b.name])) {
				continue;
			}
			if (!a.conditions.empty() || !b.conditions.empty()) {
				continue; // REQUIRE cannot be compared statically: judged at use
			}
			bool overlap = (a.azp.empty() && b.azp.empty()) || Intersects(a.azp, b.azp);
			if (overlap) {
				Bad("clients \"" + a.name + "\" and \"" + b.name + "\" of issuer \"" + a.issuer +
				    "\" would accept the same tokens - tell them apart by AUDIENCES, AZP or REQUIRE");
			}
		}
	}
	for (auto &mapping : model.mappings) {
		if (mapping.scope_kind == "client") {
			if (!model.Client(mapping.scope_name)) {
				Bad("a mapping names client \"" + mapping.scope_name + "\", which does not exist");
			}
		} else if (mapping.scope_kind == "issuer") {
			if (!model.Issuer(mapping.scope_name)) {
				Bad("a mapping names issuer \"" + mapping.scope_name + "\", which does not exist");
			}
			bool judged =
			    !context.touched ||
			    context.touched("mapping", mapping.scope_kind + "\x1f" + mapping.scope_name + "\x1f" + mapping.source +
			                                   "\x1f" + mapping.external_value + "\x1f" + mapping.role);
			if (judged && context.privileged(mapping.role)) {
				Bad("role \"" + mapping.role +
				    "\" holds an administration scope, so it is mapped FROM CLIENT only - never for every "
				    "client of an issuer");
			}
		} else {
			Bad("a mapping is scoped to a CLIENT or an ISSUER");
		}
		if (mapping.source != "group" && mapping.source != "claim-value") {
			Bad("a mapping's source is group or claim-value");
		}
	}
}

} // namespace acl
} // namespace duckdb
