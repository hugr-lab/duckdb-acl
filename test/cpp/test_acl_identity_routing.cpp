// The identity model's decisions (spec 095), with no store and no server: the routing decision over
// every specificity pattern, LIKE, a client's acceptance, the roles a client makes of a token (the
// privileged-role rule above all), the checks a write passes, and the stored shapes - including the
// v16 forms a migrated catalog carries. src/acl_identity.cpp is compiled into this test.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_identity.hpp"
#include "duckdb/common/error_data.hpp"

#include <functional>

using namespace duckdb;
using namespace acl_test;
using duckdb::acl::AttributeDef;
using duckdb::acl::ClaimCondition;
using duckdb::acl::IdentityCheckContext;
using duckdb::acl::IdentityClient;
using duckdb::acl::IdentityIssuer;
using duckdb::acl::IdentityMapping;
using duckdb::acl::IdentityModel;
using duckdb::acl::TokenClaims;

namespace {

//! The routing decision against a brute-force reading of its contract: the unique maximum wins, a
//! tie at the top is ambiguous, nothing is nothing
void PickClientExhaustively() {
	int64_t checked = 0;
	for (idx_t count = 0; count <= 5; count++) {
		idx_t combinations = 1;
		for (idx_t i = 0; i < count; i++) {
			combinations *= 3;
		}
		for (idx_t code = 0; code < combinations; code++) {
			vector<int> specificities;
			auto rest = code;
			for (idx_t i = 0; i < count; i++) {
				specificities.push_back(static_cast<int>(rest % 3));
				rest /= 3;
			}
			int top = -1;
			idx_t at_top = 0, top_index = 0;
			for (idx_t i = 0; i < specificities.size(); i++) {
				if (specificities[i] > top) {
					top = specificities[i];
					at_top = 1;
					top_index = i;
				} else if (specificities[i] == top) {
					at_top++;
				}
			}
			bool ambiguous = false;
			auto chosen = acl::PickClient(specificities, ambiguous);
			bool right = count == 0   ? chosen == -1 && !ambiguous
			             : at_top > 1 ? chosen == -1 && ambiguous
			                          : chosen == static_cast<int64_t>(top_index) && !ambiguous;
			if (!right) {
				Check(false, "PickClient disagrees for " + std::to_string(count) + " candidates, code " +
				                 std::to_string(code));
				return;
			}
			checked++;
		}
	}
	Check(true, "PickClient over every pattern of up to 5 candidates (" + std::to_string(checked) + ")");
}

void Like() {
	struct Case {
		const char *value, *pattern;
		bool match;
	};
	for (auto &c : vector<Case> {{"repo:hugr-lab/etl:ref", "repo:hugr-lab/etl:%", true},
	                             {"repo:hugr-lab/etlx:ref", "repo:hugr-lab/etl:%", false},
	                             {"u1@acme.test", "%@acme.test", true},
	                             {"u1@acme.test.evil", "%@acme.test", false},
	                             {"abc", "a_c", true},
	                             {"abbc", "a_c", false},
	                             {"", "%", true},
	                             {"x", "", false},
	                             {"a%b", "a%b", true},
	                             {"aXXb", "a%b", true},
	                             {"mississippi", "%iss%ppi", true},
	                             {"mississippi", "%iss%ppx", false}}) {
		Check(acl::LikeMatches(c.value, c.pattern) == c.match,
		      std::string(c.value) + " LIKE " + c.pattern + (c.match ? "" : " (no)"));
	}
}

IdentityClient Client(const string &name, const string &issuer) {
	IdentityClient client;
	client.name = name;
	client.issuer = issuer;
	client.audiences = {"api://x"};
	client.roles_from = {"roles"};
	return client;
}

void Acceptance() {
	TokenClaims claims(R"({"aud": ["api://x", "api://y"], "azp": "app", "sub": "svc-1", "tid": "t2",
	                      "groups": ["staff", "admin"], "nested": {"k": "v"}, "https://claims/tenant": "acme"})");
	string why;
	auto client = Client("c", "i");
	Check(acl::ClientAccepts(client, {"api://y"}, claims, "JWT", why), "an audience in the array is enough");
	Check(!acl::ClientAccepts(client, {"api://z"}, claims, "JWT", why) && why == "audience not accepted",
	      "no shared audience: " + why);
	Check(!acl::ClientAccepts(client, {}, claims, "JWT", why), "no audiences accept nothing");
	client.azp = {"other"};
	Check(!acl::ClientAccepts(client, {"api://x"}, claims, "JWT", why), "azp outside the list");
	client.azp = {"other", "app"};
	Check(acl::ClientAccepts(client, {"api://x"}, claims, "JWT", why), "azp in the list");
	client.conditions = {{"tid", ClaimCondition::Op::IN, {"t1", "t2"}},
	                     {"groups", ClaimCondition::Op::CONTAINS, {"admin"}},
	                     {"sub", ClaimCondition::Op::LIKE, {"svc-%"}},
	                     {"nested.k", ClaimCondition::Op::EQ, {"v"}},
	                     {"https://claims/tenant", ClaimCondition::Op::EQ, {"acme"}}};
	Check(acl::ClientAccepts(client, {"api://x"}, claims, "JWT", why), "every condition holds: " + why);
	client.conditions.push_back({"groups", ClaimCondition::Op::EQ, {"staff"}});
	Check(!acl::ClientAccepts(client, {"api://x"}, claims, "JWT", why),
	      "= on an array claim does not hold (it is not one value): " + why);
	client.conditions.pop_back();
	client.conditions.push_back({"missing", ClaimCondition::Op::LIKE, {"%"}});
	Check(!acl::ClientAccepts(client, {"api://x"}, claims, "JWT", why), "a missing claim fails LIKE '%'");
	client.conditions.clear();
	client.token_type = "at+jwt";
	Check(acl::ClientAccepts(client, {"api://x"}, claims, "application/at+jwt", why), "the media-type spelling");
	Check(!acl::ClientAccepts(client, {"api://x"}, claims, "JWT", why), "typ JWT is not at+jwt");
	// `appid` is Entra v1's azp, and nobody else's
	auto app_only = Client("app", "i");
	app_only.azp = {"x-app"};
	Check(acl::ClientAccepts(app_only, {"api://x"},
	                         TokenClaims(R"({"aud": "api://x", "ver": "1.0", "appid": "x-app"})"), "JWT", why),
	      "an Entra v1 token's appid is its azp");
	Check(
	    !acl::ClientAccepts(app_only, {"api://x"}, TokenClaims(R"({"aud": "api://x", "appid": "x-app"})"), "JWT", why),
	    "another IdP's appid claim decides nothing");
	Check(acl::ClientSpecificity(Client("a", "i")) == 1, "explicit, no azp/require: 1");
	auto implicit = Client("b", "i");
	implicit.implicit = true;
	Check(acl::ClientSpecificity(implicit) == 0, "implicit: 0");
	Check(acl::ClientSpecificity(client) == 2, "azp: 2");
}

void Roles() {
	IdentityModel model;
	model.issuers.push_back({"kc", "https://kc", "", ""});
	auto client = Client("desktop", "kc");
	client.roles_from = {"realm_access.roles", "groups"};
	model.clients.push_back(client);
	auto other = Client("other", "kc");
	model.clients.push_back(other);
	model.mappings.push_back({"client", "desktop", "group", "g-admin", "boss"});
	model.mappings.push_back({"issuer", "kc", "claim-value", "sales", "analyst"});
	model.mappings.push_back({"client", "other", "claim-value", "sales", "auditor"});
	model.mappings.push_back({"issuer", "kc", "claim-value", "ops", "boss"}); // a stray privileged one
	auto known = [](const string &role) {
		return role == "analyst" || role == "boss" || role == "viewer";
	};
	auto privileged = [](const string &role) {
		return role == "boss";
	};
	TokenClaims claims(R"({"realm_access": {"roles": ["sales", "viewer", "boss", "ops"]}, "groups": ["g-admin"]})");
	auto roles = acl::RolesFor(model, model.clients[0], claims, known, privileged);
	auto has = [&](const string &role) {
		return std::find(roles.roles.begin(), roles.roles.end(), role) != roles.roles.end();
	};
	Check(has("analyst"), "an issuer-scope mapping applies to every client of it");
	Check(!has("auditor"), "another client's mapping never applies");
	Check(has("boss"), "a privileged role through the client's own mapping");
	Check(!has("viewer"), "UNMAPPED IGNORE: an unmapped value is no role");
	// the same token through a client that keeps unmapped values: viewer yes, boss still only by mapping
	model.clients[0].unmapped_as_role = true;
	model.mappings.erase(model.mappings.begin()); // no own mapping to boss any more
	roles = acl::RolesFor(model, model.clients[0], claims, known, privileged);
	Check(has("viewer"), "UNMAPPED AS ROLE: an unmapped value that names a role is that role");
	Check(!has("boss"), "...but never a privileged one, mapped by the issuer or unmapped");
	Check(roles.dropped_privileged.size() == 2,
	      "both privileged paths dropped: " + std::to_string(roles.dropped_privileged.size()));
	model.clients[0].roles_constant = {"boss"};
	roles = acl::RolesFor(model, model.clients[0], claims, known, privileged);
	Check(!has("boss"), "a privileged constant is dropped at use too");
}

void Attributes() {
	auto client = Client("c", "i");
	client.attributes = {{"tenant", {"tid"}, false, ""},
	                     {"mail", {"upn", "email"}, false, ""},
	                     {"org", {}, true, "acme"},
	                     {"absent", {"nope"}, false, ""}};
	TokenClaims claims(R"({"tid": "t1", "email": "a@b", "org": "evil"})");
	auto attributes = acl::AttributesFor(client, claims);
	Check(attributes["tenant"] == "t1", "a path");
	Check(attributes["mail"] == "a@b", "the first present of the fallbacks");
	Check(attributes["org"] == "acme", "a CONSTANT is what it says, whatever the token carries");
	Check(!attributes.count("absent"), "an absent path is no attribute");
	client.subject = {"email", "sub"};
	Check(acl::SubjectFor(client, claims) == "a@b", "the subject's first present path");
}

void StoredShapes() {
	Check(acl::ParseStoredList("a, b ,c") == vector<string> {"a", "b", "c"}, "a v16 csv list");
	Check(acl::ParseStoredList(R"(["a,1","b"])") == vector<string> {"a,1", "b"}, "a JSON list keeps its commas");
	Check(acl::ParseStoredList(acl::StoredList({"x\"y", "z"})) == vector<string> {"x\"y", "z"}, "round trip");
	auto legacy = acl::ParseStoredAttributes(R"({"tid": "tenant", "oid": "user_id"})");
	Check(legacy.size() == 2 && legacy[0].name == "tenant" && legacy[0].paths[0] == "tid", "a v16 claim map");
	auto attributes = acl::ParseStoredAttributes(acl::StoredAttributes(legacy));
	Check(attributes.size() == 2 && attributes[1].name == "user_id", "attributes round trip");
	vector<ClaimCondition> conditions {{"tid", ClaimCondition::Op::IN, {"a", "b"}}};
	auto back = acl::ParseStoredConditions(acl::StoredConditions(conditions));
	Check(back.size() == 1 && back[0].op == ClaimCondition::Op::IN && back[0].values.size() == 2, "conditions");
}

IdentityCheckContext NoSecrets() {
	IdentityCheckContext context;
	context.read_secret = [](const string &, const string &, const string &, case_insensitive_map_t<string> &) {
		return false;
	};
	context.privileged = [](const string &role) {
		return role == "boss";
	};
	return context;
}

bool Refuses(const IdentityModel &model, const IdentityCheckContext &context, const string &why) {
	try {
		acl::ValidateIdentity(model, context);
	} catch (std::exception &ex) {
		string text = ErrorData(ex).RawMessage();
		return Check(text.find(why) != string::npos, "refused (" + why + "): " + text);
	}
	return Check(false, "refused (" + why + "): it passed");
}

void Writes() {
	auto context = NoSecrets();
	IdentityModel model;
	model.issuers.push_back({"kc", "https://kc", "", ""});
	model.clients.push_back(Client("a", "kc"));
	acl::ValidateIdentity(model, context);
	Check(true, "one issuer, one client");

	auto twin = model;
	twin.issuers.push_back({"kc2", "https://kc", "", ""});
	Refuses(twin, context, "have the same URL");

	auto overlap = model;
	overlap.clients.push_back(Client("b", "kc"));
	Refuses(overlap, context, "would accept the same tokens");
	overlap.clients[1].audiences = {"api://other"};
	acl::ValidateIdentity(overlap, context);
	Check(true, "disjoint audiences do not overlap");
	overlap.clients[0].azp = {"app-a"};
	overlap.clients[1].audiences = {"api://x"};
	overlap.clients[1].azp = {"app-b"};
	acl::ValidateIdentity(overlap, context);
	Check(true, "disjoint azp do not overlap");
	overlap.clients[1].azp = {"app-b", "app-a"};
	Refuses(overlap, context, "would accept the same tokens");
	overlap.clients[1].azp.clear();
	overlap.clients[1].conditions = {{"sub", ClaimCondition::Op::EQ, {"x"}}};
	overlap.clients[0].conditions = {{"tid", ClaimCondition::Op::EQ, {"y"}}};
	acl::ValidateIdentity(overlap, context);
	Check(true, "REQUIRE is judged at use, not at write");

	auto deaf = model;
	deaf.clients[0].audiences.clear();
	Refuses(deaf, context, "AUDIENCES is required");

	auto silent = model;
	silent.clients[0].roles_from.clear();
	Refuses(silent, context, "yields no roles");

	auto bossy = model;
	bossy.clients[0].roles_constant = {"boss"};
	Refuses(bossy, context, "ROLES CONSTANT names \"boss\"");

	auto wide = model;
	wide.mappings.push_back({"issuer", "kc", "claim-value", "x", "boss"});
	Refuses(wide, context, "mapped FROM CLIENT only");
	wide.mappings.back().scope_kind = "client";
	wide.mappings.back().scope_name = "a";
	acl::ValidateIdentity(wide, context);
	Check(true, "a privileged role through the client's own mapping is written");

	auto orphan = model;
	orphan.clients.push_back(Client("lost", "nosuch"));
	Refuses(orphan, context, "names issuer \"nosuch\", which does not exist");

	auto flows = model;
	flows.clients[0].flows = {"password"};
	Refuses(flows, context, "names FLOWS but has no CLIENT ID");

	auto secret = model;
	secret.issuers[0].secret = "s";
	secret.issuers[0].secret_service = "corp";
	Refuses(secret, context, "has no secret of type oidc_issuer");
	// a write that does not touch the issuer does not read its secret: the service may be down
	auto untouched = context;
	untouched.touched = [](const string &, const string &) {
		return false;
	};
	acl::ValidateIdentity(secret, untouched);
	Check(true, "an untouched object's secret is judged where it is used");
	// a client the write did not touch is not judged again: a migrated client without audiences, or a
	// role made an administrator after it was mapped issuer-wide, must not block an unrelated write
	auto legacy = model;
	legacy.clients[0].audiences.clear();
	legacy.mappings.push_back({"issuer", "kc", "claim-value", "old", "boss"});
	legacy.mappings.push_back({"client", "a", "claim-value", "new", "analyst"});
	auto only_new = context;
	only_new.touched = [](const string &kind, const string &name) {
		return kind == "mapping" && name.find("new") != string::npos;
	};
	acl::ValidateIdentity(legacy, only_new);
	Check(true, "an untouched client and an untouched mapping are not judged again");
	auto both = context;
	both.read_secret = [](const string &, const string &, const string &type, case_insensitive_map_t<string> &fields) {
		fields["url"] = "https://other";
		return type == "oidc_issuer";
	};
	Refuses(secret, both, "both on the issuer and in its secret");
}

} // namespace

int main(int argc, char *argv[]) {
	return RunMain("the identity model's decisions (spec 095)", [&] {
		Scenario("routing", PickClientExhaustively);
		Scenario("LIKE", Like);
		Scenario("acceptance", Acceptance);
		Scenario("roles", Roles);
		Scenario("attributes", Attributes);
		Scenario("stored shapes", StoredShapes);
		Scenario("writes", Writes);
	});
}
