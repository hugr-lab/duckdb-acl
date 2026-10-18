// The node's label in its sessions' names (spec 134): every rule of acl_node_label.hpp - which labels
// are DNS labels, how a Cookie header is read by name, when the label's Set-Cookie is sent, and what a
// connection id starts with - header-only, no instance. The doors' wiring is test_acl_quack_embed.cpp's
// (quack) and test/e2e/flight/run.sh's (Flight); the setting is test/sql/acl_node_label.test's.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_node_label.hpp"

using namespace duckdb::acl;
using namespace acl_test;

int main(int argc, char *argv[]) {
	return RunMain("the node's label in its sessions' names (spec 134)", [&] {
		Scenario("a label is a DNS label", [&] {
			for (auto ok : {"n", "node-1", "hugr-node-etl-7f9c4d-x2k8p", "0", "a1"}) {
				Check(ValidNodeLabel(ok), std::string("accepted: ") + ok);
			}
			Check(ValidNodeLabel(std::string(63, 'a')), "63 characters is the longest");
			Check(!ValidNodeLabel(std::string(64, 'a')), "64 is one too many");
			for (auto bad : {"", "Node-1", "node_1", "a.b", "-node", "node-", "node 1", "nöde", "a;b", "a=b"}) {
				Check(!ValidNodeLabel(bad), std::string("refused: '") + bad + "'");
			}
		});

		Scenario("a cookie is read by its name, never as a substring", [&] {
			std::string value;
			Check(CookieNamed("acl_node=n1", NODE_LABEL_COOKIE, value) && value == "n1", "alone");
			Check(CookieNamed("a=1; acl_node=n2; b=2", NODE_LABEL_COOKIE, value) && value == "n2", "among others");
			Check(CookieNamed("a=1;acl_node = n3 ", NODE_LABEL_COOKIE, value) && value == "n3", "spaces trimmed");
			Check(!CookieNamed("x_acl_node=n4", NODE_LABEL_COOKIE, value), "a longer name is another cookie");
			Check(!CookieNamed("a=acl_node=n5", NODE_LABEL_COOKIE, value), "a value that looks like it is not it");
			Check(!CookieNamed("", NODE_LABEL_COOKIE, value), "an empty header carries none");
			Check(CookieNamed("acl_node=", NODE_LABEL_COOKIE, value) && value.empty(), "an empty value is a value");
		});

		Scenario("the label's Set-Cookie is sent only when the request lacks it", [&] {
			auto expected = std::string("acl_node=n1; HttpOnly; Path=/; SameSite=Strict");
			Check(NodeLabelSetCookie("n1", {}) == expected, "a request without cookies gets it");
			Check(NodeLabelSetCookie("n1", {"acl_flight_session_id=abc"}) == expected, "...and one with others");
			Check(NodeLabelSetCookie("n1", {"acl_node=n1"}).empty(), "a request carrying it gets none");
			Check(NodeLabelSetCookie("n1", {"a=1", "acl_node=n1; b=2"}).empty(), "...in any of its Cookie headers");
			Check(NodeLabelSetCookie("n1", {"acl_node=n2"}) == expected, "another node's label is replaced");
			Check(NodeLabelSetCookie("", {}).empty(), "without a label, never");
			Check(NodeLabelSetCookie("", {"acl_node=n1"}).empty(), "...not even to clear another node's");
		});

		Scenario("a connection id starts with the label and a dot", [&] {
			Check(NodeLabelIdPrefix("n1") == "n1.", "the prefix");
			Check(NodeLabelIdPrefix("").empty(), "no label, no prefix: the id is quack's own");
			// quack bounds a SEND_DATA header to 256 bytes as 64 + connection id + stream id (a UUID)
			auto longest = NodeLabelIdPrefix(std::string(63, 'a')) + std::string(32, 'f');
			Check(64 + longest.size() + 36 <= 256, "the longest id fits quack's SEND_DATA header");
		});
	});
}
