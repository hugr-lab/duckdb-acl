//===----------------------------------------------------------------------===//
// acl_grammar.hpp
//
// Spec 150: our grammar as rules of duckdb's PEG parser. Stage 2: the ACL prefix's head -
// `ACL <ROLE|TOKEN|SESSION|INGEST> '<value>' | ACL ADMIN`, its markers (TRACE, PARENT, LINEAGE …) and
// the client's mode marker (`ACL`, `ACL NATIVE`) - is read by a rule, which passes the rest of the
// statement through as tokens and says where it starts. The rest is then parsed as its own text, the
// way each mode parses it, by the standard parser with the connection's grammar extensions. The
// rules are compiled inside the override (the connection's extensions, ours behind them) and also
// registered as the grammar extension `acl` - for completion only.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "duckdb/parser/parser_options.hpp"

namespace duckdb {
class GrammarExtension;

namespace acl {

//! What the prefix rule read off a text's head
struct GrammarPrefix {
	enum class Kind : uint8_t { ROLE, TOKEN, SESSION, INGEST, ADMIN };
	enum class MarkerKind : uint8_t { TRACE, PARENT, LINEAGE_PARENT, LINEAGE_ROOT, LINEAGE_JOB };
	//! how many marker kinds there are - LINEAGE_JOB is the last
	static constexpr uint8_t MARKER_KINDS = static_cast<uint8_t>(MarkerKind::LINEAGE_JOB) + 1;
	//! a marker, in the order written
	struct Marker {
		MarkerKind kind;
		string value;
	};
	Kind kind = Kind::ROLE;
	//! the principal's value, as written inside its quotes (none for ADMIN)
	string value;
	vector<Marker> markers;
	//! how many times LINEAGE was written (more than once is refused by the reader)
	idx_t lineage_written = 0;
	//! the client's mode marker: `ACL` after the head, and whether `NATIVE` follows it
	bool mode_written = false;
	bool native = false;
	//! where the rest starts: past the head and the whitespace after it
	idx_t rest_start = 0;
};

//! A marker's words as a client writes them: `TRACE`, `LINEAGE JOB`, ...
const char *MarkerWords(GrammarPrefix::MarkerKind kind);

//! The grammars the override compiles, one per set of the caller's grammar extensions
class AclGrammarCache {
public:
	AclGrammarCache();
	~AclGrammarCache();

	//! Reads `query`'s ACL prefix head. False when the text has none of ours (it does not start with
	//! `ACL <kind>`) - the override leaves it. Throws a ParserException for a head the rule refuses.
	bool ReadPrefix(const string &query, const ParserOptions &options, GrammarPrefix &out);

	//! The rules as a grammar extension, registered so a connection may switch them on for completion
	//! (`SET active_grammar_extensions = ['acl']`); the override never depends on it being on
	shared_ptr<GrammarExtension> Extension() const;

private:
	struct Impl;
	unique_ptr<Impl> impl;
};

} // namespace acl
} // namespace duckdb
