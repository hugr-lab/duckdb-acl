//! spec 102: fields of structured types in a COLUMNS list. An item's name may be a path into a STRUCT
//! column (`address.city`, `address.geo.lat`) and through a LIST / ARRAY of structs (`items[].price`);
//! the items of one column form a tree, levels of a grant chain intersect trees, a principal's roles
//! unite them, and a tree compiles to the projection item the role reads (`struct_pack` /
//! `struct_update` / `list_transform`). Header-only: the grant types use it, and so does its test.
#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types.hpp"

#include <functional>

namespace duckdb {
namespace acl {
namespace acl_detail {

//! A parsed item name: the column, then the steps into it - a field name, or "" for `[]` (an element)
struct FieldPath {
	string head;
	vector<string> steps;
	bool IsColumn() const {
		return steps.empty();
	}
};

//! `address.city`, `"Order"."Zip Code"`, `items[].price`. A name is an identifier (letters, digits,
//! `_`, `$`) or a double-quoted string; `[]` follows a name or another `[]`. Anything else is refused,
//! so a path is never an expression in disguise.
inline bool ParseFieldPath(const string &text_p, FieldPath &out, string &error) {
	auto text = text_p;
	StringUtil::Trim(text);
	vector<string> parts;
	idx_t i = 0;
	bool expect_name = true;
	while (i < text.size()) {
		auto ch = text[i];
		if (expect_name) {
			string name;
			if (ch == '"') {
				i++;
				bool closed = false;
				while (i < text.size()) {
					if (text[i] == '"') {
						if (i + 1 < text.size() && text[i + 1] == '"') {
							name += '"';
							i += 2;
							continue;
						}
						closed = true;
						i++;
						break;
					}
					name += text[i++];
				}
				if (!closed || name.empty()) {
					error = "an unterminated or empty quoted name";
					return false;
				}
			} else {
				while (i < text.size() && (isalnum(static_cast<unsigned char>(text[i])) || text[i] == '_' ||
				                           text[i] == '$' || static_cast<unsigned char>(text[i]) >= 0x80)) {
					name += text[i++];
				}
				if (name.empty()) {
					error = "a path is names separated by '.', each optionally followed by []";
					return false;
				}
			}
			parts.push_back(name);
			expect_name = false;
			continue;
		}
		if (ch == '[') {
			if (i + 1 >= text.size() || text[i + 1] != ']') {
				error = "'[' must be '[]' (every element of a list)";
				return false;
			}
			parts.push_back(string());
			i += 2;
			continue;
		}
		if (ch == '.') {
			expect_name = true;
			i++;
			continue;
		}
		error = "a path is names separated by '.', each optionally followed by []";
		return false;
	}
	if (expect_name || parts.empty()) {
		error = "a path cannot end with '.'";
		return false;
	}
	out.head = parts[0];
	out.steps.assign(parts.begin() + 1, parts.end());
	return true;
}

//! A name as it is written back: bare when it is an identifier, quoted otherwise
inline string FieldName(const string &name) {
	bool bare = !name.empty() && !isdigit(static_cast<unsigned char>(name[0]));
	for (auto ch : name) {
		// the characters ParseFieldPath reads bare
		if (!isalnum(static_cast<unsigned char>(ch)) && ch != '_' && ch != '$' &&
		    static_cast<unsigned char>(ch) < 0x80) {
			bare = false;
		}
	}
	return bare ? name : "\"" + StringUtil::Replace(name, "\"", "\"\"") + "\"";
}

//! One position of a column's tree. `whole`: everything from here down is visible (except the masked
//! descendants listed); `masked`: the value here is `mask`; otherwise only `fields` / `element` are.
struct FieldNode {
	string name; // the field this node is (empty for an element)
	bool whole = false;
	bool masked = false;
	string mask;
	vector<unique_ptr<FieldNode>> fields;
	unique_ptr<FieldNode> element;

	unique_ptr<FieldNode> Clone() const {
		auto copy = make_uniq<FieldNode>();
		copy->name = name;
		copy->whole = whole;
		copy->masked = masked;
		copy->mask = mask;
		for (auto &field : fields) {
			copy->fields.push_back(field->Clone());
		}
		if (element) {
			copy->element = element->Clone();
		}
		return copy;
	}
	optional_ptr<FieldNode> Find(const string &field) {
		for (auto &child : fields) {
			if (StringUtil::CIEquals(child->name, field)) {
				return child.get();
			}
		}
		return nullptr;
	}
	optional_ptr<const FieldNode> Find(const string &field) const {
		for (auto &child : fields) {
			if (StringUtil::CIEquals(child->name, field)) {
				return child.get();
			}
		}
		return nullptr;
	}
	bool Empty() const {
		return !whole && !masked && fields.empty() && !element;
	}
	//! Visible entirely and unmasked anywhere below
	bool Plain() const {
		return whole && !masked && fields.empty() && !element;
	}
};

inline unique_ptr<FieldNode> WholeNode(const string &name) {
	auto node = make_uniq<FieldNode>();
	node->name = name;
	node->whole = true;
	return node;
}

//! A side's child by name - or, under a whole node, the whole child it implies
inline unique_ptr<FieldNode> ChildOrWhole(const FieldNode &node, const string &name) {
	auto found = node.Find(name);
	if (found) {
		return found->Clone();
	}
	return node.whole ? WholeNode(name) : nullptr;
}

//! A field of a struct value, by name - never `value.name`, which a binder may take for table.column
inline string FieldOf(const string &value, const string &name) {
	return "struct_extract(" + value + ", '" + StringUtil::Replace(name, "'", "''") + "')";
}

inline string QuotedName(const string &name) {
	return "\"" + StringUtil::Replace(name, "\"", "\"\"") + "\"";
}

//! One grant's items for one column, as a tree. `display` names the column in a refusal.
inline void InsertPath(FieldNode &root, const FieldPath &path, const string &mask, const string &display) {
	reference<FieldNode> node = root;
	for (auto &step : path.steps) {
		if (node.get().masked) {
			return; // a mask above covers the path
		}
		if (step.empty()) {
			if (!node.get().element) {
				node.get().element = make_uniq<FieldNode>();
			}
			node = *node.get().element;
			continue;
		}
		auto found = node.get().Find(step);
		if (!found) {
			auto child = make_uniq<FieldNode>();
			child->name = step;
			node.get().fields.push_back(std::move(child));
			found = node.get().fields.back().get();
		}
		node = *found;
	}
	auto &target = node.get();
	if (!mask.empty()) {
		if (target.masked && target.mask != mask) {
			throw BinderException("acl: \"%s\" is masked twice in one grant (\"%s\" and \"%s\")", display, target.mask,
			                      mask);
		}
		target.masked = true;
		target.mask = mask;
		target.fields.clear();
		target.element.reset();
		return;
	}
	if (!target.masked) {
		target.whole = true;
	}
}

//! Within one grant: under a plain whole node, only masked descendants say anything
inline void Simplify(FieldNode &node) {
	if (node.masked) {
		node.fields.clear();
		node.element.reset();
		return;
	}
	vector<unique_ptr<FieldNode>> kept;
	for (auto &child : node.fields) {
		if (node.whole && !child->masked) {
			child->whole = true; // the wider item wins: `address` + `address.geo.lat` keeps all of geo
		}
		Simplify(*child);
		if (node.whole && child->Plain()) {
			continue;
		}
		if (!child->Empty()) {
			kept.push_back(std::move(child));
		}
	}
	node.fields = std::move(kept);
	if (node.element) {
		if (node.whole && !node.element->masked) {
			node.element->whole = true;
		}
		Simplify(*node.element);
		if ((node.whole && node.element->Plain()) || node.element->Empty()) {
			node.element.reset();
		}
	}
}

//! Levels (spec 011): what both the wider level `a` and the narrower `b` let through, the narrower's
//! mask winning where both mask. Null when nothing is left.
inline unique_ptr<FieldNode> IntersectNodes(const FieldNode &a, const FieldNode &b) {
	auto result = make_uniq<FieldNode>();
	result->name = a.name;
	if (b.masked || a.masked) {
		result->masked = true;
		result->mask = b.masked ? b.mask : a.mask;
		return result;
	}
	result->whole = a.whole && b.whole;
	vector<string> names;
	for (auto &child : a.fields) {
		names.push_back(child->name);
	}
	for (auto &child : b.fields) {
		if (!a.Find(child->name)) {
			names.push_back(child->name);
		}
	}
	for (auto &name : names) {
		auto ac = ChildOrWhole(a, name);
		auto bc = ChildOrWhole(b, name);
		if (!ac || !bc) {
			continue;
		}
		auto merged = IntersectNodes(*ac, *bc);
		if (merged && !(result->whole && merged->Plain())) {
			result->fields.push_back(std::move(merged));
		}
	}
	// an element is judged only where a side names one: two whole sides have nothing to say about it
	unique_ptr<FieldNode> ae = a.element ? a.element->Clone() : (a.whole ? WholeNode("") : nullptr);
	unique_ptr<FieldNode> be = b.element ? b.element->Clone() : (b.whole ? WholeNode("") : nullptr);
	if ((a.element || b.element) && ae && be) {
		auto merged = IntersectNodes(*ae, *be);
		if (merged && !(result->whole && merged->Plain())) {
			result->element = std::move(merged);
		}
	}
	if (result->Empty()) {
		return nullptr;
	}
	return result;
}

//! Roles (spec 011): what either lets through - a visible field beats a masked one, the whole beats a
//! part, and two different masks of one position are refused rather than picked.
inline unique_ptr<FieldNode> UniteNodes(optional_ptr<const FieldNode> a, optional_ptr<const FieldNode> b,
                                        const string &display) {
	if (!a) {
		return b ? b->Clone() : nullptr;
	}
	if (!b) {
		return a->Clone();
	}
	if (a->masked && b->masked) {
		if (a->mask != b->mask) {
			throw BinderException(
			    "acl: the principal's roles mask column \"%s\" differently (\"%s\" vs \"%s\") - grant "
			    "the same expression, or drop one of the grants",
			    display, a->mask, b->mask);
		}
		return a->Clone();
	}
	if (a->masked) {
		return b->Clone();
	}
	if (b->masked) {
		return a->Clone();
	}
	auto result = make_uniq<FieldNode>();
	result->name = a->name;
	result->whole = a->whole || b->whole;
	vector<string> names;
	for (auto &child : a->fields) {
		names.push_back(child->name);
	}
	for (auto &child : b->fields) {
		if (!a->Find(child->name)) {
			names.push_back(child->name);
		}
	}
	for (auto &name : names) {
		auto ac = ChildOrWhole(*a, name);
		auto bc = ChildOrWhole(*b, name);
		auto merged = UniteNodes(ac.get(), bc.get(), display + "." + FieldName(name));
		if (merged && !(result->whole && merged->Plain())) {
			result->fields.push_back(std::move(merged));
		}
	}
	unique_ptr<FieldNode> ae = a->element ? a->element->Clone() : (a->whole ? WholeNode("") : nullptr);
	unique_ptr<FieldNode> be = b->element ? b->element->Clone() : (b->whole ? WholeNode("") : nullptr);
	if (a->element || b->element) {
		auto merged = UniteNodes(ae.get(), be.get(), display + "[]");
		if (merged && !(result->whole && merged->Plain())) {
			result->element = std::move(merged);
		}
	}
	return result;
}

//! A tree back to COLUMNS items (`name` / `name = expr`), the form the grant types carry
inline void SerializeNode(const FieldNode &node, const string &prefix, vector<std::pair<string, string>> &out) {
	if (node.masked) {
		out.emplace_back(prefix, node.mask);
		return;
	}
	if (node.whole) {
		out.emplace_back(prefix, string());
	}
	for (auto &child : node.fields) {
		SerializeNode(*child, prefix + "." + FieldName(child->name), out);
	}
	if (node.element) {
		SerializeNode(*node.element, prefix + "[]", out);
	}
}

//! The value a tree lets the role read, over `value` (a column, a field of it, a list element).
//! Fields are read with struct_extract - never `a.b`, which a binder may take for table.column.
inline string CompileNode(const FieldNode &node, const string &value, idx_t depth = 0) {
	if (node.masked) {
		return node.mask;
	}
	auto field_of = [&](const string &name) {
		return FieldOf(value, name);
	};
	auto quoted = QuotedName;
	auto lambda = "__acl_e" + std::to_string(depth);
	if (node.element) {
		// a list keeps its shape: each element through the element's tree
		return "list_transform(" + value + ", lambda " + lambda + ": " + CompileNode(*node.element, lambda, depth + 1) +
		       ")";
	}
	if (node.whole) {
		if (node.fields.empty()) {
			return value;
		}
		vector<string> updates;
		for (auto &child : node.fields) {
			updates.push_back(quoted(child->name) + " := " + CompileNode(*child, field_of(child->name), depth));
		}
		// struct_update over a NULL struct answers a struct of NULLs: a NULL stays NULL
		return "CASE WHEN " + value + " IS NULL THEN NULL ELSE struct_update(" + value + ", " +
		       StringUtil::Join(updates, ", ") + ") END";
	}
	vector<string> packed;
	for (auto &child : node.fields) {
		packed.push_back(quoted(child->name) + " := " + CompileNode(*child, field_of(child->name), depth));
	}
	return "CASE WHEN " + value + " IS NULL THEN NULL ELSE struct_pack(" + StringUtil::Join(packed, ", ") + ") END";
}

//! Whether a tree steps into list elements anywhere - such a column is not written through: the
//! written list's elements cannot be matched to the stored ones (spec 102, decision 3)
inline bool HasElementStep(const FieldNode &node) {
	if (node.element) {
		return true;
	}
	for (auto &child : node.fields) {
		if (HasElementStep(*child)) {
			return true;
		}
	}
	return false;
}

//! spec 102 part B: the value a principal's write puts into a narrowed column. `written` is what the
//! statement supplies, `stored` the column's current value (empty for an INSERT). A field the role
//! sees takes the written value, a hidden field keeps the stored one (an INSERT leaves it NULL - duckdb
//! fills a missing field by name), a masked field takes the mask, and a written value that carries a
//! field the role cannot see is refused - never silently dropped. `refusal` is the error's message.
inline string CompileWrite(const FieldNode &node, const string &written, const string &stored, const string &refusal,
                           idx_t depth = 0) {
	if (node.masked) {
		return node.mask;
	}
	auto field_of = FieldOf;
	auto quoted = QuotedName;
	auto child_write = [&](const FieldNode &child) {
		return CompileWrite(child, field_of(written, child.name),
		                    stored.empty() ? string() : field_of(stored, child.name), refusal, depth + 1);
	};
	if (node.whole) {
		if (node.fields.empty()) {
			return written;
		}
		// the whole is the role's: what it writes stands, except the masked fields, which the grant assigns
		vector<string> updates;
		for (auto &child : node.fields) {
			updates.push_back(quoted(child->name) + " := " + child_write(*child));
		}
		return "CASE WHEN " + written + " IS NULL THEN NULL ELSE struct_update(" + written + ", " +
		       StringUtil::Join(updates, ", ") + ") END";
	}
	vector<string> visible;
	vector<string> fields;
	for (auto &child : node.fields) {
		visible.push_back("'" + StringUtil::Replace(StringUtil::Lower(child->name), "'", "''") + "'");
		fields.push_back(quoted(child->name) + " := " + child_write(*child));
	}
	auto key = "__acl_k" + std::to_string(depth);
	auto foreign = "len(list_filter(struct_keys(" + written + "), lambda " + key + ": translate(" + key +
	               ", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') NOT IN (" +
	               StringUtil::Join(visible, ", ") + "))) > 0";
	auto refuse = "error('" + StringUtil::Replace(refusal, "'", "''") + "')";
	string value;
	if (stored.empty()) {
		value =
		    "CASE WHEN " + written + " IS NULL THEN NULL ELSE struct_pack(" + StringUtil::Join(fields, ", ") + ") END";
	} else {
		// a NULL stored struct has no hidden fields to keep: the written fields are the struct
		auto fresh = CompileWrite(node, written, string(), refusal, depth);
		value = "CASE WHEN " + stored + " IS NULL THEN " + fresh + " ELSE struct_update(" + stored + ", " +
		        StringUtil::Join(fields, ", ") + ") END";
	}
	return "CASE WHEN " + foreign + " THEN " + refuse + " ELSE " + value + " END";
}

//! The type CompileNode's expression has over a value of type `source` - what a listing must say the
//! role reads. `mask_type(path)` answers a masked position's type (a mask's type is the probe's).
//! Mirrors duckdb: struct_pack builds a STRUCT in the listed order, struct_update replaces a field in
//! place, list_transform answers a LIST (from an ARRAY too).
inline LogicalType ProjectedType(const FieldNode &node, const LogicalType &source, const string &path,
                                 const std::function<LogicalType(const string &)> &mask_type) {
	if (node.masked) {
		return mask_type(path);
	}
	if (node.element) {
		if (source.id() != LogicalTypeId::LIST && source.id() != LogicalTypeId::ARRAY) {
			return source;
		}
		auto &child =
		    source.id() == LogicalTypeId::LIST ? ListType::GetChildType(source) : ArrayType::GetChildType(source);
		return LogicalType::LIST(ProjectedType(*node.element, child, path + "[]", mask_type));
	}
	if (source.id() != LogicalTypeId::STRUCT || node.fields.empty()) {
		return source;
	}
	auto &children = StructType::GetChildTypes(source);
	auto type_of = [&](const string &name) -> optional_ptr<const LogicalType> {
		for (auto &child : children) {
			if (StringUtil::CIEquals(child.first.GetIdentifierName(), name)) {
				return &child.second;
			}
		}
		return nullptr;
	};
	child_list_t<LogicalType> result;
	if (node.whole) {
		for (auto &child : children) {
			auto field = node.Find(child.first.GetIdentifierName());
			result.emplace_back(
			    child.first, field ? ProjectedType(*field, child.second,
			                                       path + "." + FieldName(child.first.GetIdentifierName()), mask_type)
			                       : child.second);
		}
		// struct_update appends a field the struct does not have - a mask whose field left the source
		for (auto &field : node.fields) {
			if (!type_of(field->name) && field->masked) {
				result.emplace_back(Identifier(field->name), mask_type(path + "." + FieldName(field->name)));
			}
		}
		return LogicalType::STRUCT(std::move(result));
	}
	for (auto &field : node.fields) {
		auto type = type_of(field->name);
		if (!type && field->masked) {
			// a mask is read whatever the source has: struct_pack builds the field from it
			result.emplace_back(Identifier(field->name), mask_type(path + "." + FieldName(field->name)));
			continue;
		}
		if (!type) {
			continue; // the grant names a field the source no longer has: the read fails, the check says so
		}
		result.emplace_back(Identifier(field->name),
		                    ProjectedType(*field, *type, path + "." + FieldName(field->name), mask_type));
	}
	return LogicalType::STRUCT(std::move(result));
}

//! A type at a path of the form ProjectedType walks (`.name`, `[]`), or nothing
inline bool TypeAtPath(const LogicalType &type, const string &path, LogicalType &out) {
	FieldPath parsed;
	string error;
	if (!ParseFieldPath("x" + path, parsed, error)) {
		return false;
	}
	LogicalType current = type;
	for (auto &step : parsed.steps) {
		if (step.empty()) {
			if (current.id() == LogicalTypeId::LIST) {
				current = ListType::GetChildType(current);
			} else if (current.id() == LogicalTypeId::ARRAY) {
				current = ArrayType::GetChildType(current);
			} else {
				return false;
			}
			continue;
		}
		if (current.id() != LogicalTypeId::STRUCT) {
			return false;
		}
		bool found = false;
		for (auto &child : StructType::GetChildTypes(current)) {
			if (StringUtil::CIEquals(child.first.GetIdentifierName(), step)) {
				current = child.second;
				found = true;
				break;
			}
		}
		if (!found) {
			return false;
		}
	}
	out = current;
	return true;
}

//! COLUMNS items grouped by column, each column's items a tree. A plain column is a whole root.
struct ColumnTrees {
	vector<unique_ptr<FieldNode>> columns; // in the order the columns first appear

	optional_ptr<FieldNode> Find(const string &name) {
		for (auto &column : columns) {
			if (StringUtil::CIEquals(column->name, name)) {
				return column.get();
			}
		}
		return nullptr;
	}
	optional_ptr<const FieldNode> Find(const string &name) const {
		for (auto &column : columns) {
			if (StringUtil::CIEquals(column->name, name)) {
				return column.get();
			}
		}
		return nullptr;
	}

	static ColumnTrees From(const vector<std::pair<string, string>> &items) {
		ColumnTrees trees;
		for (auto &item : items) {
			// a name without '.' or '[' is a column whatever it holds (`odd name`, `od'd` - spec 037 lists
			// them as written), and so is one that does not read as a path: the object's check names it
			FieldPath path;
			string error;
			auto trimmed = item.first;
			StringUtil::Trim(trimmed);
			bool is_path = (trimmed.find('.') != string::npos || trimmed.find('[') != string::npos ||
			                (!trimmed.empty() && trimmed[0] == '"')) &&
			               ParseFieldPath(trimmed, path, error);
			if (!is_path) {
				path.head = item.first;
				StringUtil::Trim(path.head);
				path.steps.clear();
			}
			auto root = trees.Find(path.head);
			if (!root) {
				auto node = make_uniq<FieldNode>();
				node->name = path.head;
				trees.columns.push_back(std::move(node));
				root = trees.columns.back().get();
			}
			InsertPath(*root, path, item.second, item.first);
		}
		for (auto &column : trees.columns) {
			Simplify(*column);
		}
		return trees;
	}

	vector<std::pair<string, string>> Items() const {
		vector<std::pair<string, string>> items;
		for (auto &column : columns) {
			SerializeNode(*column, RootName(*column), items);
		}
		return items;
	}

	//! A column is written as it was named; only one that paths step into is quoted, where needed,
	//! so the paths read back
	static string RootName(const FieldNode &column) {
		bool plain_ok = column.name.find('.') == string::npos && column.name.find('[') == string::npos &&
		                (column.name.empty() || column.name[0] != '"');
		return column.fields.empty() && !column.element && plain_ok ? column.name : FieldName(column.name);
	}
};

//! COLUMNS items as the csv the grant rows store
inline string ItemsCsv(const vector<std::pair<string, string>> &items) {
	vector<string> parts;
	for (auto &item : items) {
		parts.push_back(item.second.empty() ? item.first : item.first + " = " + item.second);
	}
	return StringUtil::Join(parts, ", ");
}

//! True when an item list names any path (not only columns) - the fast path keeps today's behaviour
inline bool HasFieldPaths(const vector<std::pair<string, string>> &items) {
	for (auto &item : items) {
		auto name = item.first;
		StringUtil::Trim(name);
		if (name.find('.') != string::npos || name.find('[') != string::npos || (!name.empty() && name[0] == '"')) {
			return true;
		}
	}
	return false;
}

//! Levels: the wider list `a` narrowed by `b`, in `a`'s column order
inline vector<std::pair<string, string>> IntersectColumnItems(const vector<std::pair<string, string>> &a,
                                                              const vector<std::pair<string, string>> &b) {
	auto ta = ColumnTrees::From(a);
	auto tb = ColumnTrees::From(b);
	ColumnTrees result;
	for (auto &column : ta.columns) {
		auto other = tb.Find(column->name);
		if (!other) {
			continue;
		}
		auto merged = IntersectNodes(*column, *other);
		if (merged) {
			result.columns.push_back(std::move(merged));
		}
	}
	return result.Items();
}

//! Roles: `a` united with `b`, `a`'s columns first, then the new ones in `b`'s order
inline vector<std::pair<string, string>> UniteColumnItems(const vector<std::pair<string, string>> &a,
                                                          const vector<std::pair<string, string>> &b) {
	auto ta = ColumnTrees::From(a);
	auto tb = ColumnTrees::From(b);
	ColumnTrees result;
	for (auto &column : ta.columns) {
		auto other = tb.Find(column->name);
		result.columns.push_back(UniteNodes(column.get(), other ? other.get() : nullptr, column->name));
	}
	for (auto &column : tb.columns) {
		if (!ta.Find(column->name)) {
			result.columns.push_back(column->Clone());
		}
	}
	return result.Items();
}

} // namespace acl_detail
} // namespace acl
} // namespace duckdb
