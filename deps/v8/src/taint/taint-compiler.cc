// src/taint/taint-compiler.cc
#include "src/taint/taint-compiler.h"
#include <cstring>
#include <iostream>

namespace dynalysis {

// =========================================================================
// Helper: deep-copy strings onto the heap for engine lifetime
// =========================================================================
static const char* AllocateString(const std::string& str) {
    if (str.empty()) return nullptr;
    return strdup(str.c_str());
}

// =========================================================================
// Binary .tbin loader — zero JSON dependency
// Format: see DTAdoc/tsl/TSL_RFC.md section 4.2
// =========================================================================

// Helper: read a little-endian value from buffer
static uint16_t ReadU16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static int8_t   ReadI8(const uint8_t* p) { return static_cast<int8_t>(p[0]); }
static int32_t  ReadI32(const uint8_t* p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

// =========================================================================
// TBIN v2 Binary Format Protocol
// =========================================================================
//
// Header (14 bytes for v2, 12 bytes for v1):
//   [0:4]   Magic "TBIN"
//   [4:6]   Version (u16 LE): 1 or 2
//   [6:8]   v1: RuleCount (u16)  |  v2: Flags (u16, reserved=0)
//   [8:10]  v1: StrTableOff lo   |  v2: RuleCount (u16)
//   [10:12] v1: StrTableOff hi   |  v2: StrTableOffset (u32) [10:14]
//   [12:14] v2 only: (part of StrTableOffset u32)
//
// v2 Header (14 bytes):
//   [0:4]   Magic "TBIN"
//   [4:6]   Version = 2
//   [6:8]   Flags (u16, reserved)
//   [8:10]  RuleCount (u16)
//   [10:14] StringTableOffset (u32)
//
// Per Rule (v2 adds DispatchCategory byte):
//   [0:2]   SignatureIndex (u16, into string table)
//   [2]     DispatchCategory (u8): 0=V8_native, 1=V8_runtime, 2=V8_bytecode, 3=Node
//   [3]     SubRuleCount (u8)
//   ...subrules (encoding unchanged from v1)
//
// Per SubRule:
//   [0]     ActionType (u8): 0-8 per enum
//   [1:3]   AlertCWE (u16)
//   [3]     GuardCount (u8)
//   ...guards, sources, sinks (unchanged)
//
// =========================================================================

// Helper: read a ValueSource from the binary stream
static ValueSource ReadValueSourceFromBinary(const uint8_t* data, size_t& pos, size_t limit,
                                              const std::vector<std::string>& strings) {
    ValueSource vs;
    if (pos >= limit) return vs;
    vs.type = static_cast<ValueSourceType>(data[pos]); pos += 1;
    if (vs.type == ValueSourceType::kLocatorTaint ||
        vs.type == ValueSourceType::kLocatorRef ||
        vs.type == ValueSourceType::kLocatorValue) {
        if (pos + 2 > limit) return vs;
        uint8_t base = data[pos]; pos += 1;
        int8_t index = ReadI8(data + pos); pos += 1;
        vs.base = static_cast<BaseEntity>(base);
        vs.index = index;
    } else if (vs.type == ValueSourceType::kLiteral) {
        if (pos >= limit) return vs;
        uint8_t lit_type = data[pos]; pos += 1;
        vs.literal_type = static_cast<GuardPredicate::LitType>(lit_type);
        switch (vs.literal_type) {
            case GuardPredicate::LitType::kString: {
                if (pos + 2 > limit) break;
                uint16_t sidx = ReadU16(data + pos); pos += 2;
                if (sidx < strings.size()) vs.literal_string = AllocateString(strings[sidx]);
                break;
            }
            case GuardPredicate::LitType::kInt:
                if (pos + 4 > limit) break;
                vs.literal_int = ReadI32(data + pos); pos += 4;
                break;
            case GuardPredicate::LitType::kBool:
                if (pos >= limit) break;
                vs.literal_bool = (data[pos] != 0); pos += 1;
                break;
            case GuardPredicate::LitType::kNull:
                break;
            default:
                break;
        }
    }
    return vs;
}

ParsedRuleSet TaintCompiler::CompileBinary(const uint8_t* data, size_t size) {
    ParsedRuleSet ruleset;
    if (size < 12) return ruleset;

    // Validate magic
    if (data[0] != 'T' || data[1] != 'B' || data[2] != 'I' || data[3] != 'N') {
        std::cerr << "[DTA-ERROR] Invalid .tbin magic bytes" << std::endl;
        return ruleset;
    }

    uint16_t version = ReadU16(data + 4);
    uint16_t rule_count;
    uint32_t str_table_offset;
    size_t rules_start;
    uint16_t var_count = 0;

    if (version == 4) {
        // v4 header: 20 bytes
        if (size < 20) return ruleset;
        // flags = ReadU16(data + 6);
        var_count = ReadU16(data + 8);
        rule_count = ReadU16(data + 10);
        uint32_t rules_offset = data[12] | (data[13] << 8) | (data[14] << 16) | (data[15] << 24);
        str_table_offset = data[16] | (data[17] << 8) | (data[18] << 16) | (data[19] << 24);
        rules_start = rules_offset;
    } else if (version == 2 || version == 3) {
        // v2/v3 header: 14 bytes (same layout; v3 adds callback_owner bytes in locators)
        if (size < 14) return ruleset;
        // flags = ReadU16(data + 6); // reserved
        rule_count = ReadU16(data + 8);
        str_table_offset = data[10] | (data[11] << 8) | (data[12] << 16) | (data[13] << 24);
        rules_start = 14;
    } else if (version == 1) {
        // v1 header: 12 bytes (legacy)
        rule_count = ReadU16(data + 6);
        str_table_offset = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
        rules_start = 12;
    } else {
        std::cerr << "[DTA-ERROR] Unsupported .tbin version: " << version << std::endl;
        return ruleset;
    }

    // Read string table
    std::vector<std::string> strings;
    if (str_table_offset < size) {
        size_t pos = str_table_offset;
        uint16_t entry_count = ReadU16(data + pos); pos += 2;
        for (uint16_t i = 0; i < entry_count && pos < size; i++) {
            uint16_t len = ReadU16(data + pos); pos += 2;
            if (pos + len > size) break;
            strings.emplace_back(reinterpret_cast<const char*>(data + pos), len);
            pos += len;
        }
    }

    auto get_str = [&](uint16_t idx) -> const char* {
        if (idx < strings.size()) return AllocateString(strings[idx]);
        return nullptr;
    };

    // v4: read var table (between header and rules_start)
    if (version == 4 && var_count > 0) {
        size_t vpos = 20;  // var table starts right after 20-byte header
        for (uint16_t vi = 0; vi < var_count && vpos < rules_start; vi++) {
            VarDeclaration vd;
            if (vpos + 4 > rules_start) break;
            uint16_t name_idx = ReadU16(data + vpos); vpos += 2;
            vd.name = get_str(name_idx);
            vd.value_type = static_cast<VarValueType>(data[vpos]); vpos += 1;
            vd.structure = static_cast<VarStructure>(data[vpos]); vpos += 1;
            if (vd.structure == VarStructure::kMap1 || vd.structure == VarStructure::kMap2) {
                if (vpos >= rules_start) break;
                vd.key1_type = static_cast<VarValueType>(data[vpos]); vpos += 1;
            }
            if (vd.structure == VarStructure::kMap2) {
                if (vpos >= rules_start) break;
                vd.key2_type = static_cast<VarValueType>(data[vpos]); vpos += 1;
            }
            ruleset.var_declarations.push_back(vd);
        }
    }

    // Read rules
    size_t pos = rules_start;
    for (uint16_t ri = 0; ri < rule_count && pos < str_table_offset; ri++) {
        uint16_t sig_idx = ReadU16(data + pos); pos += 2;

        // v2: dispatch category byte
        DispatchCategory category = DispatchCategory::kLegacy;
        if (version >= 2) {
            category = static_cast<DispatchCategory>(data[pos]); pos += 1;
        }

        uint8_t sr_count = data[pos]; pos += 1;

        std::string func_sig = (sig_idx < strings.size()) ? strings[sig_idx] : "";
        BuiltinRuleDescriptor desc;
        desc.operation_name = AllocateString(func_sig);
        desc.is_valid = true;
        desc.category = category;

        for (uint8_t si = 0; si < sr_count && pos < str_table_offset; si++) {
            SubRule sr;
            uint8_t action = data[pos]; pos += 1;
            sr.action = static_cast<ActionType>(action);
            sr.alert_cwe = ReadU16(data + pos); pos += 2;

            // Guards
            uint8_t guard_count = data[pos]; pos += 1;
            for (uint8_t gi = 0; gi < guard_count && pos < str_table_offset; gi++) {
                GuardPredicate g;
                g.expr_type = static_cast<GuardPredicate::ExprType>(data[pos]); pos += 1;

                if (g.expr_type == GuardPredicate::ExprType::kMagicGlobal) {
                    g.magic_global_id = data[pos]; pos += 1;
                } else if (g.expr_type == GuardPredicate::ExprType::kVarLookup) {
                    // kVarLookup: VarIndex(u16) + KeySourceCount(u8) + KeySources
                    g.var_index = ReadU16(data + pos); pos += 2;
                    uint8_t key_src_count = data[pos]; pos += 1;
                    for (uint8_t ki = 0; ki < key_src_count && pos < str_table_offset; ki++) {
                        g.var_key_sources.push_back(
                            ReadValueSourceFromBinary(data, pos, str_table_offset, strings));
                    }
                } else {
                    g.param_index = ReadI8(data + pos); pos += 1;
                    uint16_t prop_idx = ReadU16(data + pos); pos += 2;
                    if (prop_idx > 0 && prop_idx < strings.size()) {
                        g.prop_name = get_str(prop_idx);
                    }
                }
                g.magic_prop = static_cast<GuardPredicate::MagicPropType>(data[pos]); pos += 1;
                g.compare_op = static_cast<GuardPredicate::CompareOp>(data[pos]); pos += 1;
                g.negate = (data[pos] != 0); pos += 1;
                uint8_t lit_type = data[pos]; pos += 1;
                g.literal_type = static_cast<GuardPredicate::LitType>(lit_type);

                switch (g.literal_type) {
                    case GuardPredicate::LitType::kString: {
                        uint16_t sidx = ReadU16(data + pos); pos += 2;
                        g.literal_string = get_str(sidx);
                        break;
                    }
                    case GuardPredicate::LitType::kInt:
                        g.literal_int = ReadI32(data + pos); pos += 4;
                        break;
                    case GuardPredicate::LitType::kBool:
                        g.literal_bool = (data[pos] != 0); pos += 1;
                        break;
                    case GuardPredicate::LitType::kNull:
                        break;
                    case GuardPredicate::LitType::kStringSet: {
                        uint8_t cnt = data[pos]; pos += 1;
                        for (uint8_t k = 0; k < cnt; k++) {
                            uint16_t sidx = ReadU16(data + pos); pos += 2;
                            g.literal_string_set.push_back(get_str(sidx));
                        }
                        break;
                    }
                }
                sr.guards.push_back(std::move(g));
            }

            // Sources
            uint8_t src_count = data[pos]; pos += 1;
            for (uint8_t j = 0; j < src_count && pos < str_table_offset; j++) {
                SourceLocator loc;
                loc.base = static_cast<BaseEntity>(data[pos]); pos += 1;
                loc.index = ReadI8(data + pos); pos += 1;
                loc.end_index = ReadI8(data + pos); pos += 1;
                loc.offset = static_cast<OffsetType>(data[pos]); pos += 1;
                if (loc.offset == OffsetType::kSpecificProperty) {
                    uint16_t pidx = ReadU16(data + pos); pos += 2;
                    loc.prop_name = get_str(pidx);
                } else if (loc.offset == OffsetType::kDynamicKey) {
                    loc.dynamic_key_arg_index = data[pos]; pos += 1;
                }
                // v3: read callback_owner_arg_index for CALLBACK bases
                if (version >= 3 &&
                    (loc.base == BaseEntity::kCallbackParam ||
                     loc.base == BaseEntity::kCallbackReturn)) {
                    loc.callback_owner_arg_index = ReadI8(data + pos); pos += 1;
                    if (loc.callback_owner_arg_index == -2) {
                        loc.spread_start_index = data[pos]; pos += 1;
                    }
                }
                // v4: read var_key_sources for kVarLookup base
                if (version >= 4 && loc.base == BaseEntity::kVarLookup) {
                    uint8_t vk_count = data[pos]; pos += 1;
                    for (uint8_t vki = 0; vki < vk_count && pos < str_table_offset; vki++) {
                        loc.var_key_sources.push_back(
                            ReadValueSourceFromBinary(data, pos, str_table_offset, strings));
                    }
                }
                sr.sources.push_back(loc);
            }

            // Sinks
            uint8_t sink_count = data[pos]; pos += 1;
            for (uint8_t j = 0; j < sink_count && pos < str_table_offset; j++) {
                SinkLocator loc;
                loc.base = static_cast<BaseEntity>(data[pos]); pos += 1;
                loc.index = ReadI8(data + pos); pos += 1;
                loc.offset = static_cast<OffsetType>(data[pos]); pos += 1;
                if (loc.offset == OffsetType::kSpecificProperty) {
                    uint16_t pidx = ReadU16(data + pos); pos += 2;
                    loc.prop_name = get_str(pidx);
                } else if (loc.offset == OffsetType::kDynamicKey) {
                    loc.dynamic_key_arg_index = data[pos]; pos += 1;
                }
                // v3: read callback_owner_arg_index for CALLBACK bases
                if (version >= 3 &&
                    (loc.base == BaseEntity::kCallbackParam ||
                     loc.base == BaseEntity::kCallbackReturn)) {
                    loc.callback_owner_arg_index = ReadI8(data + pos); pos += 1;
                    if (loc.callback_owner_arg_index == -2) {
                        loc.spread_start_index = data[pos]; pos += 1;
                    }
                }
                sr.sinks.push_back(loc);
            }

            // v4: read SET action fields after standard guards/sources/sinks
            if (version >= 4 && sr.action == ActionType::kSet) {
                if (pos + 3 <= str_table_offset) {
                    sr.set_var_index = ReadU16(data + pos); pos += 2;
                    uint8_t key_src_count = data[pos]; pos += 1;
                    for (uint8_t ki = 0; ki < key_src_count && pos < str_table_offset; ki++) {
                        sr.set_key_sources.push_back(
                            ReadValueSourceFromBinary(data, pos, str_table_offset, strings));
                    }
                    sr.set_value_source =
                        ReadValueSourceFromBinary(data, pos, str_table_offset, strings);
                }
            }

            // Auto-generate label_suffix
            sr.label_suffix = AllocateString("tbin-rule");

            desc.sub_rules.push_back(std::move(sr));
        }

        if (version >= 2) {
            // v2: store in unified rules map with explicit category
            ruleset.rules[func_sig] = std::move(desc);
        } else {
            // v1 legacy: all into host_apis for name-inference reclassification
            ruleset.host_apis[func_sig] = std::move(desc);
        }
    }

    return ruleset;
}

} // namespace dynalysis