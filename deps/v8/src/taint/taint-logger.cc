// taint-logger.cc — DTA Unified Logging System Implementation
// Pure C++ implementation with no V8 dependencies.

#include "taint-logger.h"
#include "taint-core.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace dynalysis {

// =========================================================================
// Lifecycle
// =========================================================================

DtaLogger::~DtaLogger() { Shutdown(); }

void DtaLogger::Init(const char* json_path, Level level) {
  level_ = level;
  if (json_path != nullptr && json_path[0] != '\0') {
    json_file_ = fopen(json_path, "a");
    if (json_file_ == nullptr) {
      fprintf(stderr,
              "[DTA-LOGGER] WARNING: Failed to open '%s' for append, "
              "falling back to text mode\n",
              json_path);
    }
  }
}

void DtaLogger::Shutdown() {
  if (json_file_ != nullptr) {
    fclose(json_file_);
    json_file_ = nullptr;
  }
}

// =========================================================================
// Internal helpers
// =========================================================================

uint64_t DtaLogger::NowMs() {
  auto now = std::chrono::system_clock::now();
  auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          now.time_since_epoch())
          .count();
  return static_cast<uint64_t>(ms);
}

void DtaLogger::FormatTimestamp(char* buf, size_t size) {
  auto now = std::chrono::system_clock::now();
  auto ms_since_epoch =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          now.time_since_epoch())
          .count();
  auto secs = static_cast<time_t>(ms_since_epoch / 1000);
  int ms_part = static_cast<int>(ms_since_epoch % 1000);

  struct tm tm_buf;
  gmtime_r(&secs, &tm_buf);
  int written = snprintf(buf, size, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                         tm_buf.tm_year + 1900, tm_buf.tm_mon + 1,
                         tm_buf.tm_mday, tm_buf.tm_hour, tm_buf.tm_min,
                         tm_buf.tm_sec, ms_part);
  if (written < 0 || static_cast<size_t>(written) >= size) {
    if (size > 0) buf[0] = '\0';
  }
}

void DtaLogger::EscapeJsonString(const char* src, char* dst, size_t dst_size) {
  if (dst_size == 0) return;
  size_t di = 0;
  for (size_t si = 0; src[si] != '\0' && di + 1 < dst_size; ++si) {
    unsigned char ch = static_cast<unsigned char>(src[si]);
    if (ch == '"' || ch == '\\') {
      if (di + 2 >= dst_size) break;
      dst[di++] = '\\';
      dst[di++] = static_cast<char>(ch);
    } else if (ch == '\n') {
      if (di + 2 >= dst_size) break;
      dst[di++] = '\\';
      dst[di++] = 'n';
    } else if (ch == '\t') {
      if (di + 2 >= dst_size) break;
      dst[di++] = '\\';
      dst[di++] = 't';
    } else if (ch == '\r') {
      if (di + 2 >= dst_size) break;
      dst[di++] = '\\';
      dst[di++] = 'r';
    } else if (ch < 0x20) {
      // Control character: emit \u00XX
      if (di + 6 >= dst_size) break;
      int written = snprintf(dst + di, dst_size - di, "\\u%04x",
                             static_cast<unsigned>(ch));
      if (written > 0) di += static_cast<size_t>(written);
    } else {
      dst[di++] = static_cast<char>(ch);
    }
  }
  dst[di] = '\0';
}

void DtaLogger::SerializeDag(const TaintEngine* engine, uint32_t taint_id,
                             char* buf, size_t buf_size) {
  if (buf_size == 0) return;
  buf[0] = '\0';

  if (engine == nullptr || taint_id == 0) {
    snprintf(buf, buf_size, "[]");
    return;
  }

  std::vector<const FlowNode*> dag = engine->CollectAncestorDAG(taint_id);
  if (dag.empty()) {
    snprintf(buf, buf_size, "[]");
    return;
  }

  size_t pos = 0;
  auto safe_append = [&](const char* s) {
    size_t len = strlen(s);
    if (pos + len < buf_size) {
      memcpy(buf + pos, s, len);
      pos += len;
      buf[pos] = '\0';
    }
  };

  safe_append("[");
  for (size_t i = 0; i < dag.size(); ++i) {
    const FlowNode* node = dag[i];
    if (node == nullptr) continue;

    const char* type_str = "D";
    if (node->type == FlowNodeType::kSource) type_str = "S";
    else if (node->type == FlowNodeType::kTransform) type_str = "T";

    char escaped_op[256];
    EscapeJsonString(node->operation.c_str(), escaped_op, sizeof(escaped_op));

    char node_buf[512];
    int n;
    if (node->location.empty()) {
      n = snprintf(node_buf, sizeof(node_buf),
                   "%s{\"id\":%u,\"op\":\"%s\",\"ty\":\"%s\",\"p\":[",
                   i > 0 ? "," : "", node->id, escaped_op, type_str);
    } else {
      char escaped_loc[128];
      EscapeJsonString(node->location.c_str(), escaped_loc, sizeof(escaped_loc));
      n = snprintf(node_buf, sizeof(node_buf),
                   "%s{\"id\":%u,\"op\":\"%s\",\"loc\":\"%s\",\"ty\":\"%s\",\"p\":[",
                   i > 0 ? "," : "", node->id, escaped_op, escaped_loc, type_str);
    }
    if (n > 0) safe_append(node_buf);

    for (size_t j = 0; j < node->parents.size(); ++j) {
      char pbuf[32];
      snprintf(pbuf, sizeof(pbuf), "%s%u", j > 0 ? "," : "",
               node->parents[j]);
      safe_append(pbuf);
    }
    safe_append("]}");

    // Safety: check if we're running out of space
    if (pos + 64 >= buf_size) {
      // Truncate gracefully
      if (pos + 2 < buf_size) {
        buf[pos++] = ']';
        buf[pos] = '\0';
      }
      return;
    }
  }
  safe_append("]");
}

void DtaLogger::WriteJsonLine(const char* json_str) {
  if (json_file_ != nullptr) {
    fprintf(json_file_, "%s\n", json_str);
  }
}

void DtaLogger::WriteText(const char* text) {
  fprintf(stderr, "%s", text);
}

void DtaLogger::PrintDagText(TaintEngine* engine, uint32_t taint_id) {
  if (engine == nullptr || taint_id == 0) return;
  const FlowNode* node = engine->GetNode(taint_id);
  if (node == nullptr) return;

  char line[256];
  snprintf(line, sizeof(line), "    === Flow DAG (T%u) ===\n", taint_id);
  WriteText(line);
  PrintDagTextRecursive(engine, taint_id, "    ", true);
}

void DtaLogger::PrintDagTextRecursive(TaintEngine* engine,
                                      uint32_t node_id, const char* prefix,
                                      bool is_last) {
  const FlowNode* node = engine->GetNode(node_id);
  if (node == nullptr) return;

  const char* type_str = "[Derive]";
  if (node->type == FlowNodeType::kSource) type_str = "[Source]";
  else if (node->type == FlowNodeType::kTransform) type_str = "[Transform]";

  char line[512];
  snprintf(line, sizeof(line), "%s%s [%u] %s %s\n", prefix,
           is_last ? "\\-- " : "|-- ", node->id, node->operation.c_str(),
           type_str);
  WriteText(line);

  char new_prefix[256];
  snprintf(new_prefix, sizeof(new_prefix), "%s%s", prefix,
           is_last ? "    " : "|   ");

  for (size_t i = 0; i < node->parents.size(); ++i) {
    bool last_child = (i == node->parents.size() - 1);
    PrintDagTextRecursive(engine, node->parents[i], new_prefix, last_child);
  }
}

// =========================================================================
// Alert Layer (Level >= kAlert)
// =========================================================================

void DtaLogger::Alert(int cwe, const char* sink,
                      const std::vector<std::pair<int, uint32_t>>& tainted_args,
                      TaintEngine* engine) {
  if (level_ < Level::kAlert) return;

  if (IsJsonMode()) {
    char buf[262144];
    size_t pos = 0;
    uint64_t ts = NowMs();

    char escaped_sink[256];
    EscapeJsonString(sink, escaped_sink, sizeof(escaped_sink));

    int n = snprintf(buf, sizeof(buf),
                     "{\"ts\":%lu,\"t\":\"alert\",\"cwe\":%d,"
                     "\"sink\":\"%s\",\"args\":[",
                     static_cast<unsigned long>(ts), cwe, escaped_sink);
    if (n > 0) pos = static_cast<size_t>(n);

    for (size_t i = 0; i < tainted_args.size(); ++i) {
      char arg_buf[64];
      snprintf(arg_buf, sizeof(arg_buf), "%s{\"i\":%d,\"tid\":%u}",
               i > 0 ? "," : "", tainted_args[i].first,
               tainted_args[i].second);
      size_t len = strlen(arg_buf);
      if (pos + len < sizeof(buf)) {
        memcpy(buf + pos, arg_buf, len);
        pos += len;
      }
    }
    {
      const char* s = "],\"dag\":{";
      size_t len = strlen(s);
      if (pos + len < sizeof(buf)) {
        memcpy(buf + pos, s, len);
        pos += len;
      }
    }

    // Collect unique taint_ids and serialize DAGs
    bool first_dag = true;
    std::vector<uint32_t> seen_ids;
    for (const auto& arg : tainted_args) {
      uint32_t tid = arg.second;
      if (tid == 0) continue;
      bool already_seen = false;
      for (uint32_t seen : seen_ids) {
        if (seen == tid) { already_seen = true; break; }
      }
      if (already_seen) continue;
      seen_ids.push_back(tid);

      char dag_buf[65536];
      SerializeDag(engine, tid, dag_buf, sizeof(dag_buf));

      char key_buf[32];
      snprintf(key_buf, sizeof(key_buf), "%s\"%u\":",
               first_dag ? "" : ",", tid);
      first_dag = false;

      size_t key_len = strlen(key_buf);
      size_t dag_len = strlen(dag_buf);
      if (pos + key_len + dag_len < sizeof(buf)) {
        memcpy(buf + pos, key_buf, key_len);
        pos += key_len;
        memcpy(buf + pos, dag_buf, dag_len);
        pos += dag_len;
      }

      // Check if we're running out of space
      if (pos + 256 >= sizeof(buf)) {
        if (pos + 32 < sizeof(buf)) {
          int tn = snprintf(buf + pos, sizeof(buf) - pos,
                            "},\"dag_truncated\":true}");
          if (tn > 0) pos += static_cast<size_t>(tn);
          buf[pos] = '\0';
          WriteJsonLine(buf);
          fflush(json_file_);
          return;
        }
        break;
      }
    }
    {
      const char* s = "}}";
      size_t len = strlen(s);
      if (pos + len < sizeof(buf)) {
        memcpy(buf + pos, s, len);
        pos += len;
      }
    }
    buf[pos] = '\0';
    WriteJsonLine(buf);
    fflush(json_file_);
  } else {
    // Text mode
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));

    char line[1024];
    size_t pos = 0;
    pos += snprintf(line + pos, sizeof(line) - pos,
                    "%s [ALERT] CWE-%d | Sink: %s | Args:", ts_buf, cwe, sink);

    for (const auto& arg : tainted_args) {
      if (pos + 32 < sizeof(line)) {
        pos += snprintf(line + pos, sizeof(line) - pos, " arg[%d]=T%u",
                        arg.first, arg.second);
      }
    }
    pos += snprintf(line + pos, sizeof(line) - pos, "\n");
    WriteText(line);

    // Print DAGs for each unique taint_id
    std::vector<uint32_t> seen_ids;
    for (const auto& arg : tainted_args) {
      uint32_t tid = arg.second;
      if (tid == 0) continue;
      bool already_seen = false;
      for (uint32_t seen : seen_ids) {
        if (seen == tid) { already_seen = true; break; }
      }
      if (already_seen) continue;
      seen_ids.push_back(tid);
      PrintDagText(engine, tid);
    }
  }
}

void DtaLogger::AlertBytecode(int cwe, const char* sink, uint32_t taint_id,
                               TaintEngine* engine) {
  if (level_ < Level::kAlert) return;

  std::vector<std::pair<int, uint32_t>> args;
  args.push_back({0, taint_id});
  Alert(cwe, sink, args, engine);
}

// =========================================================================
// Info Layer (Level >= kInfo)
// =========================================================================

void DtaLogger::Gap(const char* api, const char* ns) {
  if (level_ < Level::kInfo) return;

  if (IsJsonMode()) {
    char buf[4096];
    char escaped_api[512];
    char escaped_ns[256];
    EscapeJsonString(api, escaped_api, sizeof(escaped_api));
    EscapeJsonString(ns, escaped_ns, sizeof(escaped_ns));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"gap\",\"api\":\"%s\",\"ns\":\"%s\"}",
             static_cast<unsigned long>(NowMs()), escaped_api, escaped_ns);
    WriteJsonLine(buf);
    fflush(json_file_);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[1024];
    snprintf(line, sizeof(line), "%s [GAP] Missing model: %s (%s)\n", ts_buf,
             api, ns);
    WriteText(line);
  }
}

void DtaLogger::InitReport(int v8_native, int v8_runtime, int node, int hof,
                            int bytecode) {
  if (level_ < Level::kInfo) return;

  if (IsJsonMode()) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"init\",\"v8_native\":%d,\"v8_runtime\":%d,"
             "\"node\":%d,\"hof\":%d,\"bytecode\":%d}",
             static_cast<unsigned long>(NowMs()), v8_native, v8_runtime, node,
             hof, bytecode);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line),
             "%s [INIT] Rules: V8_native=%d V8_runtime=%d Node=%d HOF=%d "
             "Bytecode=%d\n",
             ts_buf, v8_native, v8_runtime, node, hof, bytecode);
    WriteText(line);
  }
}

void DtaLogger::Warn(const char* msg) {
  if (level_ < Level::kInfo) return;

  if (IsJsonMode()) {
    char buf[4096];
    char escaped[3072];
    EscapeJsonString(msg, escaped, sizeof(escaped));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"warn\",\"msg\":\"%s\"}",
             static_cast<unsigned long>(NowMs()), escaped);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[4096];
    snprintf(line, sizeof(line), "%s [WARN] %s\n", ts_buf, msg);
    WriteText(line);
  }
}

void DtaLogger::Error(const char* msg) {
  if (level_ < Level::kInfo) return;

  if (IsJsonMode()) {
    char buf[4096];
    char escaped[3072];
    EscapeJsonString(msg, escaped, sizeof(escaped));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"error\",\"msg\":\"%s\"}",
             static_cast<unsigned long>(NowMs()), escaped);
    WriteJsonLine(buf);
    fflush(json_file_);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[4096];
    snprintf(line, sizeof(line), "%s [ERROR] %s\n", ts_buf, msg);
    WriteText(line);
    fflush(stderr);
  }
}

// =========================================================================
// Debug Layer Impl (Level >= kDebug)
// =========================================================================

void DtaLogger::ClassifyImpl(const char* name, const char* category,
                              bool has_rules) {
  if (IsJsonMode()) {
    char buf[4096];
    char escaped_name[1024];
    char escaped_cat[256];
    EscapeJsonString(name, escaped_name, sizeof(escaped_name));
    EscapeJsonString(category, escaped_cat, sizeof(escaped_cat));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"classify\",\"target\":\"%s\","
             "\"cat\":\"%s\",\"rules\":%s}",
             static_cast<unsigned long>(NowMs()), escaped_name, escaped_cat,
             has_rules ? "true" : "false");
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[1024];
    snprintf(line, sizeof(line), "%s [CLASSIFY] %s: %s has_rules=%d\n", ts_buf,
             category, name, has_rules ? 1 : 0);
    WriteText(line);
  }
}

void DtaLogger::RuleImpl(const char* sig, bool found, int argc,
                          const uintptr_t* addrs, const uint32_t* taints) {
  if (IsJsonMode()) {
    char buf[4096];
    char escaped_sig[512];
    EscapeJsonString(sig, escaped_sig, sizeof(escaped_sig));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"rule\",\"sig\":\"%s\",\"found\":%s,"
             "\"argc\":%d}",
             static_cast<unsigned long>(NowMs()), escaped_sig,
             found ? "true" : "false", argc);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[2048];
    size_t pos = 0;
    pos += snprintf(line + pos, sizeof(line) - pos,
                    "%s [RULE] %s found=%d argc=%d", ts_buf, sig,
                    found ? 1 : 0, argc);
    if (addrs != nullptr && taints != nullptr) {
      for (int i = 0; i < argc && pos + 64 < sizeof(line); ++i) {
        pos += snprintf(line + pos, sizeof(line) - pos,
                        " | arg[%d] addr=0x%lx taint=%u", i,
                        static_cast<unsigned long>(addrs[i]), taints[i]);
      }
    }
    pos += snprintf(line + pos, sizeof(line) - pos, "\n");
    WriteText(line);
  }
}

void DtaLogger::CollectImpl(int rt_idx, int offset, uintptr_t addr,
                             uint32_t taint) {
  if (IsJsonMode()) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"collect\",\"rt_idx\":%d,\"offset\":%d,"
             "\"addr\":\"0x%lx\",\"taint\":%u}",
             static_cast<unsigned long>(NowMs()), rt_idx, offset,
             static_cast<unsigned long>(addr), taint);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line),
             "%s [COLLECT] rt_idx=%d offset=%d addr=0x%lx taint=%u\n", ts_buf,
             rt_idx, offset, static_cast<unsigned long>(addr), taint);
    WriteText(line);
  }
}

void DtaLogger::ScatterImpl(uintptr_t addr, uintptr_t key, uint32_t taint,
                             int base) {
  if (IsJsonMode()) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"scatter\",\"addr\":\"0x%lx\","
             "\"key\":\"0x%lx\",\"taint\":%u,\"base\":%d}",
             static_cast<unsigned long>(NowMs()),
             static_cast<unsigned long>(addr),
             static_cast<unsigned long>(key), taint, base);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line),
             "%s [SCATTER] addr=0x%lx key=0x%lx taint=%u sink.base=%d\n",
             ts_buf, static_cast<unsigned long>(addr),
             static_cast<unsigned long>(key), taint, base);
    WriteText(line);
  }
}

void DtaLogger::ScatterFailImpl(int base, int index) {
  if (IsJsonMode()) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"scatter_fail\",\"base\":%d,\"index\":%d}",
             static_cast<unsigned long>(NowMs()), base, index);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line),
             "%s [SCATTER] FAILED target_addr=0 sink.base=%d sink.index=%d\n",
             ts_buf, base, index);
    WriteText(line);
  }
}

void DtaLogger::BinOpImpl(uint32_t left, uint32_t right, const char* op,
                           uint32_t result, uintptr_t result_addr) {
  if (IsJsonMode()) {
    char buf[4096];
    char escaped_op[64];
    EscapeJsonString(op, escaped_op, sizeof(escaped_op));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"binop\",\"left\":%u,\"right\":%u,"
             "\"op\":\"%s\",\"result\":%u}",
             static_cast<unsigned long>(NowMs()), left, right, escaped_op,
             result);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line),
             "%s [BINOP] PropagateBinaryOp(%u, %u, %s) -> %u "
             "result_addr=0x%lx\n",
             ts_buf, left, right, op, result,
             static_cast<unsigned long>(result_addr));
    WriteText(line);
  }
}

void DtaLogger::HofInjectImpl(const char* op, int param, uint32_t taint) {
  if (IsJsonMode()) {
    char buf[4096];
    char escaped_op[256];
    EscapeJsonString(op, escaped_op, sizeof(escaped_op));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"hof_inject\",\"op\":\"%s\",\"param\":%d,"
             "\"taint\":%u}",
             static_cast<unsigned long>(NowMs()), escaped_op, param, taint);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line), "%s [HOF-INJECT] %s param[%d] taint=%u\n",
             ts_buf, op, param, taint);
    WriteText(line);
  }
}

void DtaLogger::HofExtractImpl(const char* op, uint32_t taint) {
  if (IsJsonMode()) {
    char buf[4096];
    char escaped_op[256];
    EscapeJsonString(op, escaped_op, sizeof(escaped_op));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"hof_extract\",\"op\":\"%s\",\"taint\":%u}",
             static_cast<unsigned long>(NowMs()), escaped_op, taint);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line), "%s [HOF-EXTRACT] %s cb_ret_taint=%u\n",
             ts_buf, op, taint);
    WriteText(line);
  }
}

void DtaLogger::HofExtractAddrImpl(const char* op, uint32_t taint,
                                    uintptr_t addr) {
  if (IsJsonMode()) {
    char buf[4096];
    char escaped_op[256];
    EscapeJsonString(op, escaped_op, sizeof(escaped_op));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"hof_extract\",\"op\":\"%s\",\"taint\":%u,"
             "\"addr\":\"0x%lx\"}",
             static_cast<unsigned long>(NowMs()), escaped_op, taint,
             static_cast<unsigned long>(addr));
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line),
             "%s [HOF-EXTRACT] %s cb_ret_taint=%u -> obj=0x%lx\n", ts_buf, op,
             taint, static_cast<unsigned long>(addr));
    WriteText(line);
  }
}

void DtaLogger::HofInjectSkipImpl(int depth, int expected) {
  if (IsJsonMode()) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"hof_inject_skip\",\"depth\":%d,"
             "\"expected\":%d}",
             static_cast<unsigned long>(NowMs()), depth, expected);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[128];
    snprintf(line, sizeof(line),
             "%s [HOF-INJECT-SKIP] depth=%d expected=%d\n", ts_buf, depth,
             expected);
    WriteText(line);
  }
}

void DtaLogger::SkipBitmapDisabledImpl() {
  if (IsJsonMode()) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"skip_bitmap_disabled\"}",
             static_cast<unsigned long>(NowMs()));
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[128];
    snprintf(line, sizeof(line),
             "%s [DEBUG] Builtin skip bitmap DISABLED (all zeros)\n", ts_buf);
    WriteText(line);
  }
}

// =========================================================================
// Trace Layer Impl (Level >= kTrace)
// =========================================================================

void DtaLogger::FrameImpl(uintptr_t fp, int skip_idx, uint8_t old_val,
                           uint8_t new_val, int argc, uint32_t acc,
                           const uint32_t* buf, int buf_len) {
  if (IsJsonMode()) {
    char line[4096];
    size_t pos = 0;
    pos += snprintf(line + pos, sizeof(line) - pos,
                    "{\"ts\":%lu,\"t\":\"frame\",\"fp\":\"0x%lx\","
                    "\"skip_idx\":%d,\"old\":%u,\"new\":%u,\"argc\":%d,"
                    "\"acc\":%u,\"buf\":[",
                    static_cast<unsigned long>(NowMs()),
                    static_cast<unsigned long>(fp), skip_idx,
                    static_cast<unsigned>(old_val),
                    static_cast<unsigned>(new_val), argc, acc);
    if (buf != nullptr) {
      for (int i = 0; i < buf_len && pos + 16 < sizeof(line); ++i) {
        if (i > 0) pos += snprintf(line + pos, sizeof(line) - pos, ",");
        pos += snprintf(line + pos, sizeof(line) - pos, "%u", buf[i]);
      }
    }
    pos += snprintf(line + pos, sizeof(line) - pos, "]}");
    WriteJsonLine(line);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[2048];
    size_t pos = 0;
    pos += snprintf(
        line + pos, sizeof(line) - pos,
        "%s [PUSHFRAME] fp=0x%lx is_user=1 skip[%d]: 0x%02X -> 0x%02X "
        "arg_count=%d shadow_acc=%u buf=[",
        ts_buf, static_cast<unsigned long>(fp), skip_idx,
        static_cast<unsigned>(old_val), static_cast<unsigned>(new_val), argc,
        acc);
    if (buf != nullptr) {
      for (int i = 0; i < buf_len && pos + 16 < sizeof(line); ++i) {
        if (i > 0) pos += snprintf(line + pos, sizeof(line) - pos, ",");
        pos += snprintf(line + pos, sizeof(line) - pos, "%u", buf[i]);
      }
    }
    pos += snprintf(line + pos, sizeof(line) - pos, "]\n");
    WriteText(line);
  }
}

void DtaLogger::FrameHofImpl(uintptr_t fp, int call_top, uint32_t acc,
                              bool hof) {
  if (IsJsonMode()) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"frame_hof\",\"fp\":\"0x%lx\","
             "\"call_top\":%d,\"acc\":%u,\"hof\":%s}",
             static_cast<unsigned long>(NowMs()),
             static_cast<unsigned long>(fp), call_top, acc,
             hof ? "true" : "false");
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line),
             "%s [PUSHFRAME] fp=0x%lx hof_callback call_top=%d shadow_acc=%u "
             "hof=%d\n",
             ts_buf, static_cast<unsigned long>(fp), call_top, acc,
             hof ? 1 : 0);
    WriteText(line);
  }
}

void DtaLogger::ObjectDumpImpl(const char* type_name) {
  if (IsJsonMode()) {
    char buf[4096];
    char escaped[1024];
    EscapeJsonString(type_name, escaped, sizeof(escaped));
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"object_dump\",\"type\":\"%s\"}",
             static_cast<unsigned long>(NowMs()), escaped);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line), "%s [DUMP] Type: %s\n", ts_buf, type_name);
    WriteText(line);
  }
}

void DtaLogger::ApiGetTaintImpl(uintptr_t addr, uint32_t elem, uint32_t prop) {
  if (IsJsonMode()) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lu,\"t\":\"api_get_taint\",\"addr\":\"0x%lx\","
             "\"elem\":%u,\"prop\":%u}",
             static_cast<unsigned long>(NowMs()),
             static_cast<unsigned long>(addr), elem, prop);
    WriteJsonLine(buf);
  } else {
    char ts_buf[32];
    FormatTimestamp(ts_buf, sizeof(ts_buf));
    char line[256];
    snprintf(line, sizeof(line),
             "%s [DEBUG-API] getTaint addr=0x%lx ELEM_WILDCARD=%u "
             "PROP_WILDCARD=%u\n",
             ts_buf, static_cast<unsigned long>(addr), elem, prop);
    WriteText(line);
  }
}

}  // namespace dynalysis
