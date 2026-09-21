// Parse the driver and cc1 invocation only. Never create a compiler instance,
// frontend action, preprocessor, AST, or code-generation output.
#pragma once
#include "clang/Basic/DiagnosticFrontend.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/Job.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "llvm/TargetParser/Host.h"

class CheckDiagnostics : public clang::DiagnosticConsumer {
public:
  unsigned errors = 0;
  llvm::json::Array messages;
  std::set<std::string> unknown;
  std::map<std::string, std::set<std::string>> phases;
  std::string phase = "driver";
  void HandleDiagnostic(clang::DiagnosticsEngine::Level level,
                        const clang::Diagnostic &info) override {
    if (level >= clang::DiagnosticsEngine::Error) ++errors;
    llvm::SmallString<256> text;
    info.FormatDiagnostic(text);
    messages.push_back(llvm::json::Object{{"id", info.getID()},
        {"level", static_cast<int>(level)}, {"message", text.str().str()}});
    unsigned index = 0;
    if (info.getID() == clang::diag::warn_unknown_diag_option) index = 1;
    else if (info.getID() != clang::diag::err_drv_unknown_argument &&
             info.getID() != clang::diag::err_drv_unknown_argument_with_suggestion) return;
    if (info.getNumArgs() <= index) return;
    std::string spelling;
    if (info.getArgKind(index) == clang::DiagnosticsEngine::ak_std_string)
      spelling = info.getArgStdStr(index);
    else if (info.getArgKind(index) == clang::DiagnosticsEngine::ak_c_string)
      spelling = info.getArgCStr(index);
    if (!spelling.empty()) {
      unknown.insert(spelling);
      phases[spelling].insert(phase);
    }
  }
};

static int checkArguments(int argc, char **argv) {
  if (argc != 3) return 2;
  auto buffer = llvm::MemoryBuffer::getFile(argv[2]);
  if (!buffer) return 2;
  auto value = llvm::json::parse((*buffer)->getBuffer());
  if (!value) { llvm::consumeError(value.takeError()); return 2; }
  auto *job = value->getAsObject();
  if (!job || !job->getArray("arguments")) return 2;
  std::vector<std::string> arguments;
  for (auto &arg : *job->getArray("arguments")) {
    if (!arg.getAsString()) return 2;
    arguments.push_back(arg.getAsString()->str());
  }
  if (arguments.empty()) return 2;
  // Driver job construction itself has optional outputs (e.g. -MJ). Dry-run
  // mode suppresses those too, including when this API is called directly.
  auto terminator = std::find(arguments.begin(), arguments.end(), "--");
  arguments.insert(terminator, "-###");
  llvm::SmallVector<const char *, 32> pointers;
  for (auto &arg : arguments) pointers.push_back(arg.c_str());
  CheckDiagnostics consumer;
  llvm::IntrusiveRefCntPtr<clang::DiagnosticIDs> ids(new clang::DiagnosticIDs);
  llvm::IntrusiveRefCntPtr<clang::DiagnosticOptions> options(new clang::DiagnosticOptions);
  clang::DiagnosticsEngine diagnostics(ids, options, &consumer, false);
  clang::driver::Driver driver(arguments[0], llvm::sys::getDefaultTargetTriple(), diagnostics);
  driver.setCheckInputsExist(false);
  std::unique_ptr<clang::driver::Compilation> compilation(driver.BuildCompilation(pointers));
  // A driver error can prevent creation of cc1 jobs. Remove only its diagnosed
  // outer options for this non-executing probe so the same check also reports
  // frontend errors. The public command is still unchanged here.
  std::vector<std::string> driverArgs = arguments;
  llvm::SmallVector<const char *, 32> driverPointers;
  if (!consumer.unknown.empty()) {
    unsigned missingIndex = 0, missingCount = 0;
    auto parsed = clang::driver::getDriverOptTable().ParseArgs(
        llvm::ArrayRef<const char *>(pointers).drop_front(), missingIndex, missingCount);
    std::set<size_t> remove;
    for (const auto *arg : parsed) {
      size_t index = arg->getIndex() + 1;
      if (arg->getOption().getKind() != llvm::opt::Option::InputClass &&
          consumer.unknown.count(arguments[index])) remove.insert(index);
    }
    for (size_t i = 0; i < driverArgs.size(); ++i)
      if (!remove.count(i)) driverPointers.push_back(driverArgs[i].c_str());
    diagnostics.Reset();
    compilation.reset(driver.BuildCompilation(driverPointers));
  }
  llvm::json::Array targets;
  consumer.phase = "frontend";
  if (compilation) {
    for (const auto &command : compilation->getJobs()) {
      const auto &args = command.getArguments();
      if (args.empty() || llvm::StringRef(args.front()) != "-cc1") continue;
      clang::CompilerInvocation invocation;
      clang::CompilerInvocation::CreateFromArgs(invocation,
          llvm::ArrayRef<const char *>(args).drop_front(), diagnostics, arguments[0].c_str());
      // Do not let -w/-Wno-unknown-warning-option hide argument-check evidence.
      invocation.getDiagnosticOpts().IgnoreWarnings = false;
      invocation.getDiagnosticOpts().Warnings.push_back("unknown-warning-option");
      clang::ProcessWarningOptions(diagnostics, invocation.getDiagnosticOpts());
      targets.push_back(invocation.getTargetOpts().Triple);
    }
  }
  llvm::json::Array unknown;
  for (const auto &spelling : consumer.unknown) {
    llvm::json::Array positions;
    std::set<std::string> scopes;
    bool outer = consumer.phases[spelling].count("driver") || llvm::StringRef(spelling).starts_with("-W");
    bool forwarded = consumer.phases[spelling].count("frontend");
    unsigned missingIndex = 0, missingCount = 0;
    auto parsed = clang::driver::getDriverOptTable().ParseArgs(
        llvm::ArrayRef<const char *>(pointers).drop_front(), missingIndex, missingCount);
    for (const auto *arg : parsed) {
      if (arg->getOption().getKind() == llvm::opt::Option::InputClass) continue;
      size_t index = arg->getIndex() + 1;
      llvm::StringRef raw(arguments[index]);
      if (raw == spelling && outer) { positions.push_back(index); scopes.insert(""); }
      else if (forwarded && (raw == "-Xclang" || raw == "-Xpreprocessor") &&
               arg->getNumValues() == 1 && arg->getValue() == spelling) {
        positions.push_back(index + 1);
        scopes.insert(raw.str());
      } else if (forwarded && (raw == "-Xclang=" + spelling ||
               (raw.starts_with("-Wp,") && raw.contains(spelling)))) {
        positions.push_back(index);
        scopes.insert(raw.starts_with("-Wp,") ? "-Xpreprocessor" : "-Xclang");
      }
    }
    llvm::json::Array scopeValues;
    for (const auto &scope : scopes) scopeValues.push_back(scope);
    unknown.push_back(llvm::json::Object{{"spelling", spelling},
          {"scopes", std::move(scopeValues)}, {"argument_indices", std::move(positions)}});
  }
  llvm::outs() << llvm::json::Value(llvm::json::Object{
      {"protocol", "zscope.clang-arguments.v1"}, {"clang_version", CLANG_VERSION_STRING},
      {"policy_digest", ArgumentPolicySHA}, {"errors", consumer.errors},
      {"targets", std::move(targets)}, {"unknown_options", std::move(unknown)},
      {"diagnostics", std::move(consumer.messages)}}) << '\n';
  return 0; // Transport success. Compilation validity is in the structured result.
}
