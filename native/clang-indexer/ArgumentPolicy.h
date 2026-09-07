// Command compatibility is limited to warning promotion and one diagnosed retry.
#pragma once
#include "CompilerPolicy.h"

#include "clang/Basic/DiagnosticDriver.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Driver/Options.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Option/OptTable.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"
#include <map>
#include <chrono>
#include <set>
#include <string>
#include <vector>

static const llvm::json::Object &argumentPolicy() {
  static auto parsed = llvm::json::parse(ArgumentPolicyJSON);
  return *parsed->getAsObject();
}

static int argumentPolicyVersion() { return *argumentPolicy().getInteger("version"); }
static int argumentMaxAttempts() { return *argumentPolicy().getInteger("max_attempts"); }

class BatchDiagnostics : public clang::DiagnosticConsumer {
  llvm::IntrusiveRefCntPtr<clang::DiagnosticOptions> options{
      new clang::DiagnosticOptions()};
  clang::TextDiagnosticPrinter printer{llvm::errs(), options.get()};

public:
  unsigned errors = 0, warnings = 0;
  std::set<std::string> unknownOptions;

  void BeginSourceFile(const clang::LangOptions &lang,
                       const clang::Preprocessor *preprocessor) override {
    printer.BeginSourceFile(lang, preprocessor);
  }
  void EndSourceFile() override { printer.EndSourceFile(); }
  void HandleDiagnostic(clang::DiagnosticsEngine::Level level,
                        const clang::Diagnostic &info) override {
    clang::DiagnosticConsumer::HandleDiagnostic(level, info);
    printer.HandleDiagnostic(level, info);
    if (level == clang::DiagnosticsEngine::Warning) ++warnings;
    if (level < clang::DiagnosticsEngine::Error) return;
    ++errors; // Driver and frontend use different engines; keep our own total.
    if (info.getID() != clang::diag::err_drv_unknown_argument &&
        info.getID() != clang::diag::err_drv_unknown_argument_with_suggestion)
      return;
    if (!info.getNumArgs()) return;
    if (info.getArgKind(0) == clang::DiagnosticsEngine::ak_std_string)
      unknownOptions.insert(info.getArgStdStr(0));
    else if (info.getArgKind(0) == clang::DiagnosticsEngine::ak_c_string)
      unknownOptions.insert(info.getArgCStr(0));
  }
};

static llvm::json::Array stringsJSON(const std::vector<std::string> &values) {
  llvm::json::Array result;
  for (const auto &value : values) result.push_back(value);
  return result;
}

static bool expandArguments(std::vector<std::string> &arguments,
                            llvm::StringRef directory) {
  llvm::SmallVector<const char *, 32> pointers;
  for (const auto &argument : arguments) pointers.push_back(argument.c_str());
  llvm::BumpPtrAllocator allocator;
  llvm::cl::ExpansionContext expansion(allocator, llvm::cl::TokenizeGNUCommandLine);
  if (auto error = expansion.setCurrentDir(directory).expandResponseFiles(pointers)) {
    llvm::errs() << "error: " << llvm::toString(std::move(error)) << '\n';
    return false;
  }
  std::vector<std::string> expanded;
  for (const char *argument : pointers) expanded.emplace_back(argument);
  arguments = std::move(expanded);
  return true;
}

// Parse option boundaries so a path/value spelled '-Werror' is never removed.
// Unknown options have no known arity: do not guess and consume the next input.
static bool adjustOption(std::string &value, const std::set<std::string> &unknown,
                         std::vector<std::string> &ignoredWarningErrors,
                         std::vector<std::string> &removedUnknownOptions) {
  llvm::StringRef option(value);
  bool removeWarning = false;
  for (const auto &value : *argumentPolicy().getArray("remove_warning_options"))
    removeWarning |= value.getAsString() == option;
  auto errorPrefix = *argumentPolicy().getString("warning_error_prefix");
  if (removeWarning) {
    ignoredWarningErrors.push_back(value);
    return true;
  }
  if (option.starts_with(errorPrefix)) {
    ignoredWarningErrors.push_back(value);
    value = argumentPolicy().getString("warning_prefix")->str() + option.drop_front(errorPrefix.size()).str();
  } else if (unknown.count(value)) {
    removedUnknownOptions.push_back(value);
    return true;
  }
  return false;
}

static void adjustArguments(std::vector<std::string> &arguments,
                            const std::set<std::string> &unknown,
                            std::vector<std::string> &ignoredWarningErrors,
                            std::vector<std::string> &removedUnknownOptions) {
  llvm::SmallVector<const char *, 32> pointers;
  for (size_t i = 1; i < arguments.size(); ++i)
    pointers.push_back(arguments[i].c_str());
  unsigned missingIndex = 0, missingCount = 0;
  auto parsed = clang::driver::getDriverOptTable().ParseArgs(
      pointers, missingIndex, missingCount);
  // Forwarded options have their own operands, e.g. -Xclang -I -Xclang -Werror.
  // Parse each forwarded stream before deciding which tokens are options.
  std::set<std::pair<size_t, size_t>> forwardedOptions;
  for (const auto &item : *argumentPolicy().getArray("forwarded_options")) {
    llvm::StringRef forwarding = *item.getAsString();
    std::vector<std::string> values;
    std::vector<std::pair<size_t, size_t>> owners;
    for (const auto *argument : parsed) {
      if (argument->getOption().getKind() == llvm::opt::Option::InputClass) continue;
      size_t index = argument->getIndex() + 1;
      llvm::StringRef raw(arguments[index]);
      if (raw == forwarding && argument->getNumValues() == 1) {
        values.emplace_back(argument->getValue());
        owners.emplace_back(index, 0);
      } else if (forwarding == "-Xclang" && raw.starts_with("-Xclang=")) {
        values.push_back(raw.drop_front(8).str());
        owners.emplace_back(index, 0);
      } else if (forwarding == "-Xpreprocessor" && raw.starts_with("-Wp,")) {
        llvm::SmallVector<llvm::StringRef, 8> parts;
        raw.drop_front(4).split(parts, ',');
        for (size_t i = 0; i < parts.size(); ++i) {
          values.push_back(parts[i].str());
          owners.emplace_back(index, i);
        }
      }
    }
    llvm::SmallVector<const char *, 16> forwarded;
    for (const auto &value : values) forwarded.push_back(value.c_str());
    auto options = clang::driver::getDriverOptTable().ParseArgs(
        forwarded, missingIndex, missingCount);
    for (const auto *option : options)
      if (option->getOption().getKind() != llvm::opt::Option::InputClass)
        forwardedOptions.insert(owners[option->getIndex()]);
  }
  std::set<size_t> removed;
  std::map<size_t, std::string> replacements;
  for (const auto *argument : parsed) {
    if (argument->getOption().getKind() == llvm::opt::Option::InputClass) continue;
    size_t index = argument->getIndex() + 1;
    size_t valueIndex = index;
    std::string prefix;
    llvm::StringRef value(arguments[index]);
    if (value.starts_with("-Wp,")) {
      llvm::SmallVector<llvm::StringRef, 8> parts;
      value.drop_front(4).split(parts, ',');
      std::string replacement;
      for (size_t i = 0; i < parts.size(); ++i) {
        std::string part = parts[i].str();
        if (forwardedOptions.count({index, i}) &&
            adjustOption(part, unknown, ignoredWarningErrors, removedUnknownOptions))
          continue;
        replacement += (replacement.empty() ? "-Wp," : ",") + part;
      }
      if (replacement.empty()) removed.insert(index);
      else if (replacement != value) replacements[index] = std::move(replacement);
      continue;
    }
    if ((value == "-Xclang" || value == "-Xpreprocessor") &&
        argument->getNumValues() == 1 && index + 1 < arguments.size()) {
      if (!forwardedOptions.count({index, 0})) continue;
      valueIndex = index + 1;
      value = arguments[valueIndex];
    } else if (value.starts_with("-Xclang=")) {
      if (!forwardedOptions.count({index, 0})) continue;
      prefix = "-Xclang=";
      value = value.drop_front(prefix.size());
    }
    std::string replacement(value);
    bool erase = adjustOption(replacement, unknown, ignoredWarningErrors, removedUnknownOptions);
    if (!erase && replacement != value) replacements[valueIndex] = prefix + replacement;
    if (erase) {
      removed.insert(index);
      removed.insert(valueIndex);
    }
  }
  std::vector<std::string> adjusted;
  for (size_t i = 0; i < arguments.size(); ++i) {
    if (removed.count(i)) continue;
    const auto replacement = replacements.find(i);
    adjusted.push_back(replacement == replacements.end() ? arguments[i] : replacement->second);
  }
  arguments = std::move(adjusted);
}
