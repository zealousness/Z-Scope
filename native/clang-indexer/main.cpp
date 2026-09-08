// Z-SCOPE bulk facts protocol v1. One compile context per process.
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Index/IndexDataConsumer.h"
#include "clang/Index/IndexingAction.h"
#include "clang/Index/USRGeneration.h"
#include "clang/Lex/Lexer.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/HeaderSearch.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SHA256.h"
#include "llvm/ADT/StringExtras.h"
#include <algorithm>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "ArgumentPolicy.h"
#include "FunctionOwnership.h"

using namespace clang;
using namespace clang::tooling;
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;

static std::string absolute(llvm::StringRef path) {
  if (path.empty() || path.starts_with("<")) return "";
  llvm::SmallString<256> result(path);
  llvm::sys::fs::make_absolute(result);
  llvm::sys::path::remove_dots(result, true);
  return std::string(result);
}

struct Location {
  std::string file;
  unsigned line = 0, column = 0, offset = 0;
  Object json() const {
    return Object{{"file", file}, {"line", line}, {"column", column}, {"offset", offset}};
  }
};

struct FunctionRange {
  std::string name, usr, file;
  unsigned begin, end, line;
};

struct State {
  llvm::raw_ostream &output;
  std::string root;
  std::vector<std::string> includes, excludes;
  SourceManager *sm = nullptr;
  ASTContext *context = nullptr;
  std::set<std::string> dependencies, emitted, searchDirectories;
  Object dependencyDigests;
  mutable std::map<const NamedDecl *, std::string> definitionHashes;
  std::vector<FunctionRange> functions;
  FunctionOwnership functionOwners;
  std::vector<Object> macroUses;
  std::map<std::pair<std::string, unsigned>, std::string> referenceKinds;
  bool dependencyComplete = true;
  explicit State(llvm::raw_ostream &output) : output(output) {}

  static bool under(llvm::StringRef path, llvm::StringRef parent) {
    return path == parent || (path.starts_with(parent) && path.size() > parent.size() &&
                              (path[parent.size()] == '/' || path[parent.size()] == '\\'));
  }
  bool allowed(llvm::StringRef file) const {
    if (file.empty()) return false;
    for (const auto &excluded : excludes) if (under(file, excluded)) return false;
    if (includes.empty()) return under(file, root);
    for (const auto &included : includes) if (under(file, included)) return true;
    return false;
  }
  Location location(SourceLocation loc, bool spelling = false) const {
    if (!sm || loc.isInvalid()) return {};
    loc = spelling ? sm->getSpellingLoc(loc) : sm->getExpansionLoc(loc);
    auto fid = sm->getFileID(loc);
    auto entry = sm->getFileEntryRefForID(fid);
    if (!entry) return {};
    return {absolute(entry->getName()), sm->getLineNumber(fid, sm->getFileOffset(loc)),
            sm->getColumnNumber(fid, sm->getFileOffset(loc)), sm->getFileOffset(loc)};
  }
  std::string text(SourceRange range) const {
    if (!context || range.isInvalid()) return "";
    return Lexer::getSourceText(CharSourceRange::getTokenRange(range), *sm,
                                context->getLangOpts()).str();
  }
  std::string usr(const Decl *decl) const {
    llvm::SmallString<128> result;
    if (!decl || index::generateUSRForDecl(decl->getCanonicalDecl(), result)) return "";
    return std::string(result);
  }
  Object target(const NamedDecl *decl) const {
    const NamedDecl *definition = decl;
    if (const auto *var = dyn_cast<VarDecl>(decl)) {
      if (const auto *value = var->getDefinition()) definition = value;
    } else if (const auto *fn = dyn_cast<FunctionDecl>(decl)) {
      if (const auto *value = fn->getDefinition()) definition = value;
    } else if (const auto *tag = dyn_cast<TagDecl>(decl)) {
      if (const auto *value = tag->getDefinition()) definition = value;
    }
    std::string definitionHash;
    if (context && isa<TypeDecl>(definition)) {
      auto found = definitionHashes.find(definition);
      if (found == definitionHashes.end()) {
        std::string printed;
        llvm::raw_string_ostream stream(printed);
        definition->print(stream, context->getPrintingPolicy());
        stream.flush();
        auto digest = llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(
          reinterpret_cast<const uint8_t *>(printed.data()), printed.size()));
        found = definitionHashes.emplace(definition, llvm::toHex(digest, true)).first;
      }
      definitionHash = found->second;
    }
    return Object{{"usr", usr(decl)}, {"name", decl->getNameAsString()}, {"definition_hash", definitionHash},
            {"qualified_name", decl->getQualifiedNameAsString()},
            {"location", location(definition->getLocation(), true).json()},
            {"declaration", location(decl->getLocation(), true).json()}};
  }
  Object owner(const Location &loc) const {
    auto position = functionOwners.find(loc.file, loc.offset);
    if (position == FunctionOwnership::missing) return {};
    const auto *found = &functions[position];
    return Object{{"name", found->name}, {"usr", found->usr}, {"file", found->file}, {"line", found->line}};
  }
  void emit(Object object) { output << Value(std::move(object)) << '\n'; }
};

class Declarations : public RecursiveASTVisitor<Declarations> {
  State &state;
public:
  explicit Declarations(State &state) : state(state) {}
  bool shouldVisitTemplateInstantiations() const { return true; }
  bool VisitFunctionDecl(FunctionDecl *decl) {
    const auto loc = state.location(decl->getLocation());
    if (!state.allowed(loc.file) || decl->isImplicit()) return true;
    auto begin = state.location(decl->getBeginLoc()), end = state.location(decl->getEndLoc());
    std::string identity = state.usr(decl);
    if (!state.emitted.insert("function:" + identity + ":" + loc.file + ":" + std::to_string(loc.offset)).second) return true;
    std::string signature = state.text(decl->getSourceRange());
    if (decl->doesThisDeclarationHaveABody()) {
      auto body = state.location(decl->getBody()->getBeginLoc());
      if (body.file == begin.file && body.offset >= begin.offset && body.offset - begin.offset <= signature.size())
        signature.resize(body.offset - begin.offset);
      state.functions.push_back({decl->getQualifiedNameAsString(), identity, loc.file,
                                  begin.offset, end.offset, begin.line});
    }
    state.emit(Object{{"kind", "function"}, {"name", decl->getQualifiedNameAsString()},
                {"usr", identity}, {"location", loc.json()}, {"begin", begin.json()}, {"end", end.json()},
                {"signature", signature}, {"is_static", decl->getStorageClass() == SC_Static},
                {"is_inline", decl->isInlineSpecified()}, {"is_declaration", !decl->doesThisDeclarationHaveABody()}});
    return true;
  }
  bool VisitVarDecl(VarDecl *decl) {
    auto loc = state.location(decl->getLocation());
    if (!decl->isFileVarDecl() || !state.allowed(loc.file) || decl->isImplicit()) return true;
    state.emit(Object{{"kind", "global"}, {"target", state.target(decl)}, {"location", loc.json()},
                {"type", decl->getType().getAsString()}, {"is_extern", decl->getStorageClass() == SC_Extern},
                {"storage_class", decl->getStorageClass() == SC_Static ? "static" : decl->getStorageClass() == SC_Extern ? "extern" : decl->getTLSKind() != VarDecl::TLS_None ? "thread_local" : "global"},
                {"qualifiers", decl->getType().getQualifiers().getAsString()},
                {"initializer", decl->hasInit() ? state.text(decl->getInit()->getSourceRange()) : ""},
                {"definition_kind", decl->isThisDeclarationADefinition() == VarDecl::DeclarationOnly ? "declaration" : "definition"}});
    return true;
  }
  bool VisitTagDecl(TagDecl *decl) {
    if (!decl->isCompleteDefinition() || decl->isImplicit()) return true;
    auto loc = state.location(decl->getLocation());
    if (!state.allowed(loc.file) || decl->getName().empty()) return true;
    Array members;
    if (const auto *record = dyn_cast<RecordDecl>(decl))
      for (const auto *field : record->fields())
        members.push_back(Object{{"name", field->getNameAsString()}, {"type", field->getType().getAsString()}});
    if (const auto *enumeration = dyn_cast<EnumDecl>(decl))
      for (const auto *constant : enumeration->enumerators())
        members.push_back(Object{{"name", constant->getNameAsString()}, {"type", "enum_constant"}});
    state.emit(Object{{"kind", "type"}, {"type_kind", decl->isStruct() ? "struct" : decl->isUnion() ? "union" : decl->isEnum() ? "enum" : "class"},
                {"target", state.target(decl)}, {"begin", state.location(decl->getBeginLoc()).json()},
                {"end", state.location(decl->getEndLoc()).json()},
                {"definition", state.text(decl->getSourceRange())}, {"members", std::move(members)}});
    return true;
  }
  bool VisitTypedefNameDecl(TypedefNameDecl *decl) {
    if (decl->isImplicit() || !state.allowed(state.location(decl->getLocation()).file)) return true;
    Array members;
    if (const auto *recordType = decl->getUnderlyingType()->getAs<RecordType>())
      if (const auto *record = recordType->getDecl()->getDefinition())
        for (const auto *field : record->fields())
          members.push_back(Object{{"name", field->getNameAsString()}, {"type", field->getType().getAsString()}});
    state.emit(Object{{"kind", "type"}, {"type_kind", "typedef"}, {"target", state.target(decl)},
                {"begin", state.location(decl->getBeginLoc()).json()},
                {"end", state.location(decl->getEndLoc()).json()},
                {"definition", state.text(decl->getSourceRange())}, {"members", std::move(members)}});
    return true;
  }
};

// Classify compiler-resolved type positions without a second parse or a name lookup.
class TypeContexts : public RecursiveASTVisitor<TypeContexts> {
  State &state;
  std::string kind = "local";
public:
  explicit TypeContexts(State &state) : state(state) {}
  bool shouldVisitTemplateInstantiations() const { return true; }
  bool TraverseDecl(Decl *decl) {
    auto previous = kind;
    if (isa_and_nonnull<FunctionDecl>(decl)) kind = "return";
    else if (const auto *value = dyn_cast_or_null<VarDecl>(decl))
      kind = value->getType()->isFunctionPointerType() ? "function_pointer" :
             isa<ParmVarDecl>(value) ? "parameter" : "local";
    bool result = RecursiveASTVisitor::TraverseDecl(decl);
    kind = previous;
    return result;
  }
  bool TraverseStmt(Stmt *stmt) {
    auto previous = kind;
    if (isa_and_nonnull<CompoundStmt>(stmt)) kind = "local";
    else if (isa_and_nonnull<ExplicitCastExpr>(stmt)) kind = "cast";
    else if (isa_and_nonnull<CompoundLiteralExpr>(stmt)) kind = "compound_literal";
    else if (const auto *trait = dyn_cast_or_null<UnaryExprOrTypeTraitExpr>(stmt))
      kind = trait->getKind() == UETT_SizeOf ? "sizeof" : "alignof";
    else if (isa_and_nonnull<OffsetOfExpr>(stmt)) kind = "offsetof";
    bool result = RecursiveASTVisitor::TraverseStmt(stmt);
    kind = previous;
    return result;
  }
  bool VisitTypeLoc(TypeLoc type) {
    SourceLocation name = type.getBeginLoc();
    if (auto tag = type.getAs<TagTypeLoc>()) name = tag.getNameLoc();
    else if (auto alias = type.getAs<TypedefTypeLoc>()) name = alias.getNameLoc();
    auto loc = state.location(name);
    if (state.allowed(loc.file)) state.referenceKinds[{loc.file, loc.offset}] = kind;
    return true;
  }
  bool VisitMemberExpr(MemberExpr *expr) {
    auto loc = state.location(expr->getBase()->getBeginLoc());
    auto owner = state.owner(loc);
    if (!state.allowed(loc.file) || owner.empty()) return true;
    QualType type = expr->getBase()->getType().getNonReferenceType();
    if (expr->isArrow()) type = type->getPointeeType();
    const NamedDecl *decl = nullptr;
    if (!type.isNull()) {
      if (const auto *alias = dyn_cast<TypedefType>(type.getTypePtr())) decl = alias->getDecl();
      else if (const auto *record = type->getAs<RecordType>()) decl = record->getDecl();
    }
    if (decl) state.emit(Object{{"kind", "type_reference"}, {"owner", std::move(owner)},
      {"target", state.target(decl)}, {"location", loc.json()}, {"reference_kind", "member_access"}});
    return true;
  }
  bool VisitCallExpr(CallExpr *expr) {
    if (expr->getDirectCallee()) return true;
    auto loc = state.location(expr->getExprLoc());
    auto owner = state.owner(loc);
    if (!state.allowed(loc.file) || owner.empty()) return true;
    std::string expression = state.text(expr->getCallee()->getSourceRange());
    state.emit(Object{{"kind", "call"}, {"owner", std::move(owner)}, {"location", loc.json()},
      {"target", Object{{"usr", ""}, {"qualified_name", expression}, {"name", expression}, {"location", Location{}.json()}}},
      {"call_type", "indirect"}, {"callee_kind", "function_pointer"}, {"resolution_reason", "indirect_target"}});
    return true;
  }
};

class Occurrences : public index::IndexDataConsumer {
  State &state;
public:
  explicit Occurrences(State &state) : state(state) {}
  bool handleDeclOccurrence(const Decl *decl, index::SymbolRoleSet roles,
                            llvm::ArrayRef<index::SymbolRelation>, SourceLocation loc,
                            ASTNodeInfo node) override {
    if (!(roles & static_cast<unsigned>(index::SymbolRole::Reference))) return true;
    auto use = state.location(loc);
    if (!state.allowed(use.file)) return true;
    auto owner = state.owner(use);
    if (owner.empty()) return true;
    const auto *named = dyn_cast<NamedDecl>(decl);
    if (!named) return true;
    std::string kind;
    if (const auto *var = dyn_cast<VarDecl>(decl)) {
      if (!var->isFileVarDecl()) return true;
      kind = "symbol_reference";
    } else if (isa<TypeDecl>(decl)) kind = "type_reference";
    else if (isa<FunctionDecl>(decl) && (roles & static_cast<unsigned>(index::SymbolRole::Call))) kind = "call";
    else return true;
    bool read = roles & static_cast<unsigned>(index::SymbolRole::Read);
    bool write = roles & static_cast<unsigned>(index::SymbolRole::Write);
    std::string referenceKind = "local";
    if (node.OrigD && isa<ParmVarDecl>(node.OrigD)) referenceKind = "parameter";
    else if (node.OrigD && isa<FunctionDecl>(node.OrigD)) referenceKind = "return";
    auto context = state.referenceKinds.find({use.file, use.offset});
    if (context != state.referenceKinds.end()) referenceKind = context->second;
    state.emit(Object{{"kind", kind}, {"owner", std::move(owner)}, {"target", state.target(named)},
                {"location", use.json()}, {"spelling", state.location(loc, true).json()},
                {"roles", roles}, {"reference_kind", referenceKind},
                {"access_kind", write ? (read ? "read_write" : "write") : "read"}});
    return true;
  }
};

class Preprocessing : public PPCallbacks {
  State &state;
  Preprocessor &pp;
public:
  Preprocessing(State &state, Preprocessor &pp) : state(state), pp(pp) {}
  void FileChanged(SourceLocation loc, FileChangeReason, SrcMgr::CharacteristicKind,
                   FileID) override {
    auto position = state.location(loc);
    if (!position.file.empty()) {
      state.dependencies.insert(position.file);
      auto data = state.sm->getBufferData(state.sm->getFileID(state.sm->getExpansionLoc(loc)));
      auto digest = llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(
          reinterpret_cast<const uint8_t *>(data.data()), data.size()));
      state.dependencyDigests[position.file] = llvm::toHex(digest, true);
    }
  }
  void InclusionDirective(SourceLocation loc, const Token &, llvm::StringRef name, bool angled,
                           CharSourceRange, OptionalFileEntryRef file, llvm::StringRef,
                           llvm::StringRef, const Module *,
#if LLVM_VERSION_MAJOR >= 19
                           bool,
#endif
                           SrcMgr::CharacteristicKind) override {
    auto position = state.location(loc);
    if (file) state.dependencies.insert(absolute(file->getName()));
    else state.dependencyComplete = false;
    if (state.allowed(position.file)) state.emit(Object{{"kind", "include"}, {"location", position.json()},
      {"target_file", file ? absolute(file->getName()) : name.str()}, {"is_system", angled}});
  }
  void HasInclude(SourceLocation, llvm::StringRef, bool, OptionalFileEntryRef file,
                   SrcMgr::CharacteristicKind) override {
    // A negative search depends on search-directory membership, not just the
    // existing files. Conservatively disable cross-run reuse for such TUs.
    if (!file) state.dependencyComplete = false;
    else state.dependencies.insert(absolute(file->getName()));
  }
  std::string macroIdentity(llvm::StringRef name, const MacroInfo *info) {
    llvm::SmallString<128> result;
    index::generateUSRForMacro(name, info->getDefinitionLoc(), *state.sm, result);
    return std::string(result);
  }
  void MacroDefined(const Token &token, const MacroDirective *directive) override {
    const auto *info = directive->getMacroInfo();
    if (!info || !token.getIdentifierInfo()) return;
    auto begin = state.location(info->getDefinitionLoc(), true);
    if (!state.allowed(begin.file)) return;
    auto end = state.location(info->getDefinitionEndLoc(), true);
    std::string definition = Lexer::getSourceText(CharSourceRange::getTokenRange(
      info->getDefinitionLoc(), info->getDefinitionEndLoc()), *state.sm, pp.getLangOpts()).str();
    state.emit(Object{{"kind", "macro"}, {"name", token.getIdentifierInfo()->getName().str()},
                {"usr", macroIdentity(token.getIdentifierInfo()->getName(), info)},
                {"begin", begin.json()}, {"end", end.json()},
                {"definition", "#define " + definition}, {"is_function_like", info->isFunctionLike()}});
  }
  void MacroExpands(const Token &token, const MacroDefinition &definition, SourceRange range,
                     const MacroArgs *) override {
    const auto *info = definition.getMacroInfo();
    if (!info || !token.getIdentifierInfo()) return;
    auto use = state.location(range.getBegin());
    if (!state.allowed(use.file)) return;
    auto target = state.location(info->getDefinitionLoc(), true);
    if (target.file.empty()) return;
    state.macroUses.push_back(Object{{"kind", "macro_reference"},
      {"location", use.json()}, {"spelling", state.location(token.getLocation(), true).json()},
      {"target", Object{{"name", token.getIdentifierInfo()->getName().str()},
                         {"usr", macroIdentity(token.getIdentifierInfo()->getName(), info)},
                         {"location", target.json()}}}});
  }
};

#include "ProgramEvents.h"

class Consumer : public ASTConsumer {
  State &state;
  CompilerInstance &compiler;
public:
  Consumer(State &state, CompilerInstance &compiler) : state(state), compiler(compiler) {}
  void HandleTranslationUnit(ASTContext &context) override {
    state.context = &context;
    Declarations declarations(state);
    declarations.TraverseDecl(context.getTranslationUnitDecl());
    state.functionOwners.build(state.functions);
    ProgramEvents events(state);
    events.TraverseDecl(context.getTranslationUnitDecl());
    TypeContexts typeContexts(state);
    typeContexts.TraverseDecl(context.getTranslationUnitDecl());
    Occurrences occurrences(state);
    index::IndexingOptions options;
    options.IndexFunctionLocals = true;
    options.IndexImplicitInstantiation = true;
    options.IndexParametersInDeclarations = true;
    options.IndexTemplateParameters = true;
    options.SystemSymbolFilter = index::IndexingOptions::SystemSymbolFilterKind::All;
    std::vector<const Decl *> roots;
    for (const auto *decl : context.getTranslationUnitDecl()->decls()) roots.push_back(decl);
    index::indexTopLevelDecls(context, compiler.getPreprocessor(), roots, occurrences, options);
    for (auto &macro : state.macroUses) {
      const auto *position = macro.getObject("location");
      Location loc{position->getString("file")->str(), static_cast<unsigned>(*position->getInteger("line")),
                   static_cast<unsigned>(*position->getInteger("column")), static_cast<unsigned>(*position->getInteger("offset"))};
      auto owner = state.owner(loc);
      if (owner.empty()) continue;
      macro["owner"] = std::move(owner);
      state.emit(std::move(macro));
    }
  }
};

class Action : public ASTFrontendAction {
  State &state;
public:
  explicit Action(State &state) : state(state) {}
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &compiler, llvm::StringRef) override {
    state.sm = &compiler.getSourceManager();
    const auto &search = compiler.getPreprocessor().getHeaderSearchInfo();
    for (const auto &directory : search.search_dir_range()) {
      if (auto entry = directory.getDirRef())
        state.searchDirectories.insert(absolute(entry->getName()));
      else
        state.dependencyComplete = false; // Header maps/framework provenance requires a future schema.
    }
    compiler.getPreprocessor().addPPCallbacks(std::make_unique<Preprocessing>(state, compiler.getPreprocessor()));
    return std::make_unique<Consumer>(state, compiler);
  }
};

class Factory : public FrontendActionFactory {
  State &state;
public:
  explicit Factory(State &state) : state(state) {}
  std::unique_ptr<FrontendAction> create() override { return std::make_unique<Action>(state); }
};

class OneCommand : public CompilationDatabase {
  CompileCommand command;
public:
  explicit OneCommand(CompileCommand command) : command(std::move(command)) {}
  std::vector<CompileCommand> getCompileCommands(llvm::StringRef) const override { return {command}; }
  std::vector<std::string> getAllFiles() const override { return {command.Filename}; }
};

int main(int argc, char **argv) {
  if (argc == 2 && std::string(argv[1]) == "--version") {
    llvm::outs() << Value(Object{{"protocol", "zscope.clang-facts.v2"}, {"version", 2},
      {"clang_version", CLANG_VERSION_STRING}, {"position_encoding", "utf-8"},
      {"argument_policy_version", argumentPolicyVersion()},
      {"argument_policy_digest", ArgumentPolicySHA}}) << '\n';
    return 0;
  }
  if (argc != 5 || std::string(argv[1]) != "--job" || std::string(argv[3]) != "--output") {
    llvm::errs() << "usage: zscope-clang-indexer --job job.json --output facts.jsonl\n";
    return 2;
  }
  auto buffer = llvm::MemoryBuffer::getFile(argv[2]);
  if (!buffer) return 2;
  auto parsed = llvm::json::parse((*buffer)->getBuffer());
  if (!parsed) { llvm::consumeError(parsed.takeError()); return 2; }
  auto *job = parsed->getAsObject();
  if (!job || !job->getString("directory") || !job->getString("source") ||
      !job->getString("root") || !job->getArray("arguments")) return 2;
  std::vector<std::string> arguments;
  for (const auto &arg : *job->getArray("arguments")) {
    if (!arg.getAsString()) return 2;
    arguments.push_back(arg.getAsString()->str());
  }
  if (arguments.empty()) return 2;
  const auto originalArguments = arguments;
  if (!expandArguments(arguments, *job->getString("directory"))) return 2;
  std::vector<std::string> ignoredWarningErrors, removedUnknownOptions;
  adjustArguments(arguments, {}, ignoredWarningErrors, removedUnknownOptions);
  Array attempts;
  auto source = job->getString("source")->str();
  for (unsigned attempt = 1; attempt <= static_cast<unsigned>(argumentMaxAttempts()); ++attempt) {
    // A retry owns a fresh state and truncates the failed attempt's facts.
    std::error_code error;
    llvm::raw_fd_ostream output(argv[4], error);
    if (error) return 2;
    State state(output);
    state.root = absolute(*job->getString("root"));
    for (const auto *key : {"includes", "excludes"}) {
      if (const auto *paths = job->getArray(key))
        for (const auto &path : *paths) {
          if (!path.getAsString()) return 2;
          (std::string(key) == "includes" ? state.includes : state.excludes).push_back(absolute(*path.getAsString()));
        }
    }
    state.dependencies.insert(absolute(source));
    OneCommand database(CompileCommand(job->getString("directory")->str(), source, arguments, ""));
    ClangTool tool(database, {source});
    BatchDiagnostics diagnostics;
    tool.setDiagnosticConsumer(&diagnostics);
    Factory factory(state);
    state.emit(Object{{"kind", "header"}, {"protocol", "zscope.clang-facts.v2"},
                {"clang_version", CLANG_VERSION_STRING}, {"source", source}, {"position_encoding", "utf-8"}});
    auto attemptStarted = std::chrono::steady_clock::now();
    int result = tool.run(&factory);
    double attemptSeconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - attemptStarted).count();
    bool success = result == 0 && diagnostics.errors == 0;
    Array unknown;
    for (const auto &option : diagnostics.unknownOptions) unknown.push_back(option);
    attempts.push_back(Object{{"number", attempt}, {"tool_exit_code", result},
                            {"wall_seconds", attemptSeconds}, {"effective_arguments", stringsJSON(arguments)},
                            {"error_count", diagnostics.errors}, {"warning_count", diagnostics.warnings},
                            {"unknown_options", std::move(unknown)}});
    if (!success && attempt == 1 && !diagnostics.unknownOptions.empty()) {
      auto count = removedUnknownOptions.size();
      adjustArguments(arguments, diagnostics.unknownOptions, ignoredWarningErrors, removedUnknownOptions);
      if (removedUnknownOptions.size() > count) {
        llvm::errs() << "[clang-batch-arguments] retry=1 removed=";
        for (size_t i = count; i < removedUnknownOptions.size(); ++i)
          llvm::errs() << ' ' << removedUnknownOptions[i];
        llvm::errs() << '\n';
        continue;
      }
    }
    Array dependencies, searchDirectories;
    for (const auto &path : state.dependencies) dependencies.push_back(path);
    for (const auto &path : state.searchDirectories) searchDirectories.push_back(path);
    state.emit(Object{{"kind", "complete"}, {"success", success},
                {"dependencies_complete", state.dependencyComplete}, {"dependencies", std::move(dependencies)},
                {"dependency_digests", std::move(state.dependencyDigests)},
                {"search_directories", std::move(searchDirectories)},
                {"argument_adjustments", Object{{"policy_version", argumentPolicyVersion()},
                    {"policy_digest", ArgumentPolicySHA},
                    {"original_command", Object{{"directory", job->getString("directory")->str()},
                                                 {"source", source}, {"arguments", stringsJSON(originalArguments)}}},
                    {"ignored_warning_errors", stringsJSON(ignoredWarningErrors)},
                    {"removed_unknown_options", stringsJSON(removedUnknownOptions)},
                    {"effective_arguments", stringsJSON(arguments)},
                    {"attempts", std::move(attempts)}}}});
    output.flush();
    return success ? 0 : (result ? result : 1);
  }
  return 1;
}
