#pragma once

#include "llvm/ADT/DenseMap.h"
#include "PthreadCleanup.h"

// One CFG per function in the existing TU parse; never spawn per candidate.
class ProgramEvents : public RecursiveASTVisitor<ProgramEvents> {
  State &state;
  llvm::DenseMap<const Stmt *, bool> macroFlags;
  // Only immutable, internal-linkage tables with explicit function initializers.
  // No pointer chasing, writable table or incomplete target set is inferred.
  void closedTargets(const CallExpr *call, Object &identity) {
    const Expr *callee = call->getCallee()->IgnoreParenImpCasts();
    const Expr *base = nullptr;
    std::string selection;
    if (const auto *member = dyn_cast<MemberExpr>(callee)) {
      const auto *field = dyn_cast<FieldDecl>(member->getMemberDecl());
      if (member->isArrow() || !field || field->getParent()->isUnion()) return;
      base = member->getBase()->IgnoreParenImpCasts();
      selection = std::to_string(field->getFieldIndex());
    } else if (const auto *subscript = dyn_cast<ArraySubscriptExpr>(callee)) {
      base = subscript->getBase()->IgnoreParenImpCasts();
      selection = expression(subscript->getIdx());
    } else return;
    const auto *reference = dyn_cast<DeclRefExpr>(base);
    const auto *variable = reference ? dyn_cast<VarDecl>(reference->getDecl()) : nullptr;
    if (!variable || !variable->isFileVarDecl() || variable->hasExternalFormalLinkage() ||
        !variable->getType().isConstQualified() || variable->getType().isVolatileQualified() || !variable->hasInit() ||
        variable->getTLSKind() != VarDecl::TLS_None || variable->hasAttrs()) return;
    const auto *init = dyn_cast<InitListExpr>(variable->getInit()->IgnoreParenImpCasts());
    if (!init || init->getNumInits() == 0 || init->getNumInits() > 8 || init->hasArrayFiller()) return;
    Array targets;
    for (const Expr *item : init->inits()) {
      const QualType slotType = item->getType();
      item = item->IgnoreParenImpCasts();
      if (const auto *address = dyn_cast<UnaryOperator>(item)) {
        if (address->getOpcode() != UO_AddrOf) return;
        item = address->getSubExpr()->IgnoreParenImpCasts();
      }
      const auto *ref = dyn_cast<DeclRefExpr>(item);
      const auto *function = ref ? dyn_cast<FunctionDecl>(ref->getDecl()) : nullptr;
      if (!function || function->hasAttrs() || !slotType->isPointerType() ||
          !state.context->hasSameType(slotType->getPointeeType(), function->getType())) return;
      targets.push_back(state.target(function));
    }
    identity["closed_targets"] = Object{{"schema", "zscope.const-call-targets.v1"},
      {"table_usr", state.usr(variable)}, {"selection", selection},
      {"base", variable->getNameAsString()}, {"expression", expression(call->getCallee())},
      {"targets", std::move(targets)}};
  }
public:
  explicit ProgramEvents(State &value) : state(value) {}
  bool VisitFunctionDecl(FunctionDecl *decl) {
    if (!decl->doesThisDeclarationHaveABody() || decl->isImplicit()) return true;
    auto loc = state.location(decl->getLocation());
    if (!state.allowed(loc.file)) return true;
    CFG::BuildOptions options;
    options.AddImplicitDtors = true;
    options.AddTemporaryDtors = true;
    options.AddEHEdges = true;
    auto cfg = CFG::buildCFG(decl, decl->getBody(), state.context, options);
    PthreadCleanup cleanup(state, decl);
    Array events, edges, parameters;
    for (unsigned index = 0; index < decl->getNumParams(); ++index) {
      const auto *parameter = decl->getParamDecl(index);
      auto identity = valueIdentity(parameter, nullptr);
      identity["index"] = index;
      const auto *record = parameter->getType()->isPointerType()
        ? parameter->getType()->getPointeeType()->getAsRecordDecl() : nullptr;
      identity["pointee_record_kind"] = record ? (record->isUnion() ? "union" : "struct") : "";
      identity["pointee_record_usr"] = record ? state.usr(record->getCanonicalDecl()) : "";
      parameters.push_back(std::move(identity));
    }
    if (cfg) {
      for (const auto *block : *cfg) {
        unsigned ordinal = 0;
        for (const auto &element : *block) {
          if (auto destructor = element.getAs<CFGAutomaticObjDtor>()) {
            auto *var = destructor->getVarDecl();
            auto *trigger = destructor->getTriggerStmt();
            events.push_back(Object{{"event_kind", "implicit_release"}, {"resource_family", "cxx_object"},
              {"block", block->getBlockID()}, {"ordinal", ordinal++}, {"object", state.target(var)},
              {"destructor", state.target(destructor->getDestructorDecl(*state.context))},
              {"location", state.location(trigger->getEndLoc()).json()}, {"ast_kind", "AutomaticObjectDtor"},
              {"expression", var->getNameAsString()}});
            continue;
          }
          if (auto destructor = element.getAs<CFGTemporaryDtor>()) {
            auto *expr = destructor->getBindTemporaryExpr();
            events.push_back(Object{{"event_kind", "implicit_release"}, {"resource_family", "cxx_temporary"},
              {"block", block->getBlockID()}, {"ordinal", ordinal++},
              {"destructor", state.target(destructor->getDestructorDecl(*state.context))},
              {"location", state.location(expr->getEndLoc()).json()}, {"ast_kind", "TemporaryDtor"},
              {"expression", expression(expr)}});
            continue;
          }
          auto statement = element.getAs<CFGStmt>();
          if (!statement) continue;
          const Stmt *stmt = statement->getStmt();
          auto begin = state.location(stmt->getBeginLoc());
          std::string kind = "statement", family, operation;
          Object object, calleeIdentity;
          Array argumentObjects, argumentExpressions, argumentUses, defs, uses;
          std::string returnValue, assignmentTarget, assignmentValue;
          if (const auto *declaration = dyn_cast<DeclStmt>(stmt)) {
            for (const auto *declared : declaration->decls()) {
              const auto *var = dyn_cast<VarDecl>(declared);
              if (!var) continue;
              auto definition = valueIdentity(var, nullptr);
              if (var->hasInit()) {
                if (const auto *construct = dyn_cast<CXXConstructExpr>(var->getInit()->IgnoreParenImpCasts())) {
                  const auto *record = construct->getConstructor()->getParent();
                  definition["construction"] = Object{
                    {"constructor", state.target(construct->getConstructor())},
                    {"destructor", record->getDestructor() ? state.target(record->getDestructor()) : Object{}},
                    {"record", state.target(record)},
                    {"automatic_storage", var->hasLocalStorage() && !var->isStaticLocal()},
                    {"complete_object", construct->getConstructionKind() == CXXConstructionKind::Complete}};
                }
              }
              defs.push_back(std::move(definition));
              if (var->hasInit()) {
                kind = "declaration_initializer";
                assignmentTarget = var->getNameAsString();
                assignmentValue = expression(var->getInit());
                appendValues(uses, var->getInit());
              }
            }
          } else if (const auto *allocation = dyn_cast<CXXNewExpr>(stmt)) {
            kind = "acquire";
            object = acquisitionIdentity(allocation);
            if (!object.empty()) defs.push_back(acquisitionIdentity(allocation));
            family = allocation->isArray() ? "new_array" : "new_scalar";
            if (allocation->getNumPlacementArgs() || (allocation->getOperatorNew() &&
                !allocation->getOperatorNew()->isReplaceableGlobalAllocationFunction())) family = "custom_allocation";
          } else if (const auto *release = dyn_cast<CXXDeleteExpr>(stmt)) {
            kind = "release";
            family = release->isArrayForm() ? "new_array" : "new_scalar";
            object = objectIdentity(release->getArgument());
            operation = std::string(release->isArrayForm() ? "delete[] " : "delete ") + expression(release->getArgument());
            appendValues(uses, release->getArgument());
          } else if (const auto *call = dyn_cast<CallExpr>(stmt)) {
            kind = "call";
            object = acquisitionIdentity(call);
            if (!object.empty()) defs.push_back(acquisitionIdentity(call));
            if (const auto *callee = call->getDirectCallee()) {
              calleeIdentity = state.target(callee);
              operation = callee->getQualifiedNameAsString();
            } else {
              calleeIdentity = objectIdentity(call->getCallee());
              closedTargets(call, calleeIdentity);
              operation = expression(call->getCallee());
            }
            operation += "(";
            for (unsigned i = 0; i < call->getNumArgs(); ++i) {
              if (i) operation += ", ";
              operation += expression(call->getArg(i));
              argumentObjects.push_back(objectIdentity(call->getArg(i)));
              argumentExpressions.push_back(expression(call->getArg(i)));
              Array oneArgumentUses;
              appendValues(oneArgumentUses, call->getArg(i));
              argumentUses.push_back(std::move(oneArgumentUses));
              appendValues(uses, call->getArg(i));
            }
            operation += ")";
          } else if (const auto *returned = dyn_cast<ReturnStmt>(stmt)) {
            kind = "return";
            if (returned->getRetValue()) {
              returnValue = expression(returned->getRetValue());
              appendValues(uses, returned->getRetValue());
            }
          } else if (const auto *assignment = dyn_cast<BinaryOperator>(stmt)) {
            if (assignment->isAssignmentOp()) {
              kind = assignment->isCompoundAssignmentOp() ? "compound_assignment" : "assignment";
              assignmentTarget = expression(assignment->getLHS());
              assignmentValue = expression(assignment->getRHS());
              defs.push_back(objectIdentity(assignment->getLHS()));
              appendValues(uses, assignment->getRHS());
              if (assignment->isCompoundAssignmentOp()) appendValues(uses, assignment->getLHS());
            }
          } else if (const auto *unary = dyn_cast<UnaryOperator>(stmt)) {
            if (unary->isIncrementDecrementOp()) {
              kind = "increment_decrement";
              defs.push_back(objectIdentity(unary->getSubExpr()));
              appendValues(uses, unary->getSubExpr());
            } else appendValues(uses, stmt);
          } else {
            appendValues(uses, stmt);
          }
          unsigned nestedCalls = 0;
          nestedCalls = appendNestedCallEvents(events, stmt, block->getBlockID(), ordinal, cleanup);
          bool directNestedCallTransfer = false;
          if (const auto *declaration = dyn_cast<DeclStmt>(stmt)) {
            const VarDecl *initialized = nullptr;
            for (const auto *declared : declaration->decls()) {
              const auto *var = dyn_cast<VarDecl>(declared);
              if (!var || !var->hasInit()) continue;
              if (initialized) {
                initialized = nullptr;
                break;
              }
              initialized = var;
            }
            directNestedCallTransfer = initialized &&
              isa<CallExpr>(initialized->getInit()->IgnoreParenImpCasts());
          } else if (const auto *assignment = dyn_cast<BinaryOperator>(stmt)) {
            directNestedCallTransfer = assignment->isAssignmentOp() &&
              isa<CallExpr>(assignment->getRHS()->IgnoreParenImpCasts());
          }
          // A nested call already represents the value transfer into the
          // declaration/assignment target only when the call is the entire
          // RHS. A call embedded in a larger expression needs the outer event.
          if (nestedCalls && (kind == "declaration_initializer" || kind == "assignment" ||
                              kind == "compound_assignment") && directNestedCallTransfer)
            continue;
          std::string eventId = std::to_string(block->getBlockID()) + ":" + std::to_string(ordinal);
          const auto *constant = dyn_cast<Expr>(stmt);
          if (const auto *returned = dyn_cast<ReturnStmt>(stmt)) constant = returned->getRetValue();
          bool nullConstant = constant && constant->isNullPointerConstant(
            *state.context, Expr::NPC_ValueDependentIsNotNull) != Expr::NPCK_NotNull;
          const bool waitConstantMacro = containsMacro(stmt) && waitConstantOnlyMacros(stmt);
          events.push_back(Object{{"event_id", eventId}, {"event_kind", kind}, {"resource_family", family},
            {"block", block->getBlockID()}, {"ordinal", ordinal++},
            {"location", begin.json()}, {"end", state.location(stmt->getEndLoc()).json()},
            {"ast_kind", stmt->getStmtClassName()}, {"expression", state.text(stmt->getSourceRange())},
            {"operation", operation}, {"object", std::move(object)},
            {"callee", std::move(calleeIdentity)}, {"arguments", std::move(argumentExpressions)},
            {"return_value", returnValue}, {"assignment_target", assignmentTarget},
            {"assignment_value", assignmentValue},
            {"argument_objects", std::move(argumentObjects)}, {"argument_uses", std::move(argumentUses)},
            {"defs", std::move(defs)},
            {"uses", std::move(uses)}, {"macro_expansion", stmt->getBeginLoc().isMacroID()},
            {"contains_macro", containsMacro(stmt)}, {"null_pointer_constant", nullConstant},
            {"pthread_timed_wait", timedWait(dyn_cast<CallExpr>(stmt))},
            {"pthread_wait_constant_macro", waitConstantMacro},
            {"pthread_wait_constant_expression", waitConstantMacro && isa<Expr>(stmt) ? expression(cast<Expr>(stmt)) : ""},
            {"pthread_cleanup", cleanup.marker(stmt)}});
        }
        unsigned successorIndex = 0;
        const auto *condition = dyn_cast_or_null<Expr>(block->getTerminatorCondition());
        for (auto successor : block->succs()) {
          if (const auto *target = successor.getReachableBlock()) {
            Array conditionUses;
            if (condition) appendValues(conditionUses, condition);
            edges.push_back(Object{{"from", block->getBlockID()}, {"to", target->getBlockID()},
              {"condition", condition ? expression(condition) : ""},
              {"condition_uses", std::move(conditionUses)},
              {"pthread_cleanup", cleanup.marker(condition)},
              {"branch", condition && block->succ_size() == 2 &&
                !isa_and_nonnull<SwitchStmt>(block->getTerminatorStmt())
                ? (successorIndex == 0 ? "true" : "false") : "unknown"}});
          }
          ++successorIndex;
        }
      }
    }
    state.emit(Object{{"kind", "program_function"}, {"owner", state.owner(loc)},
      {"callable", state.target(decl)}, {"linkage_facts_version", "zscope.c-linkage.v1"},
      {"location", loc.json()}, {"complete", bool(cfg)}, {"events", std::move(events)},
      {"cfg_edges", std::move(edges)}, {"parameters", std::move(parameters)},
      {"cfg_entry", cfg ? static_cast<int64_t>(cfg->getEntry().getBlockID()) : -1},
      {"cfg_exit", cfg ? static_cast<int64_t>(cfg->getExit().getBlockID()) : -1},
      {"return_value_kind", decl->getReturnType()->isPointerType() ? "pointer" :
        decl->getReturnType()->isIntegerType() ? "integer" :
        decl->getReturnType()->isVoidType() ? "void" : "unsupported"},
      {"return_integer_bits", decl->getReturnType()->isIntegerType()
        ? static_cast<int64_t>(state.context->getTypeSize(decl->getReturnType())) : 0},
      {"return_integer_unsigned", decl->getReturnType()->isUnsignedIntegerType()},
      {"target_values", state.targetValues()}, {"fact_version", "zscope.program-events.v7"},
      {"resource_protocol_facts_version", "zscope.resource-protocol-facts.v1"},
      {"lifecycle_value_facts_version", "zscope.lifecycle-value-facts.v1"},
      {"pthread_storage_facts_version", "zscope.pthread-storage.v1"},
      {"pthread_wait_facts_version", "zscope.pthread-wait.v3"},
      {"pthread_cleanup_facts_version", "zscope.pthread-cleanup.v1"},
      {"pthread_cleanup_control_exit", cleanup.unsupportedExit},
      {"cxx_lifetime_facts_version", "zscope.cxx-lifetime-facts.v1"}});
    return true;
  }
  bool VisitDeclRefExpr(DeclRefExpr *expr) {
    const auto *decl = dyn_cast<VarDecl>(expr->getDecl());
    if (!decl || !decl->hasGlobalStorage() || decl->getTLSKind() != VarDecl::TLS_None) return true;
    access(expr, decl, "global");
    return true;
  }
  bool VisitMemberExpr(MemberExpr *expr) {
    const auto *base = expr->getBase()->IgnoreParenImpCasts();
    if (!expr->isArrow()) {
      if (const auto *reference = dyn_cast<DeclRefExpr>(base)) {
        if (const auto *var = dyn_cast<VarDecl>(reference->getDecl())) {
          if (var->getTLSKind() != VarDecl::TLS_None ||
              (!var->hasGlobalStorage() && !var->getType()->isReferenceType())) return true;
        }
      }
    }
    if (isa<FieldDecl>(expr->getMemberDecl())) access(expr, expr->getMemberDecl(), "field");
    return true;
  }
private:
  class ValueCollector : public RecursiveASTVisitor<ValueCollector> {
    ProgramEvents &owner;
  public:
    std::vector<std::pair<const ValueDecl *, const Expr *>> values;
    explicit ValueCollector(ProgramEvents &value) : owner(value) {}
    bool VisitDeclRefExpr(DeclRefExpr *expr) {
      if (const auto *decl = dyn_cast<ValueDecl>(expr->getDecl())) values.emplace_back(decl, expr);
      return true;
    }
    bool VisitMemberExpr(MemberExpr *expr) {
      if (const auto *decl = dyn_cast<ValueDecl>(expr->getMemberDecl())) values.emplace_back(decl, expr);
      return true;
    }
  };
  class CallCollector : public RecursiveASTVisitor<CallCollector> {
  public:
    std::vector<const CallExpr *> calls;
    std::vector<const AtomicExpr *> atomics;
    bool VisitCallExpr(CallExpr *expr) {
      calls.push_back(expr);
      return true;
    }
    bool VisitAtomicExpr(AtomicExpr *expr) {
      atomics.push_back(expr);
      return true;
    }
  };
  unsigned appendNestedCallEvents(Array &events, const Stmt *stmt,
                                  unsigned blockId, unsigned &ordinal, const PthreadCleanup &cleanup) {
    CallCollector collector;
    collector.TraverseStmt(const_cast<Stmt *>(stmt));
    unsigned emitted = 0;
    for (const auto *call : collector.calls) {
      if (call == stmt) continue;
      Object calleeIdentity;
      std::string operation;
      if (const auto *callee = call->getDirectCallee()) {
        calleeIdentity = state.target(callee);
        operation = callee->getQualifiedNameAsString();
      } else {
        calleeIdentity = objectIdentity(call->getCallee());
        closedTargets(call, calleeIdentity);
        operation = expression(call->getCallee());
      }
      operation += "(";
      Array argumentObjects, argumentExpressions, argumentUses, defs, uses;
      for (unsigned index = 0; index < call->getNumArgs(); ++index) {
        if (index) operation += ", ";
        operation += expression(call->getArg(index));
        argumentObjects.push_back(objectIdentity(call->getArg(index)));
        argumentExpressions.push_back(expression(call->getArg(index)));
        Array oneArgumentUses;
        appendValues(oneArgumentUses, call->getArg(index));
        argumentUses.push_back(std::move(oneArgumentUses));
        appendValues(uses, call->getArg(index));
      }
      operation += ")";
      auto result = acquisitionIdentity(call);
      if (!result.empty()) defs.push_back(std::move(result));
      std::string eventId = std::to_string(blockId) + ":" + std::to_string(ordinal);
      events.push_back(Object{{"event_id", eventId}, {"event_kind", "call"},
        {"resource_family", ""}, {"block", blockId}, {"ordinal", ordinal++},
        {"location", state.location(call->getBeginLoc()).json()},
        {"end", state.location(call->getEndLoc()).json()}, {"ast_kind", call->getStmtClassName()},
        {"expression", state.text(call->getSourceRange())}, {"operation", operation},
        {"object", Object{}}, {"callee", std::move(calleeIdentity)},
        {"arguments", std::move(argumentExpressions)},
        {"return_value", ""}, {"assignment_target", ""}, {"assignment_value", ""},
        {"argument_objects", std::move(argumentObjects)},
        {"argument_uses", std::move(argumentUses)}, {"defs", std::move(defs)},
        {"uses", std::move(uses)}, {"macro_expansion", call->getBeginLoc().isMacroID()},
        {"pthread_cleanup", cleanup.marker(call)},
        {"pthread_timed_wait", timedWait(call)}});
      ++emitted;
    }
    // Clang represents __atomic_* and __sync_* builtins as AtomicExpr rather
    // than CallExpr.  Preserve them as exact compiler-intrinsic events so
    // instance consumers do not need to authorize reserved operations from
    // source spelling alone.
    for (const auto *atomic : collector.atomics) {
      const std::string name = atomic->getOpAsString().str();
      Array argumentObjects, argumentExpressions, argumentUses, defs, uses;
      std::string operation = name + "(";
      for (unsigned index = 0; index < atomic->getNumSubExprs(); ++index) {
        const auto *argument = atomic->getSubExprs()[index];
        if (index) operation += ", ";
        operation += expression(argument);
        argumentObjects.push_back(objectIdentity(argument));
        argumentExpressions.push_back(expression(argument));
        Array oneArgumentUses;
        appendValues(oneArgumentUses, argument);
        argumentUses.push_back(std::move(oneArgumentUses));
        appendValues(uses, argument);
      }
      operation += ")";
      auto result = acquisitionIdentity(atomic);
      if (!result.empty()) defs.push_back(std::move(result));
      std::string eventId = std::to_string(blockId) + ":" + std::to_string(ordinal);
      Object calleeIdentity{{"name", name}, {"qualified_name", name},
        {"usr", "c:@F@" + name}, {"referenced_usr", "c:@F@" + name},
        {"canonical_signature", atomic->getType().getCanonicalType().getAsString()},
        {"external_linkage", true}, {"has_definition", false},
        {"is_system_header", false}, {"compiler_intrinsic", true}};
      events.push_back(Object{{"event_id", eventId}, {"event_kind", "compiler_intrinsic"},
        {"resource_family", ""}, {"block", blockId}, {"ordinal", ordinal++},
        {"location", state.location(atomic->getBeginLoc()).json()},
        {"end", state.location(atomic->getEndLoc()).json()}, {"ast_kind", "AtomicExpr"},
        {"expression", state.text(atomic->getSourceRange())}, {"operation", operation},
        {"object", Object{}}, {"callee", std::move(calleeIdentity)},
        {"arguments", std::move(argumentExpressions)}, {"return_value", ""},
        {"assignment_target", ""}, {"assignment_value", ""},
        {"argument_objects", std::move(argumentObjects)},
        {"argument_uses", std::move(argumentUses)}, {"defs", std::move(defs)},
        {"uses", std::move(uses)}, {"macro_expansion", atomic->getBeginLoc().isMacroID()},
        {"pthread_cleanup", cleanup.marker(atomic)}, {"pthread_timed_wait", Object{}}});
      ++emitted;
    }
    return emitted;
  }
  Object valueIdentity(const ValueDecl *decl, const Expr *expr) const {
    Object result = state.target(decl);
    std::string storage = "local";
    if (isa<ParmVarDecl>(decl)) storage = "parameter";
    else if (isa<FieldDecl>(decl)) storage = "field";
    else if (const auto *var = dyn_cast<VarDecl>(decl))
      if (var->hasGlobalStorage()) storage = "global";
    result["value_kind"] = storage;
    bool functionScopeLocal = false;
    if (const auto *var = dyn_cast<VarDecl>(decl)) {
      if (storage == "local") {
        const auto *function = dyn_cast<FunctionDecl>(var->getDeclContext());
        auto parents = state.context->getParents(*var);
        if (function && parents.size() == 1 && parents[0].get<DeclStmt>()) {
          auto scopes = state.context->getParents(parents[0]);
          functionScopeLocal = scopes.size() == 1 &&
            scopes[0].get<CompoundStmt>() == function->getBody();
        }
      }
    }
    result["function_scope_local"] = functionScopeLocal;
    const auto type = decl->getType();
    const auto *record = type->getAsRecordDecl();
    // Opaque POSIX storage may be a libc union. Preserve its actual system
    // declaration identity; consumers must not interpret the union members.
    std::string systemRecord;
    if (record && state.sm->isInSystemHeader(record->getLocation())) {
      if (const auto *alias = record->getTypedefNameForAnonDecl()) {
        const auto name = alias->getNameAsString();
        if (name == "pthread_mutex_t" || name == "pthread_cond_t") systemRecord = name;
      }
    }
    result["system_record_type"] = systemRecord;
    result["record_value"] = record != nullptr;
    const auto *field = dyn_cast<FieldDecl>(decl);
    result["bit_field"] = field && field->isBitField();
    result["overlapping_storage"] = (record && record->isUnion()) ||
      (field && field->getParent()->isUnion());
    result["volatile_or_atomic"] = type.isVolatileQualified() || type->isAtomicType() ||
      (type->isPointerType() && (type->getPointeeType().isVolatileQualified() ||
        type->getPointeeType()->isAtomicType()));
    // Anonymous enums declared inside a class template have an integer-like,
    // dependent type before instantiation.  Asking ASTContext for their
    // concrete layout recurses through the unresolved enum type and may
    // crash libclang.  A dependent or incomplete value has no build-bound
    // width to publish, so retain the identity while reporting the layout as
    // unknown (zero bits) until a concrete instantiation is observed.
    const bool concreteInteger = type->isIntegerType() &&
      !type->isDependentType() && !type->isIncompleteType();
    result["integer_bits"] = concreteInteger
      ? static_cast<int64_t>(state.context->getTypeSize(type)) : 0;
    result["integer_unsigned"] = concreteInteger && type->isUnsignedIntegerType();
    result["floating_value"] = type->isRealFloatingType();
    result["expression"] = expr ? expression(expr) : decl->getNameAsString();
    if (expr) {
      const auto *normalized = expr->IgnoreParenImpCasts();
      if (const auto *member = dyn_cast<MemberExpr>(normalized)) {
        result["base_expression"] = expression(member->getBase());
        result["identity_complete"] = !member->isArrow();
      }
    }
    return result;
  }
  void appendValues(Array &output, const Stmt *stmt) {
    if (!stmt) return;
    ValueCollector collector(*this);
    collector.TraverseStmt(const_cast<Stmt *>(stmt));
    std::set<std::string> seen;
    for (const auto &item : collector.values) {
      std::string key = state.usr(item.first) + "\x1f" + expression(item.second);
      if (!seen.insert(key).second) continue;
      output.push_back(valueIdentity(item.first, item.second));
    }
  }
  Object acquisitionIdentity(const Expr *expr) const {
    auto node = DynTypedNode::create(*expr);
    for (unsigned depth = 0; depth < 8; ++depth) {
      auto parents = state.context->getParents(node);
      if (parents.size() != 1) break;
      node = parents[0];
      if (const auto *parentCall = node.get<CallExpr>())
        if (parentCall != expr) break;
      if (const auto *var = node.get<VarDecl>()) return valueIdentity(var, nullptr);
      if (const auto *binary = node.get<BinaryOperator>()) {
        if (binary->isAssignmentOp()) return objectIdentity(binary->getLHS());
        break;
      }
      if (!node.get<Expr>()) break;
    }
    return {};
  }
  std::string expression(const Expr *expr) const {
    std::string text;
    llvm::raw_string_ostream stream(text);
    expr->printPretty(stream, nullptr, state.context->getPrintingPolicy());
    stream.flush();
    return text;
  }
  Object timedWait(const CallExpr *call) const {
    const auto *callee = call ? call->getDirectCallee() : nullptr;
    if (!callee || !state.sm->isInSystemHeader(callee->getLocation())) return {};
    const auto name = callee->getNameAsString();
    const bool explicitClock = name == "pthread_cond_clockwait";
    if ((!explicitClock && name != "pthread_cond_timedwait") ||
        call->getNumArgs() != (explicitClock ? 4u : 3u)) return {};
    Object clock{{"kind", "condition_default"}, {"name", "CLOCK_REALTIME"}};
    if (explicitClock) {
      const auto *value = dyn_cast<IntegerLiteral>(call->getArg(2)->IgnoreParenImpCasts());
      if (!value || !value->getLocation().isMacroID()) return {};
      const auto use = state.location(value->getLocation());
      const auto expansion = state.pthreadWaitConstants.find({use.file, use.offset});
      if (expansion == state.pthreadWaitConstants.end() ||
          (expansion->second != "CLOCK_REALTIME" && expansion->second != "CLOCK_MONOTONIC") ||
          Lexer::getImmediateMacroName(value->getLocation(), *state.sm, state.context->getLangOpts()) != expansion->second)
        return {};
      const auto current = state.targetConstants.find(expansion->second);
      const auto system = state.systemWaitConstants.find(expansion->second);
      if (current == state.targetConstants.end() || system == state.systemWaitConstants.end() ||
          !system->second || value->getValue().getLimitedValue() != static_cast<uint64_t>(current->second)) return {};
      clock = Object{{"kind", "explicit_system_constant"}, {"name", expansion->second}, {"value", current->second}};
    }
    // Do not erase casts or accept project lookalikes for the deadline record.
    const auto *argument = call->getArg(explicitClock ? 3 : 2)->IgnoreParenImpCasts();
    const auto *address = dyn_cast<UnaryOperator>(argument);
    if (!address || address->getOpcode() != UO_AddrOf) return {};
    const auto *ref = dyn_cast<DeclRefExpr>(address->getSubExpr()->IgnoreParenImpCasts());
    const auto *var = ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
    const auto *record = var ? var->getType()->getAsRecordDecl() : nullptr;
    if (!var || !var->hasLocalStorage() || var->hasAttrs() || var->getType().isVolatileQualified() ||
        !record || record->getNameAsString() != "timespec" || record->isUnion() ||
        !state.sm->isInSystemHeader(record->getLocation())) return {};
    Object fields;
    for (const auto *field : record->fields()) {
      const auto name = field->getNameAsString();
      if ((name != "tv_sec" && name != "tv_nsec") || field->isBitField() ||
          field->getFieldIndex() != (name == "tv_sec" ? 0u : 1u) ||
          !field->getType()->isSignedIntegerType() ||
          state.context->getTypeSize(field->getType()) != 64 ||
          field->getType().isVolatileQualified()) return {};
      fields[name] = state.usr(field);
    }
    if (fields.size() != 2) return {};
    const auto &layout = state.context->getASTRecordLayout(record);
    if (layout.getSize().getQuantity() != 16 || layout.getAlignment().getQuantity() != 8 ||
        layout.getFieldOffset(0) != 0 || layout.getFieldOffset(1) != 64) return {};
    return Object{{"schema", "zscope.pthread-deadline.v3"}, {"clock", std::move(clock)},
      {"variable_usr", state.usr(var)}, {"fields", std::move(fields)},
      {"layout", Object{{"size_bytes", 16}, {"alignment_bytes", 8},
                        {"tv_sec_offset_bits", 0}, {"tv_nsec_offset_bits", 64}}}};
  }
  bool waitConstantOnlyMacros(const Stmt *stmt) const {
    if (!stmt) return true;
    for (auto loc : {stmt->getBeginLoc(), stmt->getEndLoc()}) {
      if (!loc.isMacroID()) continue;
      auto use = state.location(loc);
      const auto expansion = state.pthreadWaitConstants.find({use.file, use.offset});
      if (expansion == state.pthreadWaitConstants.end() ||
          Lexer::getImmediateMacroName(loc, *state.sm, state.context->getLangOpts()) != expansion->second) return false;
    }
    for (const auto *child : stmt->children()) if (!waitConstantOnlyMacros(child)) return false;
    return true;
  }
  bool containsMacro(const Stmt *stmt) {
    if (!stmt) return false;
    auto known = macroFlags.find(stmt);
    if (known != macroFlags.end()) return known->second;
    bool found = stmt->getBeginLoc().isMacroID() || stmt->getEndLoc().isMacroID();
    if (!found) for (const auto *child : stmt->children()) if (containsMacro(child)) { found = true; break; }
    macroFlags[stmt] = found;
    return found;
  }
  Object objectIdentity(const Expr *expr) const {
    expr = expr->IgnoreParenImpCasts();
    if (const auto *reference = dyn_cast<DeclRefExpr>(expr)) return valueIdentity(reference->getDecl(), reference);
    if (const auto *member = dyn_cast<MemberExpr>(expr)) {
      auto identity = valueIdentity(member->getMemberDecl(), member);
      identity["base_expression"] = expression(member->getBase());
      identity["value_kind"] = "field";
      identity["expression"] = expression(member);
      identity["identity_complete"] = !member->isArrow();
      return identity;
    }
    return Object{{"expression", expression(expr)}, {"identity_complete", false}};
  }
  void access(const Expr *expr, const ValueDecl *decl, const char *storage) {
    auto loc = state.location(expr->getExprLoc());
    auto owner = state.owner(loc);
    if (!state.allowed(loc.file) || owner.empty()) return;
    std::string kind = "read";
    auto parents = state.context->getParents(*expr);
    while (parents.size() == 1) {
      const auto *parent = parents[0].get<Expr>();
      if (!parent || (!isa<ParenExpr>(parent) && !isa<ImplicitCastExpr>(parent))) break;
      parents = state.context->getParents(*parent);
    }
    if (!parents.empty()) {
      if (const auto *unary = parents[0].get<UnaryOperator>())
        if (unary->isIncrementDecrementOp()) kind = "read_write";
      if (const auto *binary = parents[0].get<BinaryOperator>())
        if (binary->isAssignmentOp() && binary->getLHS()->IgnoreParenImpCasts() == expr)
          kind = binary->isCompoundAssignmentOp() ? "read_write" : "write";
    }
    Object receiver;
    if (const auto *member = dyn_cast<MemberExpr>(expr)) receiver = objectIdentity(member->getBase());
    state.emit(Object{{"kind", "program_access"}, {"owner", std::move(owner)}, {"receiver", std::move(receiver)},
      {"location", loc.json()}, {"target", state.target(decl)}, {"storage_class", storage},
      {"atomic", decl->getType()->isAtomicType() || decl->getType().getAsString().find("atomic<") != std::string::npos},
      {"const", decl->getType().isConstQualified()}, {"access_kind", kind},
      {"expression", state.text(expr->getSourceRange())}});
  }
};
