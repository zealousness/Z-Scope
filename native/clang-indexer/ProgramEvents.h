#pragma once

// One CFG per function in the existing TU parse; never spawn per candidate.
class ProgramEvents : public RecursiveASTVisitor<ProgramEvents> {
  State &state;
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
    Array events, edges, parameters;
    for (unsigned index = 0; index < decl->getNumParams(); ++index) {
      const auto *parameter = decl->getParamDecl(index);
      auto identity = valueIdentity(parameter, nullptr);
      identity["index"] = index;
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
              {"location", state.location(trigger->getEndLoc()).json()}, {"ast_kind", "AutomaticObjectDtor"},
              {"expression", var->getNameAsString()}});
            continue;
          }
          if (auto destructor = element.getAs<CFGTemporaryDtor>()) {
            auto *expr = destructor->getBindTemporaryExpr();
            events.push_back(Object{{"event_kind", "implicit_release"}, {"resource_family", "cxx_temporary"},
              {"block", block->getBlockID()}, {"ordinal", ordinal++},
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
              defs.push_back(valueIdentity(var, nullptr));
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
          nestedCalls = appendNestedCallEvents(events, stmt, block->getBlockID(), ordinal);
          // A nested call already represents the value transfer into the
          // declaration/assignment target. Emitting the wrapper as another
          // defining event would overwrite that call-result identity and make
          // argument-to-result propagation look like a direct must-flow.
          if (nestedCalls && (kind == "declaration_initializer" || kind == "assignment" ||
                              kind == "compound_assignment"))
            continue;
          std::string eventId = std::to_string(block->getBlockID()) + ":" + std::to_string(ordinal);
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
            {"uses", std::move(uses)}, {"macro_expansion", stmt->getBeginLoc().isMacroID()}});
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
              {"branch", condition && block->succ_size() == 2 &&
                !isa_and_nonnull<SwitchStmt>(block->getTerminatorStmt())
                ? (successorIndex == 0 ? "true" : "false") : "unknown"}});
          }
          ++successorIndex;
        }
      }
    }
    state.emit(Object{{"kind", "program_function"}, {"owner", state.owner(loc)},
      {"location", loc.json()}, {"complete", bool(cfg)}, {"events", std::move(events)},
      {"cfg_edges", std::move(edges)}, {"parameters", std::move(parameters)},
      {"target_values", state.targetValues()}, {"fact_version", "zscope.program-events.v5"}});
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
    bool VisitCallExpr(CallExpr *expr) {
      calls.push_back(expr);
      return true;
    }
  };
  unsigned appendNestedCallEvents(Array &events, const Stmt *stmt,
                                  unsigned blockId, unsigned &ordinal) {
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
        {"uses", std::move(uses)}, {"macro_expansion", call->getBeginLoc().isMacroID()}});
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
      if (const auto *var = node.get<VarDecl>()) return state.target(var);
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
  Object objectIdentity(const Expr *expr) const {
    expr = expr->IgnoreParenImpCasts();
    if (const auto *reference = dyn_cast<DeclRefExpr>(expr)) return state.target(reference->getDecl());
    if (const auto *member = dyn_cast<MemberExpr>(expr)) {
      auto identity = state.target(member->getMemberDecl());
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
