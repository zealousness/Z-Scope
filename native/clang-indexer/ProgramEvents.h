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
    Array events, edges;
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
          Object object;
          Array argumentObjects;
          if (const auto *allocation = dyn_cast<CXXNewExpr>(stmt)) {
            kind = "acquire";
            object = acquisitionIdentity(allocation);
            family = allocation->isArray() ? "new_array" : "new_scalar";
            if (allocation->getNumPlacementArgs() || (allocation->getOperatorNew() &&
                !allocation->getOperatorNew()->isReplaceableGlobalAllocationFunction())) family = "custom_allocation";
          } else if (const auto *release = dyn_cast<CXXDeleteExpr>(stmt)) {
            kind = "release";
            family = release->isArrayForm() ? "new_array" : "new_scalar";
            object = objectIdentity(release->getArgument());
            operation = std::string(release->isArrayForm() ? "delete[] " : "delete ") + expression(release->getArgument());
          } else if (const auto *call = dyn_cast<CallExpr>(stmt)) {
            kind = "call";
            object = acquisitionIdentity(call);
            if (const auto *callee = call->getDirectCallee()) {
              operation = callee->getQualifiedNameAsString() + "(";
              for (unsigned i = 0; i < call->getNumArgs(); ++i) {
                if (i) operation += ", ";
                operation += expression(call->getArg(i));
                argumentObjects.push_back(objectIdentity(call->getArg(i)));
              }
              operation += ")";
            }
          }
          events.push_back(Object{{"event_kind", kind}, {"resource_family", family},
            {"block", block->getBlockID()}, {"ordinal", ordinal++},
            {"location", begin.json()}, {"end", state.location(stmt->getEndLoc()).json()},
            {"ast_kind", stmt->getStmtClassName()}, {"expression", state.text(stmt->getSourceRange())},
            {"operation", operation}, {"object", std::move(object)},
            {"argument_objects", std::move(argumentObjects)}, {"macro_expansion", stmt->getBeginLoc().isMacroID()}});
        }
        for (auto successor : block->succs())
          if (const auto *target = successor.getReachableBlock())
            edges.push_back(Object{{"from", block->getBlockID()}, {"to", target->getBlockID()}});
      }
    }
    state.emit(Object{{"kind", "program_function"}, {"owner", state.owner(loc)},
      {"location", loc.json()}, {"complete", bool(cfg)}, {"events", std::move(events)},
      {"cfg_edges", std::move(edges)}, {"fact_version", "zscope.program-events.v1"}});
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
  Object acquisitionIdentity(const Expr *expr) const {
    auto node = DynTypedNode::create(*expr);
    for (unsigned depth = 0; depth < 8; ++depth) {
      auto parents = state.context->getParents(node);
      if (parents.size() != 1) break;
      node = parents[0];
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
