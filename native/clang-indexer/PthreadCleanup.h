#pragma once

// Preserve raw CFGs. Only an explicitly marked async consumer may project the
// verified C/glibc setjmp scaffold into push/pop operations. C++ and exception
// variants, user redefinitions and arbitrary macro arguments remain unknown.
class PthreadCleanup : public RecursiveASTVisitor<PthreadCleanup> {
  State &state;
  std::map<unsigned, Object> receipts;
  std::map<unsigned, const VarDecl *> routines, arguments;
  std::map<unsigned, unsigned> pairs;
  std::set<unsigned> invalid;
  std::map<unsigned, std::map<std::string, unsigned>> calls;
  std::vector<unsigned> exits;
  std::string file;

  static bool identifier(llvm::StringRef value) {
    if (value.empty() || !(llvm::isAlpha(value.front()) || value.front() == '_')) return false;
    return std::all_of(value.begin(), value.end(), [](char c) { return llvm::isAlnum(c) || c == '_'; });
  }
  unsigned offset(SourceLocation loc) const { return state.location(loc).offset; }
  const Object *macro(SourceLocation loc) const {
    if (!loc.isMacroID()) return nullptr;
    auto found = state.pthreadCleanupMacros.find({file, offset(loc)});
    return found == state.pthreadCleanupMacros.end() ? nullptr : &found->second;
  }
  static const DeclRefExpr *reference(const Expr *expr) {
    return expr ? dyn_cast<DeclRefExpr>(expr->IgnoreParenImpCasts()) : nullptr;
  }
public:
  bool unsupportedExit = false;
  explicit PthreadCleanup(State &s, FunctionDecl *function) : state(s) {
    file = state.location(function->getLocation()).file;
    const auto first = state.pthreadCleanupMacros.lower_bound({file, offset(function->getBody()->getBeginLoc())});
    if (first == state.pthreadCleanupMacros.end() || first->first.first != file ||
        first->first.second > offset(function->getBody()->getEndLoc())) return;
    if (state.context->getLangOpts().CPlusPlus || state.context->getLangOpts().Exceptions ||
        state.targetLibc != "glibc") return;
    TraverseStmt(function->getBody());
    for (const auto &pair : pairs) {
      const unsigned push = pair.first, pop = pair.second;
      for (unsigned position : exits) if (push < position && position < pop) unsupportedExit = true;
      const auto *r = routines[push], *a = arguments[push];
      const auto *rr = r ? reference(r->getInit()) : nullptr;
      const auto *ar = a ? reference(a->getInit()) : nullptr;
      const auto *callback = rr ? dyn_cast<FunctionDecl>(rr->getDecl()) : nullptr;
      const auto *value = ar ? dyn_cast<VarDecl>(ar->getDecl()) : nullptr;
      if (invalid.count(push) || invalid.count(pop) ||
          state.pthreadCleanupRewritten.count({file, push}) ||
          state.pthreadCleanupRewritten.count({file, pop}) || !callback || !value ||
          !value->hasLocalStorage() || !value->getType()->isPointerType() || value->hasAttrs() ||
          value->getType().isVolatileQualified() || value->getType()->isAtomicType()) continue;
      const auto &pc = calls[push], &qc = calls[pop];
      if (pc != std::map<std::string, unsigned>{{"setjmp", 1}, {"__builtin_expect", 1},
            {"__pthread_register_cancel", 1}, {"__pthread_unwind_next", 1}, {"indirect", 1}} ||
          qc != std::map<std::string, unsigned>{{"__pthread_unregister_cancel", 1}, {"indirect", 1}}) continue;
      const auto &pm = state.pthreadCleanupMacros.at({file, push});
      const auto &qm = state.pthreadCleanupMacros.at({file, pop});
      const auto *pa = pm.getArray("arguments"), *qa = qm.getArray("arguments");
      if (!pa || pa->size() != 2 || !qa || qa->size() != 1 ||
          (*pa)[0].getAsString() != callback->getName() ||
          (*pa)[1].getAsString() != value->getName()) continue;
      Object common{{"schema", "zscope.pthread-cleanup.v1"}, {"pair", push},
        {"callback", state.target(callback)}, {"argument", value->getNameAsString()},
        {"argument_usr", state.usr(value)}, {"push_offset", push}, {"pop_offset", pop}};
      receipts[push] = common;
      receipts[push]["action"] = "push";
      receipts[pop] = std::move(common);
      receipts[pop]["action"] = "pop";
      receipts[pop]["execute"] = (*qa)[0].getAsString().value_or("") == "1";
    }
  }
  bool VisitDoStmt(DoStmt *stmt) {
    const auto *push = macro(stmt->getBeginLoc()), *pop = macro(stmt->getEndLoc());
    if (!push || !pop || push->getString("name") != "pthread_cleanup_push" ||
        pop->getString("name") != "pthread_cleanup_pop") return true;
    static const std::string pushText =
      "do{__pthread_unwind_buf_t__cancel_buf;void(*__cancel_routine)(void*)=(routine);"
      "void*__cancel_arg=(arg);int__not_first_call=__sigsetjmp_cancel(__cancel_buf.__cancel_jmp_buf,0);"
      "if(__glibc_unlikely(__not_first_call)){__cancel_routine(__cancel_arg);"
      "__pthread_unwind_next(&__cancel_buf);}__pthread_register_cancel(&__cancel_buf);do{";
    static const std::string popText =
      "do{}while(0);}while(0);__pthread_unregister_cancel(&__cancel_buf);"
      "if(execute)__cancel_routine(__cancel_arg);}while(0)";
    const auto *pa = push->getArray("arguments"), *qa = pop->getArray("arguments");
    if (push->getString("replacement") != pushText || pop->getString("replacement") != popText ||
        push->getBoolean("system_definition") != true || pop->getBoolean("system_definition") != true ||
        push->getBoolean("direct_invocation") != true || pop->getBoolean("direct_invocation") != true ||
        !pa || pa->size() != 2 || !identifier((*pa)[0].getAsString().value_or("")) ||
        !identifier((*pa)[1].getAsString().value_or("")) || !qa || qa->size() != 1 ||
        ((*qa)[0].getAsString() != "0" && (*qa)[0].getAsString() != "1")) return true;
    pairs[offset(stmt->getBeginLoc())] = offset(stmt->getEndLoc());
    return true;
  }
  bool VisitVarDecl(VarDecl *decl) {
    if (!macro(decl->getLocation())) return true;
    if (decl->getName() == "__cancel_routine") routines[offset(decl->getLocation())] = decl;
    if (decl->getName() == "__cancel_arg") arguments[offset(decl->getLocation())] = decl;
    return true;
  }
  bool VisitReturnStmt(ReturnStmt *stmt) { exits.push_back(offset(stmt->getBeginLoc())); return true; }
  bool VisitBreakStmt(BreakStmt *stmt) { exits.push_back(offset(stmt->getBeginLoc())); return true; }
  bool VisitContinueStmt(ContinueStmt *stmt) { exits.push_back(offset(stmt->getBeginLoc())); return true; }
  bool VisitGotoStmt(GotoStmt *stmt) { unsupportedExit = true; return true; }
  bool VisitIndirectGotoStmt(IndirectGotoStmt *stmt) { unsupportedExit = true; return true; }
  bool VisitCallExpr(CallExpr *call) {
    if (!macro(call->getBeginLoc())) return true;
    const auto *callee = call->getDirectCallee();
    if (!callee) {
      const auto *ref = reference(call->getCallee());
      if (!ref || ref->getDecl()->getName() != "__cancel_routine") invalid.insert(offset(call->getBeginLoc()));
      ++calls[offset(call->getBeginLoc())]["indirect"];
      return true;
    }
    const auto name = callee->getNameAsString();
    ++calls[offset(call->getBeginLoc())][name == "__sigsetjmp" || name == "__sigsetjmp_cancel" ? "setjmp" : name];
    const bool builtin = name == "__builtin_expect" && callee->getBuiltinID();
    const bool runtime = (name == "__sigsetjmp" || name == "__sigsetjmp_cancel" ||
      name == "__pthread_register_cancel" || name == "__pthread_unregister_cancel" ||
      name == "__pthread_unwind_next") && !callee->hasBody() &&
      state.sm->isInSystemHeader(callee->getLocation()) && callee->hasExternalFormalLinkage();
    if (!builtin && !runtime) invalid.insert(offset(call->getBeginLoc()));
    return true;
  }
  bool VisitIfStmt(IfStmt *stmt) {
    const auto *m = macro(stmt->getBeginLoc());
    if (!m) return true;
    const Expr *condition = stmt->getCond()->IgnoreParenImpCasts();
    bool valid = false;
    if (m->getString("name") == "pthread_cleanup_push") {
      const auto *call = dyn_cast<CallExpr>(condition);
      if (call && call->getNumArgs() == 2 && call->getDirectCallee() &&
          call->getDirectCallee()->getName() == "__builtin_expect" && call->getDirectCallee()->getBuiltinID()) {
        const auto *ref = reference(call->getArg(0));
        const auto *zero = dyn_cast<IntegerLiteral>(call->getArg(1)->IgnoreParenImpCasts());
        valid = ref && ref->getDecl()->getName() == "__not_first_call" && zero && zero->getValue() == 0;
      }
    } else {
      const auto *literal = dyn_cast<IntegerLiteral>(condition);
      const auto *args = m->getArray("arguments");
      valid = literal && args && args->size() == 1 && literal->getValue().getLimitedValue(2) ==
        ((*args)[0].getAsString() == "1" ? 1 : 0);
    }
    if (!valid) invalid.insert(offset(stmt->getBeginLoc()));
    return true;
  }
  Object marker(const Stmt *stmt) const {
    if (!stmt || !stmt->getBeginLoc().isMacroID()) return {};
    auto found = receipts.find(offset(stmt->getBeginLoc()));
    if (found == receipts.end()) return {};
    Object result = found->second;
    if (const auto *expr = dyn_cast<Expr>(stmt))
      if (const auto *literal = dyn_cast<IntegerLiteral>(expr->IgnoreParenImpCasts()))
        result["condition_value"] = static_cast<int64_t>(literal->getValue().getLimitedValue(2));
    bool operation = false;
    if (const auto *call = dyn_cast<CallExpr>(stmt)) if (const auto *callee = call->getDirectCallee())
      operation = callee->getName() == "__pthread_register_cancel" ||
                  callee->getName() == "__pthread_unregister_cancel";
    result["operation"] = operation;
    return result;
  }
};
