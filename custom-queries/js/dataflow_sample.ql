/**
 * @name NoSQL_injection_custom_query 
 * @description cutomize sqlinjection.ql 
 * @id js/dataflow_sample
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @tags security
 */

import javascript
import semmle.javascript.security.TaintedObject
import semmle.javascript.security.dataflow.NosqlInjectionCustomizations::NosqlInjection
import DataFlow::PathGraph

class MyMongoSanitize extends TaintTracking::SanitizerGuardNode, DataFlow::CallNode {
  MyMongoSanitize() { this.getCalleeName() = "sanitize" }
  override predicate sanitizes(boolean outcome, Expr e){
    outcome = true and
    e = getArgument(0).asExpr()
  }
}

class Configuration extends TaintTracking::Configuration{
    Configuration() { this = "NOSQLInjection"}
  override predicate isSource(DataFlow::Node source, DataFlow::FlowLabel label) {
    TaintedObject::isSource(source, label)
  }
  override predicate isSink(DataFlow::Node sink, DataFlow::FlowLabel label) {
    sink.(Sink).getAFlowLabel() = label
  }

  override predicate isSanitizerGuard(TaintTracking::SanitizerGuardNode guard){
    guard instanceof MyMongoSanitize
  }

  override predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ, DataFlow::FlowLabel inlbl, DataFlow::FlowLabel outlbl){
    TaintedObject::step(pred, succ, inlbl, outlbl)
    or
    // additional flow step to track taint through NoSQL query objects
    inlbl = TaintedObject::label() and
    outlbl = TaintedObject::label() and
    exists(NoSql::Query query, DataFlow::SourceNode queryObj |
      queryObj.flowsToExpr(query) and
      queryObj.flowsTo(succ) and
      pred = queryObj.getAPropertyWrite().getRhs()
    )
  }
}

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on $@.", source.getNode(),
  "a user-provided value"
